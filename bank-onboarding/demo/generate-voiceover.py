#!/usr/bin/env python3
"""Generate a scene-aligned WAV voiceover with hexgrad/Kokoro-82M.

Adapted from darkedges/pingfedonetap (scripts/generate-voiceover.py). Each cue in demo/voiceover.json is
rendered in its own worker process (Kokoro holds a lot of memory), checked to finish before the next cue
starts, and mixed at its start time into one 24 kHz WAV. Extra cue fields (such as the recorder's
`action`) are ignored here.

Run through `pnpm demo:voiceover`, which runs this in the demo-voiceover container.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any


SAMPLE_RATE = 24_000
FADE_SECONDS = 0.012
MINIMUM_GAP_SECONDS = 0.08


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the timed relationship-risk demo voiceover using Kokoro-82M."
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=Path(__file__).with_name("voiceover.json"),
        help="Timed cue JSON file (default: demo/voiceover.json).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/demo/voiceover.wav"),
        help="Destination WAV file.",
    )
    parser.add_argument("--voice", help="Override the Kokoro voice from the cue file.")
    parser.add_argument("--language", help="Override the Kokoro language code.")
    parser.add_argument("--speed", type=float, help="Override the speech speed.")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate cue timing without loading the model or downloading weights.",
    )
    parser.add_argument("--worker-cue", type=int, help=argparse.SUPPRESS)
    return parser.parse_args()


def load_script(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"Voiceover script not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error

    cues = data.get("cues")
    duration = data.get("duration_seconds")
    if not isinstance(cues, list) or not cues:
        raise ValueError("The script must contain a non-empty 'cues' array.")
    if not isinstance(duration, (int, float)) or duration <= 0:
        raise ValueError("'duration_seconds' must be a positive number.")

    previous_start = -1.0
    for index, cue in enumerate(cues, start=1):
        if not isinstance(cue, dict):
            raise ValueError(f"Cue {index} must be an object.")
        start = cue.get("start")
        text = cue.get("text")
        if not isinstance(start, (int, float)) or start < 0:
            raise ValueError(f"Cue {index} has an invalid start time.")
        if start <= previous_start:
            raise ValueError("Cue start times must be strictly increasing.")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"Cue {index} must contain narration text.")
        if start >= duration:
            raise ValueError(f"Cue {index} starts after the declared duration.")
        previous_start = float(start)

    return data


def apply_fades(audio: Any, sample_rate: int, numpy: Any) -> Any:
    fade_length = min(int(FADE_SECONDS * sample_rate), len(audio) // 2)
    if fade_length:
        ramp = numpy.linspace(0.0, 1.0, fade_length, dtype=numpy.float32)
        audio[:fade_length] *= ramp
        audio[-fade_length:] *= ramp[::-1]
    return audio


def render_cue(
    data: dict[str, Any], cue_index: int, output: Path, voice: str, language: str, speed: float
) -> None:
    # spaCy may invoke `uv pip install` while downloading its English model.
    # An interpreter launched by absolute path does not activate the venv, so
    # advertise the current prefix explicitly for that child process.
    os.environ.setdefault("VIRTUAL_ENV", sys.prefix)

    try:
        import numpy
        import soundfile
        import torch
        from kokoro import KPipeline
    except ImportError as error:
        raise RuntimeError(
            "Voiceover dependencies are missing. Run it with 'pnpm demo:voiceover' (the demo-voiceover container)."
        ) from error

    if cue_index < 0 or cue_index >= len(data["cues"]):
        raise ValueError(f"Cue index {cue_index} is out of range.")

    warnings.filterwarnings("ignore", message="dropout option adds dropout")
    warnings.filterwarnings("ignore", message=".*weight_norm.*deprecated.*")
    pipeline = KPipeline(
        lang_code=language,
        repo_id=str(data.get("model", "hexgrad/Kokoro-82M")),
    )
    cue = data["cues"][cue_index]
    with torch.inference_mode():
        chunks = [
            numpy.asarray(audio, dtype=numpy.float32).reshape(-1)
            for _graphemes, _phonemes, audio in pipeline(
                cue["text"], voice=voice, speed=speed
            )
        ]
    if not chunks:
        raise RuntimeError(f"Kokoro returned no audio for cue {cue_index + 1}.")

    segment = apply_fades(numpy.concatenate(chunks), SAMPLE_RATE, numpy)
    output.parent.mkdir(parents=True, exist_ok=True)
    soundfile.write(output, segment, SAMPLE_RATE, subtype="FLOAT")


def synthesize(
    data: dict[str, Any], script_path: Path, output: Path, voice: str, language: str, speed: float
) -> None:
    try:
        import numpy
        import soundfile
    except ImportError as error:
        raise RuntimeError(
            "Voiceover dependencies are missing. Run it with 'pnpm demo:voiceover' (the demo-voiceover container)."
        ) from error

    cues = data["cues"]
    rendered: list[tuple[int, Any]] = []
    timing_errors: list[str] = []
    latest_end = 0

    print(f"Model: {data.get('model', 'hexgrad/Kokoro-82M')}")
    print(f"Voice: {voice}; language: {language}; speed: {speed:g}x")
    print("Memory mode: isolated worker process per cue")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relationship-risk-voiceover-") as temp_dir:
        for index, cue in enumerate(cues):
            cue_output = Path(temp_dir) / f"cue-{index + 1}.wav"
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--script",
                str(script_path.resolve()),
                "--output",
                str(cue_output),
                "--voice",
                voice,
                "--language",
                language,
                "--speed",
                str(speed),
                "--worker-cue",
                str(index),
            ]
            worker_env = os.environ.copy()
            worker_env.setdefault("VIRTUAL_ENV", sys.prefix)
            result = subprocess.run(command, env=worker_env, check=False)
            if result.returncode:
                raise RuntimeError(
                    f"Kokoro worker for cue {index + 1} failed with exit code "
                    f"{result.returncode}."
                )

            segment, sample_rate = soundfile.read(
                cue_output, dtype="float32", always_2d=False
            )
            if sample_rate != SAMPLE_RATE:
                raise RuntimeError(
                    f"Cue {index + 1} has unexpected sample rate {sample_rate}."
                )

            segment = numpy.asarray(segment, dtype=numpy.float32).reshape(-1)
            start_sample = round(float(cue["start"]) * SAMPLE_RATE)
            end_sample = start_sample + len(segment)
            next_start = (
                float(cues[index + 1]["start"])
                if index + 1 < len(cues)
                else float(data["duration_seconds"])
            )
            available = next_start - float(cue["start"])
            actual = len(segment) / SAMPLE_RATE
            if actual + MINIMUM_GAP_SECONDS > available:
                timing_errors.append(
                    f"Cue {index + 1} is {actual:.2f}s long but has only "
                    f"{available:.2f}s. Increase --speed or shorten that cue."
                )

            rendered.append((start_sample, segment))
            latest_end = max(latest_end, end_sample)
            print(
                f"  {index + 1}. {float(cue['start']):05.2f}s "
                f"[{actual:04.2f}s] {cue.get('label', '')}",
                flush=True,
            )

    if timing_errors:
        raise RuntimeError("\n".join(timing_errors))

    duration_samples = max(
        round(float(data["duration_seconds"]) * SAMPLE_RATE), latest_end
    )
    mix = numpy.zeros(duration_samples, dtype=numpy.float32)
    for start_sample, segment in rendered:
        mix[start_sample : start_sample + len(segment)] += segment

    peak = float(numpy.max(numpy.abs(mix))) if len(mix) else 0.0
    if peak > 0.95:
        mix *= 0.95 / peak

    def stamp(seconds):
        ms = round(seconds * 1000)
        return f"{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}"
    subtitles = []
    timing = []
    for cue, (start, segment) in zip(cues, rendered):
        actual = len(segment) / SAMPLE_RATE
        timing.append({"start": float(cue["start"]), "duration": actual, "text": cue["text"]})
        words = cue["text"].split()
        for first in range(0, len(words), 14):
            last = min(first + 14, len(words))
            text = " ".join(words[first:min(first+7,last)]) + "\n" + " ".join(words[first+7:last])
            subtitles.append(f"{len(subtitles)+1}\n{stamp(float(cue['start'])+actual*first/len(words))} --> {stamp(float(cue['start'])+actual*last/len(words))}\n{text.strip()}\n")
    output.with_suffix(".srt").write_text("\n".join(subtitles), encoding="utf-8")
    output.with_suffix(".timing.json").write_text(json.dumps(timing, indent=2), encoding="utf-8")
    soundfile.write(output, mix, SAMPLE_RATE, subtype="PCM_16")
    print(f"Wrote {output} ({len(mix) / SAMPLE_RATE:.2f}s, {SAMPLE_RATE} Hz PCM WAV)")


def main() -> int:
    args = parse_args()
    try:
        data = load_script(args.script)
        voice = args.voice or str(data.get("voice", "bf_emma"))
        language = args.language or str(data.get("language", "b"))
        speed = args.speed if args.speed is not None else float(data.get("speed", 1.0))
        if not voice:
            raise ValueError("A Kokoro voice must be specified.")
        if not language:
            raise ValueError("A Kokoro language code must be specified.")
        if speed <= 0:
            raise ValueError("Speech speed must be greater than zero.")

        if args.worker_cue is not None:
            render_cue(data, args.worker_cue, args.output, voice, language, speed)
            return 0

        print(
            f"Validated {len(data['cues'])} cues across "
            f"{float(data['duration_seconds']):.2f} seconds."
        )
        if not args.validate_only:
            synthesize(data, args.script, args.output, voice, language, speed)
        return 0
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
