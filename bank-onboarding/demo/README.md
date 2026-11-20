# Risk E Bank: onboarding and credential lifecycle

An isolated demonstration of the actual bank, wallet and Identity Proofing user
interfaces and credential protocols. Passport/chip/liveness findings are synthetic.
The demo is not evidence of certified document checks, real biometrics or Android
Keystore protection. It never uses the existing bank database, PingFederate,
Mailgun, public issuer, device wallet, or their environment files.

## Start

Prerequisites: Docker Desktop, JDK 21+, Maven, Node 22+, npm, and the sibling
`oid4vp` libraries installed as described by the bank README. Run from this folder:

```powershell
npm install
npx playwright install chromium
make demo-up
make demo-check
npm run check:polling
make demo-rehearse
```

Select JDK 21+ using JAVA_HOME. The launcher supports this workspace's cached Node
and npm when they exist. It does not import the regular bank .env. All service
ports bind to loopback. Docker project `risk-e-onboarding-showcase` owns a separate
PostgreSQL volume and network. Stop on a port conflict rather than changing a real
service. The subnet is defined explicitly to avoid Docker address pool exhaustion.

| Service | Address |
|---|---|
| Bank / HR | http://localhost:43194/hr |
| Demo Passport issuer | http://localhost:43192 |
| Local HR identity provider | http://localhost:43180 |
| Invitation mailbox | http://localhost:43126 |
| Browser wallet | http://localhost:43100 |
| Simulated mobile proofing | http://localhost:43101 |

Fictional HR login: `hr.demo`, password `showcase-local-only`. The applicant is
Morgan Example, born 1990-04-12, morgan@example.test. Do not use real identities.
The demo creates separate EC signing keys and a callback secret under ignored
`runtime/`; these are not production credentials.

## Record

```powershell
make demo-reset
make demo-check
make demo-voiceover
make demo-record
# Or: make demo  (builds, starts, resets the demo, narrates, records)
```

`voiceover.json` defines the tightly paced story, captions and actions. The voiceover
uses the same Kokoro British-English voice as the chaos example. Its first Docker
build downloads dependencies and model weights. Recording drives actual UI and
waits for observable outcomes; it never sets bank status directly. The simulated
scan decodes the real QR image before feeding the wallet's existing link handler.
Browser-only HTTP/app-switch bridges are compiled into the showcase build, not
native production builds. The simulated proofing callback is available only in
the loopback demo broker and uses the isolated issuer's secret. The issuer stamps
`showcase-simulated` assurance, which the ordinary bank rejects.

The recommended playback is `artifacts/onboarding-directed.mp4` (about 6 minutes
33 seconds), also saved as `onboarding-short.mp4`. It removes idle time after each scene, retaining all narration and
recorded actions with a short pause before the next scene. Selectable English
subtitles are retimed to match. Recording and rendering generate both versions.
Use `make demo-shorten` to regenerate the shorter cut from an existing completed
recording without restarting services or recording the flow again.

Artifacts: `artifacts/onboarding-short.mp4`, `onboarding-short.srt`, the full
`onboarding.mp4`, `voiceover.wav`, frames, subtitles and
`report.json`. On failure, inspect `failure.png` and the named scene. Rehearsal
runs actions without waiting for narration slots. Reset before repeating a run.
The MP4 includes selectable English subtitles; onboarding.srt is also available
separately. Use `make demo-render` to assemble existing frames and audio again
without repeating the onboarding flow.
The recorder directs individual steps with `beat()` offsets relative to the scene's
narration. `focus()` scrolls the actual interface to the relevant controls or result
and keeps that area in frame after HR polling updates. Highlights are separate
overlays outside the watched staff cards, so they cannot trigger card replacement
or reset form selections. Reactivation checks both the selected checkbox and the
bank request's fresh-proofing requirement before continuing. Review `artifacts/shots.json`
and `artifacts/shots/` for the recorded focal areas, including the revocation form,
revoked status, approval comparison and fresh Passport requirement. Rehearsal writes
its own shot report without replacing the recording report.
The polling regression check covers preserved checkbox choices and notes when
responses refresh CSRF masks. The demo bank builds under `runtime/bank-target`
so rebuilding it does not replace the regular bank's running JAR.
Reset removes only the demo Compose project's resources, never existing bank or
wallet data. `make demo-down` stops the demo services and broker.

The recording pipeline adapts the cue format and Kokoro script from
`observeinc/chaos/demo`; those source files were read and copied, not modified.
See RUNBOOK.md for the presenter sequence and recovery steps.
