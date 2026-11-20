import {spawnSync} from 'node:child_process';
import {readFileSync,copyFileSync} from 'node:fs';
const dir=import.meta.dirname;
const script=JSON.parse(readFileSync(new URL('./voiceover.json',import.meta.url)));
const result=spawnSync('docker',[
 'run','--rm','-v',dir+'/artifacts:/work','jrottenberg/ffmpeg:7.1-ubuntu',
 '-y','-f','concat','-safe','0','-i','/work/frames.txt',
 '-i','/work/voiceover.wav','-i','/work/onboarding.srt',
 '-map','0:v:0','-map','1:a:0','-map','2:s:0',
 '-vf','fps=25','-c:v','libx264','-preset','veryfast','-crf','20','-pix_fmt','yuv420p',
 '-c:a','aac','-c:s','mov_text','-metadata:s:s:0','language=eng',
 '-movflags','+faststart','-t',String(script.duration_seconds),'/work/onboarding.mp4'
],{stdio:'inherit',windowsHide:true});
if(result.status!==0)throw Error('Video assembly failed');
const shorter=spawnSync(process.execPath,[dir+'/shorten.mjs'],{stdio:'inherit',windowsHide:true});
if(shorter.status!==0)throw Error('Short video assembly failed');
copyFileSync(new URL('./artifacts/onboarding-short.mp4',import.meta.url),new URL('./artifacts/onboarding-directed.mp4',import.meta.url));
copyFileSync(new URL('./artifacts/onboarding-short.srt',import.meta.url),new URL('./artifacts/onboarding-directed.srt',import.meta.url));
