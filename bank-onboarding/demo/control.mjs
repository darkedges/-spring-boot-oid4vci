import {spawnSync,spawn} from 'node:child_process';
import {existsSync,mkdirSync,readFileSync,writeFileSync,openSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {randomBytes} from 'node:crypto';
import {generateKeyPair,exportJWK} from 'jose';
const dir=import.meta.dirname,root=resolve(dir,'../../..');
process.chdir(dir);mkdirSync('runtime/keys',{recursive:true});mkdirSync('artifacts',{recursive:true});
const secretFile=resolve(dir,'runtime/callback-secret');if(!existsSync(secretFile))writeFileSync(secretFile,randomBytes(32).toString('hex'),{mode:0o600});
const env={...process.env,SHOWCASE_CALLBACK_SECRET:readFileSync(secretFile,'utf8').trim()};
if(!env.JAVA_HOME&&existsSync('C:/development/utils/java/jdk25.0.18'))env.JAVA_HOME='C:/development/utils/java/jdk25.0.18';
const priorPath=env.PATH||env.Path||'';delete env.Path;delete env.PATH;env.PATH=[dirname(process.execPath),resolve(root,'.cache/npm-runner/package/bin'),env.JAVA_HOME?env.JAVA_HOME+'/bin':'',priorPath].filter(Boolean).join(process.platform==='win32'?';':':');
const run=(cmd,args,cwd=dir)=>{if(cmd==='mvn'&&existsSync('C:/ProgramData/chocolatey/lib/maven/apache-maven-3.8.6/bin/mvn.cmd'))cmd='C:/ProgramData/chocolatey/lib/maven/apache-maven-3.8.6/bin/mvn.cmd';const result=spawnSync(cmd,args,{cwd,env,stdio:'inherit',shell:process.platform==='win32',windowsHide:true});if(result.status!==0)throw Error(cmd+' failed');};
const compose=args=>run('docker',['compose','-p','risk-e-onboarding-showcase','-f',resolve(dir,'compose.yml'),...args]);
async function check(){for(const url of ['http://localhost:43194/','http://localhost:43192/.well-known/openid-credential-issuer','http://localhost:43180/realms/risk-e-demo','http://localhost:43126/api/v1/messages','http://localhost:43100/','http://localhost:43101/']) {const r=await fetch(url,{signal:AbortSignal.timeout(3000)});if(!r.ok)throw Error('Not ready: '+url);console.log('Ready: '+url);}}
async function up(){
 for(const name of ['passport','bank'])if(!existsSync('runtime/keys/'+name+'.jwk')){const keys=await generateKeyPair('ES256',{extractable:true});const jwk={...await exportJWK(keys.privateKey),kid:'showcase-'+name};writeFileSync('runtime/keys/'+name+'.jwk',JSON.stringify(jwk),{mode:0o600});writeFileSync('runtime/keys/'+name+'-public.jwk',JSON.stringify({...await exportJWK(keys.publicKey),kid:jwk.kid}));}
 run('mvn',['-f',resolve(root,'oid4vci/pom.xml'),'-pl','bank-onboarding,oid4vci-demo-issuer','-am','package','-DskipTests','-Dbank.build.directory='+resolve(dir,'runtime/bank-target'),'-Dmaven.repo.local='+resolve(root,'.m2/repository')]);
 run('npx',['ng','build','--configuration','showcase'],resolve(root,'oid4vci-wallet'));
 run('npm',['run','build:plugins'],resolve(root,'identityproofing'));
 run('npx',['vite','build','--mode','showcase','--outDir','dist-showcase'],resolve(root,'identityproofing/app'));
 compose(['up','-d']);
 let running=false;try{running=(await fetch('http://localhost:43100/')).ok;}catch{}
 if(!running){const log=openSync('artifacts/server.log','a');const child=spawn(process.execPath,[resolve(dir,'server.mjs')],{cwd:dir,env,detached:true,windowsHide:true,stdio:['ignore',log,log]});child.unref();writeFileSync('runtime/server.pid',String(child.pid));}
 for(let i=0;i<90;i++){try{await check();return;}catch{await new Promise(r=>setTimeout(r,2000));}}throw Error('Demo did not become healthy');
}
const task=process.argv[2]||'check';
if(task==='up')await up();
else if(task==='check')await check();
else if(task==='down'){try{await fetch('http://localhost:43100/bridge/shutdown',{method:'POST',headers:{'X-Demo-Secret':env.SHOWCASE_CALLBACK_SECRET}});}catch{}compose(['down']);}
else if(task==='reset'){compose(['down','-v']);compose(['up','-d']);let ready=false;for(let i=0;i<90;i++){try{await check();ready=true;break;}catch{await new Promise(r=>setTimeout(r,2000));}}if(!ready)throw Error('Demo reset did not become healthy');}
else if(task==='voiceover')run('docker',['compose','-p','risk-e-onboarding-showcase-tools','-f','tools.yml','run','--rm','voiceover']);
else if(task==='demo'){await up();compose(['down','-v']);compose(['up','-d']);let ready=false;for(let i=0;i<90;i++){try{await check();ready=true;break;}catch{await new Promise(r=>setTimeout(r,2000));}}if(!ready)throw Error('Demo did not become healthy after reset');run(process.execPath,['control.mjs','voiceover']);run(process.execPath,['record.mjs']);}
else throw Error('Unknown demo command');
