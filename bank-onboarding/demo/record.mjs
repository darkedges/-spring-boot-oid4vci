import {chromium} from 'playwright';
import {PNG} from 'pngjs';import jsQR from 'jsqr';
import {readFileSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';import {spawnSync} from 'node:child_process';
const dir=import.meta.dirname;process.chdir(dir);const rehearse=process.argv.includes('--rehearse');const script=JSON.parse(readFileSync('voiceover.json'));
mkdirSync('artifacts/frames',{recursive:true});
mkdirSync('artifacts/shots',{recursive:true});
const browser=await chromium.launch({headless:true,slowMo:rehearse?0:180});const desktop=await browser.newContext({viewport:{width:1920,height:1080}}),mobile=await browser.newContext({viewport:{width:1920,height:1080}});
await mobile.addInitScript(()=>document.addEventListener('DOMContentLoaded',()=>{
 const style=document.createElement('style');style.textContent='body{background:#102b3b!important}ion-app{position:absolute!important;top:35px!important;bottom:75px!important;left:calc(50% - 240px)!important;width:480px!important;max-width:480px!important;right:auto!important;border:9px solid #263c49;border-radius:26px;overflow:hidden;box-shadow:0 14px 50px #0008}';document.head.append(style);
}));
const applicantContext=await browser.newContext({viewport:{width:1920,height:1080}}),staffContext=await browser.newContext({viewport:{width:1920,height:1080}});
const hr=await desktop.newPage(),applicant=await applicantContext.newPage(),staff=await staffContext.newPage(),wallet=await mobile.newPage(),proof=await mobile.newPage();
let captureFailures=0,captureError;
let active=hr,caption='',frame=0,capturing=false,stopped=false,requestPage,previousStaffId,pendingInvite,pendingProof=false;
let sceneStart=0,currentScene=0,shotNumber=0;
const focusTargets=new Map(),shots=[];
const beat=async seconds=>{if(rehearse)return;const remaining=sceneStart+seconds*1000-Date.now();if(remaining>0)await new Promise(r=>setTimeout(r,remaining));};
const show=async page=>{active=page;await page.bringToFront();};
const focus=async(page,selector,label)=>{
 await show(page);const target=page.locator(selector).first();await target.waitFor({state:'visible'});
 focusTargets.set(page,selector);
 await target.evaluate(e=>{
  document.getElementById('showcase-pointer')?.remove();
  const article=e.closest('#hire-list > article,#hire-history article');
  if(article){document.body.style.paddingBottom='65vh';window.scrollTo({top:window.scrollY+article.getBoundingClientRect().top-70,behavior:'instant'});}
  else e.scrollIntoView({block:'center',behavior:'instant'});
 });
 await page.waitForTimeout(150);
 const box=await target.boundingBox();
 if(!box||box.y<0||box.y+Math.min(box.height,60)>1010)throw Error('Focal area is outside the recorded viewport: '+label);
 const path=`artifacts/shots/${String(currentScene).padStart(2,'0')}-${String(++shotNumber).padStart(2,'0')}-${label}.jpg`;
 await page.screenshot({path,type:'jpeg',quality:85});
 shots.push({scene:currentScene,label,at:(Date.now()-sceneStart)/1000,selector,path});
};
const hireStatus='#hire-list > article > p:has(> strong)';
const hireTable='#hire-list > article table';
const report=[],captured=[];
// Warm and verify the complete isolated OIDC round trip before starting the film clock.
let hrReady=false;
for(let attempt=0;attempt<3;attempt++){
 const context=await browser.newContext();const probe=await context.newPage();
 try{
  await probe.goto('http://localhost:43194/hr');await probe.locator('#username').fill('hr.demo');await probe.locator('#password').fill('showcase-local-only');await probe.locator('#kc-login').click();
  await probe.locator('form[action="/hr/hires"]').waitFor({state:'visible',timeout:10000});hrReady=true;
 }catch{console.log('Waiting for the isolated HR identity provider to complete sign-in');}
 finally{await context.close();}
 if(hrReady)break;
}
if(!hrReady){await browser.close();throw Error('Demo HR sign-in preflight failed');}
for(let n=0;n<50;n++){const stale=await(await fetch('http://localhost:43100/bridge/event')).json();if(!stale.url)break;}const beginning=Date.now();
const button=(page,name)=>page.getByRole('button',{name,exact:false});
const click=async(page,name)=>{
 await show(page);focusTargets.delete(page);const target=button(page,name).last();await target.scrollIntoViewIfNeeded();const box=await target.boundingBox();
 if(box)await page.evaluate(pos=>{let pointer=document.getElementById('showcase-pointer');if(!pointer){pointer=document.createElement('div');pointer.id='showcase-pointer';pointer.style.cssText='position:fixed;width:22px;height:22px;border:3px solid #f5bd38;border-radius:50%;background:#f5bd3850;pointer-events:none;z-index:2147483646';document.body.append(pointer);}pointer.style.left=pos.x+'px';pointer.style.top=pos.y+'px';},{x:box.x+box.width/2-11,y:box.y+box.height/2-11});
 if(!rehearse)await page.waitForTimeout(200);await target.click();if(!rehearse)await page.waitForTimeout(200);
};
const event=async()=>{for(let i=0;i<90;i++){const r=await (await fetch('http://localhost:43100/bridge/event')).json();if(r.url)return r.url;await new Promise(r=>setTimeout(r,500));}throw Error('App-switch event did not arrive');};
const openWallet=async url=>{active=wallet;await wallet.bringToFront();await wallet.evaluate(url=>window.dispatchEvent(new CustomEvent('showcase-link',{detail:url})),url);};
const qr=async(page,fresh=false)=>{const source=await page.locator('img[alt="Scan with your wallet"]').getAttribute('src');const image=PNG.sync.read(Buffer.from(source.split(',')[1],'base64'));const code=jsQR(new Uint8ClampedArray(image.data),image.width,image.height);if(!code)throw Error('QR did not decode');if(fresh){const uri=new URL(code.data).searchParams.get('request_uri');if(!uri||new URL(uri).origin!=='http://localhost:43194')throw Error('Unexpected request issuer');const request=await(await fetch(uri)).json();if(!request.passport_check_after)throw Error('The bank request did not require a fresh Passport check');}await openWallet(code.data);};
const inbox=async()=>{for(let i=0;i<50;i++){const data=await (await fetch('http://localhost:43126/api/v1/messages')).json();if(data.messages?.length){const message=await (await fetch('http://localhost:43126/api/v1/message/'+data.messages[0].ID)).json();const link=message.Text.match(/http:\/\/localhost:43194\/invite\/[A-Za-z0-9_-]+/);if(link)return link[0];}await new Promise(r=>setTimeout(r,500));}throw Error('Invitation email missing');};
const returnFromProof=async()=>{if(!pendingProof)throw Error('No completed proofing result');await click(proof,'Return to your wallet');await openWallet(await event());pendingProof=false;};
const proofing=async(returnImmediately=true)=>{const url=await event();if(!url.startsWith('identityproofing:'))throw Error('Wrong app switch');await show(proof);await proof.goto('http://localhost:43101/?showcase-link='+encodeURIComponent(url));if(!returnImmediately)await beat(2);await click(proof,/I agree/);
 for(let i=0;i<160;i++){
  if(await button(proof,'Return to your wallet').isVisible()){pendingProof=true;await focus(proof,'.verdict','proofing-result');if(returnImmediately)await returnFromProof();return;}
  for(const label of [/^(Continue|Start face check|Start capture|Enter the details(?: instead)?|Use these details|Read passport|Begin)$/i]) {const b=button(proof,label).last();if(await b.isVisible()&&await b.isEnabled()){await b.click();break;}}
  if(await proof.getByText('Identity check failed',{exact:true}).isVisible())throw Error('Simulated proofing failed');await new Promise(r=>setTimeout(r,500));
 }throw Error('Proofing did not complete');};
const present=async(success=true,closeAt)=>{await click(wallet,'Approve & Send');await wallet.getByText(success?'Presentation successful':'Presentation unsuccessful',{exact:true}).waitFor();await focus(wallet,'ion-alert','presentation-'+(success?'accepted':'refused'));if(closeAt!==undefined)await beat(closeAt);else if(!rehearse)await wallet.waitForTimeout(1800);await click(wallet,'Return to wallet');};
const obtain=async()=>{await click(wallet,'Accept & Obtain');};
const startPassport=async(paced=false,fresh=false)=>{await show(applicant);await focus(applicant,'section','passport-request-start');await click(applicant,'Present passport credential');requestPage=applicant;await focus(applicant,'img[alt="Scan with your wallet"]','passport-request-qr');if(paced)await beat(10);await qr(applicant,fresh);};
const collect=async()=>{await show(applicant);await applicant.goto('http://localhost:43194/onboarding');await focus(applicant,'section','approved-collection');await beat(2);await click(applicant,'Collect approved staff credential offer');await focus(applicant,'img[alt="Scan with your wallet"]','staff-offer-qr');await beat(5);await qr(applicant);await beat(8);await obtain();await wallet.getByText('Credential obtained',{exact:true}).first().waitFor();
 const staffIds=await wallet.evaluate(()=>JSON.parse(localStorage.getItem('CapacitorStorage.wallet.credentials')||'[]').filter(c=>c.vct==='http://localhost:43194/vct/BankStaffCredential').map(c=>c.id));
 if(staffIds.length!==1)throw Error('Expected exactly one current bank staff credential');
 if(previousStaffId===staffIds[0])throw Error('Reactivation did not replace the staff credential');
 previousStaffId=staffIds[0];
 await beat(13);await wallet.goto('http://localhost:43100/home');await focus(wallet,'ion-list:visible','one-current-staff-credential');
};
const signin=async(success=true,closing=false)=>{await show(staff);await staff.goto('http://localhost:43194/');await click(staff,'Sign in with staff wallet');await focus(staff,'img[alt="Scan with your wallet"]','staff-signin-qr');await beat(closing?0:success?6:8);await qr(staff);await button(wallet,'Approve & Send').waitFor();await focus(wallet,'ion-list:visible','staff-disclosure-consent');await beat(closing?1:success?13:12);await present(success,closing?5:success?20:19);if(success){await staff.waitForURL('**/staff');await focus(staff,'section','staff-portal');}};
const actions={
 title:async()=>{await hr.goto('http://localhost:43194/');await wallet.goto('http://localhost:43100/');await focus(hr,'section','bank-staff-services');},
 hr_login:async()=>{await show(hr);focusTargets.delete(hr);await hr.goto('http://localhost:43194/hr');await hr.locator('#username').fill('hr.demo');await hr.locator('#password').fill('showcase-local-only');await beat(3);await hr.locator('#kc-login').click();await hr.waitForURL(/\/hr(?:\?.*)?$/);await focus(hr,'form[action="/hr/hires"]','hr-create-hire');},
 hire:async()=>{await focus(hr,'form[action="/hr/hires"]','recruitment-details');await hr.locator('[name=given]').fill('MORGAN');await hr.locator('[name=family]').fill('EXAMPLE');await beat(2);await hr.locator('[name=birth]').fill('1990-04-12');await hr.locator('[name=email]').fill('morgan@example.test');await hr.locator('[name=department]').fill('Customer Operations');await beat(9);await click(hr,'Create invitation');await focus(hr,'section','invitation-created');await beat(13);await hr.goto('http://localhost:43194/hr');await focus(hr,hireStatus,'invited-status');},
 email:async()=>{const link=await inbox();await show(applicant);await applicant.goto('http://localhost:43126/');await applicant.getByText('Risk E Bank',{exact:false}).first().click();await beat(7);await applicant.goto(link);await focus(applicant,'section','personal-invitation');},
 request:()=>startPassport(true),proof:()=>proofing(false),
 passport_present:async()=>{await returnFromProof();await beat(4);await obtain();await button(wallet,'Approve & Send').waitFor();await focus(wallet,'ion-list:visible','passport-disclosure-consent');await beat(12);await present(true,18);await applicant.waitForURL('**/onboarding');await beat(20);await focus(applicant,'section','awaiting-hr-review');},
 approve:async()=>{await hr.goto('http://localhost:43194/hr');await focus(hr,hireTable,'compare-recruitment-and-passport');await beat(6);await focus(hr,'#hire-list form:has(button[value="approve"])','hr-approval-controls');await beat(9);await click(hr,/^Approve$/);await focus(hr,hireStatus,'approved-status');},collect,signin:()=>signin(true),
 revoke:async()=>{await hr.goto('http://localhost:43194/hr');await focus(hr,'#hire-list form:has(button[value="revoke"])','revocation-controls');await hr.locator('#hire-list form:has(button[value=revoke]) textarea[name=reason]').fill('Demo access withdrawn for identity re-verification');await beat(4);await click(hr,'Revoke approval');await hr.locator('#hire-list article[data-status="REVOKED"]').waitFor();await focus(hr,hireStatus,'revoked-status-and-reason');},
 deny:async()=>{await show(staff);const response=await staff.reload();if(!response||response.ok())throw Error('Revoked browser session was not refused');focusTargets.delete(staff);await beat(4);await signin(false);},
 reverify:async()=>{await hr.goto('http://localhost:43194/hr');await focus(hr,'#hire-list form:has([name="forcePassportCheck"])','require-fresh-passport');await beat(3);await hr.locator('[name=forcePassportCheck]').check();await beat(5);if(!await hr.locator('[name=forcePassportCheck]').isChecked())throw Error('Fresh Passport option was cleared before submission');await click(hr,'Start reactivation');await focus(hr,'section','replacement-invitation-created');pendingInvite=await inbox();await beat(8);await hr.goto('http://localhost:43194/hr');await focus(hr,hireStatus,'new-verification-attempt');},
 freshproof:async()=>{await show(applicant);await applicant.goto(pendingInvite);await startPassport(false,true);await proofing();await obtain();await button(wallet,'Approve & Send').waitFor();await focus(wallet,'ion-list:visible','fresh-passport-disclosure');await present();await applicant.waitForURL('**/onboarding');await focus(applicant,'section','fresh-evidence-awaits-review');},
 approve_again:async()=>{await hr.goto('http://localhost:43194/hr');await focus(hr,hireTable,'review-fresh-passport');await beat(4);await click(hr,/^Approve$/);await focus(hr,hireStatus,'reactivation-approved');await beat(11);await hr.locator('#hire-history').evaluate(e=>e.open=true);await focus(hr,'#hire-history article','revoked-attempt-history');},collect_again:collect,signin_again:()=>signin(true,true),
};
const capture=async()=>{
 if(stopped||capturing||!active)return;capturing=true;
 try{
  await active.evaluate(({label,selector})=>{
   let style=document.getElementById('showcase-framing');
   if(!style){style=document.createElement('style');style.id='showcase-framing';style.textContent='pre,.dev-panel{display:none!important}';document.head.append(style);}
   let bar=document.getElementById('showcase-caption');
   if(!bar){bar=document.createElement('div');bar.id='showcase-caption';bar.style.cssText='position:fixed;bottom:0;left:0;right:0;background:#143042;color:white;padding:18px;font:22px system-ui;z-index:2147483647';document.body.append(bar);}
   bar.textContent=label+' — SIMULATED PASSPORT CHECK / FICTIONAL DATA';
   const target=selector?[...document.querySelectorAll(selector.replaceAll(':visible',''))].find(e=>e.checkVisibility()):null;
   let ring=document.getElementById('showcase-focus-ring');
   if(!ring){ring=document.createElement('div');ring.id='showcase-focus-ring';ring.style.cssText='position:fixed;border:3px solid #d89512;pointer-events:none;z-index:2147483645';document.body.append(ring);}
   ring.hidden=!target;
   if(target){
    const article=target.closest('#hire-list > article,#hire-history article');
    if(article){document.body.style.paddingBottom='65vh';window.scrollTo({top:window.scrollY+article.getBoundingClientRect().top-70,behavior:'instant'});}
    else target.scrollIntoView({block:'center',behavior:'instant'});
    const box=target.getBoundingClientRect();Object.assign(ring.style,{left:(box.left-7)+'px',top:(box.top-7)+'px',width:(box.width+8)+'px',height:(box.height+8)+'px'});
   }
  },{label:caption,selector:focusTargets.get(active)});
  const file='frames/frame-'+String(frame++).padStart(6,'0')+'.jpg';
  const at=(Date.now()-beginning)/1000;
  await active.screenshot({path:'artifacts/'+file,type:'jpeg',quality:80});captured.push({file,at});captureFailures=0;
 }catch{captureFailures++;if(captureFailures>20)captureError=new Error('Screen capture unavailable for more than ten seconds');}
 finally{capturing=false;}
};
let clock;if(!rehearse)clock=setInterval(()=>void capture(),500);
try{
 for(let i=0;i<script.cues.length;i++){const cue=script.cues[i];currentScene=cue.scene;shotNumber=0;if(!rehearse){const wait=cue.start*1000-(Date.now()-beginning);if(wait>0)await new Promise(r=>setTimeout(r,wait));}if(captureError)throw captureError;caption=cue.label;const started=Date.now();sceneStart=started;console.log('Scene '+cue.scene+': '+cue.label);await actions[cue.action]();const elapsed=(Date.now()-started)/1000;report.push({scene:cue.scene,seconds:elapsed});if(!rehearse&&i+1<script.cues.length&&Date.now()-beginning>script.cues[i+1].start*1000)throw Error('Scene overrun: '+cue.action);}
 if(!rehearse){const remaining=script.duration_seconds*1000-(Date.now()-beginning);if(remaining>0)await new Promise(r=>setTimeout(r,remaining));}
}catch(error){await active.screenshot({path:'artifacts/failure.png'});throw error;}finally{stopped=true;clearInterval(clock);while(capturing)await new Promise(r=>setTimeout(r,50));writeFileSync(rehearse?'artifacts/rehearsal-report.json':'artifacts/report.json',JSON.stringify(report,null,2));writeFileSync(rehearse?'artifacts/rehearsal-shots.json':'artifacts/shots.json',JSON.stringify(shots,null,2));await browser.close();}
rmSync('artifacts/failure.png',{force:true});
if(!rehearse){writeFileSync('artifacts/onboarding.srt',readFileSync('artifacts/voiceover.srt'));writeFileSync('artifacts/frames.txt',captured.map((f,i)=>`file '${f.file}'\nduration ${Math.max(.01,(captured[i+1]?.at??script.duration_seconds)-f.at)}\n`).join('')+`file '${captured.at(-1).file}'\n`);const result=spawnSync(process.execPath,[dir+'/assemble.mjs'],{stdio:'inherit',windowsHide:true});if(result.status!==0)throw Error('Video assembly failed');}
