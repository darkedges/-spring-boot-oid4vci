import {chromium} from 'playwright';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../src/main/resources/static/hr-watch.js',import.meta.url),'utf8');
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage();
 await page.evaluate(async moduleUrl=>{
  const {updateCards}=await import(moduleUrl);
  for(const selected of [true,false]){
   document.body.innerHTML='<div id="hire-list"><article id="hire-test" data-status="REVOKED"><h2>Morgan Example</h2><form action="/reactivate"><input type="hidden" name="_csrf" value="old-mask"><input type="checkbox" name="forcePassportCheck"><textarea name="reason"></textarea></form></article></div>';
   const incoming=new DOMParser().parseFromString(document.body.innerHTML.replace('old-mask','new-mask'),'text/html');
   incoming.querySelector('[name=forcePassportCheck]').checked=!selected;
   const old=document.querySelector('article');
   old.querySelector('textarea').value='Keep this decision note';
   const checkbox=old.querySelector('[type=checkbox]');checkbox.checked=selected;checkbox.focus();
   const ring=document.createElement('div');ring.id='showcase-focus-ring';document.body.append(ring);
   updateCards(document,incoming,()=>{});
   const current=document.querySelector('article'),next=current.querySelector('[type=checkbox]');
   if(current===old)throw Error('The regression scenario did not replace the card');
   if(next.checked!==selected)throw Error('Polling lost the fresh Passport selection');
   if(document.activeElement!==next)throw Error('Polling lost checkbox focus');
   if(current.querySelector('textarea').value!=='Keep this decision note')throw Error('Polling lost the decision note');
   if(current.querySelector('[name=_csrf]').value!=='new-mask')throw Error('Polling retained an obsolete CSRF mask');
  }
 },'data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
 console.log('Polling preserved checked and unchecked choices, notes and focus while refreshing CSRF masks.');
} finally {await browser.close();}
