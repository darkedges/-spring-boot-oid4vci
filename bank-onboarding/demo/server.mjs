import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
const root=resolve(import.meta.dirname,'../../..');
const secret=(await readFile(new URL('./runtime/callback-secret',import.meta.url),'utf8')).trim();
const events=[];
const origins=new Set(['http://localhost:43100','http://localhost:43101']);
const targets=new Set(['http://localhost:43192','http://localhost:43194']);
const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json','.png':'image/png','.woff2':'font/woff2'};
const body=async req=>{let s='';for await(const chunk of req){s+=chunk;if(s.length>2000000)throw Error('Too large');}return JSON.parse(s||'{}');};
for(const [port,folder] of [[43100,'oid4vci-wallet/www-showcase'],[43101,'identityproofing/app/dist-showcase']]) {
 http.createServer(async(req,res)=>{
  try {
   if(req.headers.origin&&!origins.has(req.headers.origin)){res.writeHead(403).end();return;}
   res.setHeader('Access-Control-Allow-Origin',req.headers.origin||'http://localhost:'+port);res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Cache-Control','no-store');
   if(req.method==='OPTIONS'){res.end();return;}
   const path=new URL(req.url,'http://localhost').pathname;
   res.setHeader('Content-Type','application/json');
   if(path==='/bridge/shutdown'&&req.method==='POST'&&req.headers['x-demo-secret']===secret){res.end('{}');setTimeout(()=>process.exit(0),100);return;}
   if(path==='/bridge/event'&&req.method==='POST'){const data=await body(req);if(!/^(identityproofing|openid-wallet|openid-credential-offer):/.test(data.url||''))throw Error('Invalid scheme');events.push(data);res.end('{}');return;}
   if(path==='/bridge/event'&&req.method==='GET'){res.end(JSON.stringify(events.shift()||{}));return;}
   if(path==='/bridge/http'){
    const data=await body(req);if(!targets.has(new URL(data.url).origin))throw Error('Non-demo destination');
    const response=await fetch(data.url,{method:data.method,headers:data.headers,body:data.method==='GET'?undefined:typeof data.body==='string'?data.body:JSON.stringify(data.body),redirect:'error'});
    const text=await response.text();let parsed;try{parsed=JSON.parse(text);}catch{parsed={};}res.end(JSON.stringify({status:response.status,body:parsed}));return;
   }
   if(path==='/bridge/proof'){
    const {sessionId}=await body(req);if(typeof sessionId!=='string'||!sessionId)throw Error('Missing session');
    const payload={session_id:sessionId,given_names:'MORGAN',surname:'EXAMPLE',date_of_birth:'1990-04-12',document_number:'RISK00001',nationality:'UTO',issuing_state:'UTO',date_of_expiry:'2099-12-31',liveness_passed:true,face_matched:true,sod_signature_valid:true,data_group_hashes_valid:true,csca_validated:true,revocation_checked:false,portrait_from_chip:true,active_authentication_valid:null};
    const result=await fetch('http://localhost:43192/proofing/result',{method:'POST',headers:{'Content-Type':'application/json','X-Proofing-Secret':secret},body:JSON.stringify(payload)});
    res.statusCode=result.status;res.end('{}');return;
   }
   const base=resolve(root,folder),file=resolve(base,'.'+decodeURIComponent(path));if(!file.startsWith(base+'/')&&!file.startsWith(base+'\\')&&file!==base)throw Error('Invalid path');
   let bytes;let name=file;try{bytes=await readFile(file);}catch{name=resolve(base,'index.html');bytes=await readFile(name);}
   res.setHeader('Content-Type',mime[extname(name)]||'application/octet-stream');res.end(bytes);
  }catch{res.writeHead(400).end('{"error":"showcase request failed"}');}
 }).listen(port,'127.0.0.1',()=>console.log('Demo UI listening on localhost:'+port));
}
