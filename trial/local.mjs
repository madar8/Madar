// Portable single-process runtime for the SAME trial API, without Netlify.
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileStore} from './file-store.mjs';
import {createHandler} from './core.mjs';
const root=resolve(new URL('..',import.meta.url).pathname),data=resolve(process.env.MADAR_TRIAL_DATA_DIR||join(root,'.trial-data'));
if(!process.env.MADAR_SETUP_TOKEN){console.error('Set MADAR_SETUP_TOKEN to a private random value of at least 32 characters.');process.exit(1);}
const api=createHandler({stateStore:fileStore(data,'state'),fileStore:fileStore(data,'documents'),setupToken:process.env.MADAR_SETUP_TOKEN,secure:process.env.MADAR_SECURE_COOKIE==='1'});
const files = {'/':'index.html','/app':'index.html','/setup':'index.html'};
for (const name of [
 'app.js','styles.css','pwa.js','sw.js',
 'manifest.webmanifest','favicon.ico','fonts/noto-sans-arabic.woff2','icons/madar-180.png',
 'icons/madar-192.png','icons/madar-48.png','icons/madar-512.png','icons/madar-maskable.png',
 'icons/madar-share.png','icons/madar.svg'
]) files['/'+name]=name;
const mime = {html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',js:'text/javascript; charset=utf-8',
 webmanifest:'application/manifest+json',woff2:'font/woff2',svg:'image/svg+xml',png:'image/png',ico:'image/x-icon'};
createServer(async(req,res)=>{try{
 const path=new URL(req.url,'http://localhost').pathname;
 if(path.startsWith('/api/')){
  const request=new Request('http://'+req.headers.host+req.url,{method:req.method,headers:req.headers,...(['GET','HEAD'].includes(req.method)?{}:{body:req,duplex:'half'})});
  const response=await api(request);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
 }else if(Object.hasOwn(files,path)){
  const file=files[path];
  res.writeHead(200,{'Content-Type':mime[file.split('.').pop()],'X-Content-Type-Options':'nosniff'});
  res.end(readFileSync(join(root,'web',file)));
 }
 else{res.writeHead(404);res.end('Not found');}
 }catch{res.writeHead(500);res.end('Request failed');}
}).listen(Number(process.env.PORT||8000),'127.0.0.1',()=>console.log('Madar portable trial: http://127.0.0.1:'+(process.env.PORT||8000)));
