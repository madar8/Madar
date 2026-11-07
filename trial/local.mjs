// Portable single-process runtime for the SAME trial API, without Netlify.
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileStore} from './file-store.mjs';
import {createHandler} from './core.mjs';
const root=resolve(new URL('..',import.meta.url).pathname),data=resolve(process.env.MADAR_TRIAL_DATA_DIR||join(root,'.trial-data'));
if(!process.env.MADAR_SETUP_TOKEN){console.error('Set MADAR_SETUP_TOKEN to a private random value of at least 32 characters.');process.exit(1);}
const api=createHandler({stateStore:fileStore(data,'state'),fileStore:fileStore(data,'documents'),setupToken:process.env.MADAR_SETUP_TOKEN,secure:process.env.MADAR_SECURE_COOKIE==='1'});
const files={'/':'index.html','/app':'index.html','/setup':'index.html','/app.js':'app.js','/styles.css':'styles.css','/fonts/noto-sans-arabic.woff2':'fonts/noto-sans-arabic.woff2'};
createServer(async(req,res)=>{try{
 const path=new URL(req.url,'http://localhost').pathname;
 if(path.startsWith('/api/')){
  const request=new Request('http://'+req.headers.host+req.url,{method:req.method,headers:req.headers,...(['GET','HEAD'].includes(req.method)?{}:{body:req,duplex:'half'})});
  const response=await api(request);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
 }else if(files[path]){res.writeHead(200,{'Content-Type':path.endsWith('.woff2')?'font/woff2':path.endsWith('.js')?'text/javascript; charset=utf-8':path.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff'});res.end(readFileSync(join(root,'web',files[path])));}
 else{res.writeHead(404);res.end('Not found');}
 }catch{res.writeHead(500);res.end('Request failed');}
}).listen(Number(process.env.PORT||8000),'127.0.0.1',()=>console.log('Madar portable trial: http://127.0.0.1:'+(process.env.PORT||8000)));
