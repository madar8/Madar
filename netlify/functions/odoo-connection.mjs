import {createHash,randomBytes,createCipheriv,createDecipheriv,timingSafeEqual} from 'node:crypto';
import {getStore} from '@netlify/blobs';
import {createHandler} from '../../trial/core.mjs';

const ODOO='https://lanamed.odoo.com';
const DATABASE='telenocodoo-lanamedicalco-main-4789102';
const KEY='connection-v1';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{...headers,'Content-Type':'application/json; charset=utf-8'}});
export function seal(value,secret){
 if(typeof secret!=='string'||secret.length<32)throw new Error('Storage key unavailable');
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',createHash('sha256').update('madar-odoo-v1:'+secret).digest(),iv);
 const data=Buffer.concat([cipher.update(JSON.stringify(value),'utf8'),cipher.final()]);
 return {iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:data.toString('base64')};
}
export function unseal(value,secret){
 if(typeof secret!=='string'||secret.length<32)throw new Error('Storage key unavailable');
 const cipher=createDecipheriv('aes-256-gcm',createHash('sha256').update('madar-odoo-v1:'+secret).digest(),Buffer.from(value.iv,'base64'));
 cipher.setAuthTag(Buffer.from(value.tag,'base64'));
 return JSON.parse(Buffer.concat([cipher.update(Buffer.from(value.data,'base64')),cipher.final()]).toString('utf8'));
}
function same(a,b){const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length>0&&x.length===y.length&&timingSafeEqual(x,y);}
export async function testOdoo({login,password,database,inspect=false},fetcher=fetch){
 if(typeof login!=='string'||!login.trim()||login.length>254||typeof password!=='string'||!password||password.length>500||database!==DATABASE)throw new Error('أدخل بيانات الاتصال الصحيحة');
 let cookie='';
 async function rpc(path,params){
  const response=await fetcher(ODOO+path,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify({jsonrpc:'2.0',method:'call',id:1,params})});
  if(!response.ok)throw new Error('تعذر اتصال مدار بأودو؛ تحقق من الخدمة وبيانات الدخول');
  const cookies=response.headers.getSetCookie?.()||[response.headers.get('set-cookie')||''];
  const session=cookies.find(x=>x.startsWith('session_id='));if(session)cookie=session.split(';')[0];
  const result=await response.json();if(result.error)throw new Error('رفض أودو المصادقة أو قراءة بيانات الحساب');
  if(!Object.hasOwn(result,'result'))throw new Error('استجابة أودو غير متوقعة');return result.result;
 }
 const auth=await rpc('/web/session/authenticate',{db:database,login:login.trim(),password});
 if(!auth?.uid||!cookie)throw new Error('لم ينجح تسجيل الدخول إلى أودو');
 const users=await rpc('/web/dataset/call_kw',{model:'res.users',method:'read',args:[[auth.uid]],kwargs:{fields:['name','login']}});
 if(!Array.isArray(users)||users.length!==1||users[0].id!==auth.uid)throw new Error('تعذر التحقق من حساب أودو');
 if(inspect){
  const categories=await rpc('/web/dataset/call_kw',{model:'approval.category',method:'search_read',args:[[]],kwargs:{fields:['id','name'],limit:100,order:'id asc'}});
  const fields=await rpc('/web/dataset/call_kw',{model:'approval.request',method:'fields_get',args:[],kwargs:{attributes:['string','type','required','readonly','relation']}});
  if(!Array.isArray(categories)||!fields||typeof fields!=='object')throw new Error('استجابة أودو غير متوقعة');
  const allowed=['name','category_id','request_owner_id','partner_id','amount','date','date_start','date_end','reason','reference','request_status','approver_ids'];
  return {categories:categories.map(x=>({id:x.id,name:x.name})),fields:Object.fromEntries(allowed.filter(k=>fields[k]).map(k=>[k,fields[k]])),read_only:true,checked_at:new Date().toISOString()};
 }
 return {uid:auth.uid,name:users[0].name,login:users[0].login,url:ODOO,database,checked_at:new Date().toISOString(),read_only_test:true};
}

const script=String.raw`'use strict';
const $=s=>document.querySelector(s);let csrf='';
async function call(url,body){const r=await fetch(url,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(55000)});const d=await r.json();if(!r.ok)throw new Error(d.error||'تعذر الاتصال');return d;}
async function refresh(){const d=await call('/odoo-connection?status=1');$('#state').textContent=d.configured?'اتصال محفوظ — آخر اختبار ناجح: '+d.account.name+' — '+new Date(d.account.checked_at).toLocaleString('ar-SA'):'لم يُحفظ اتصال بأودو بعد';if(d.configured)$('#login').value=d.account.login;}
$('#connection').onsubmit=async e=>{e.preventDefault();const b=$('#connect');b.disabled=true;$('#message').textContent='جارٍ اختبار المصادقة وقراءة بيانات الحساب فقط…';try{const d=await call('/odoo-connection',{login:$('#login').value,password:$('#password').value,database:$('#database').value});$('#password').value='';$('#message').textContent='نجح الاتصال من مدار إلى أودو وحُفظ بأمان. الحساب: '+d.account.name+'. لم يُنشأ أو يُرسل أي طلب.';await refresh();}catch(e){$('#message').textContent=e.message;}finally{b.disabled=false;}};
$('#inspect').onclick=async()=>{const b=$('#inspect');b.disabled=true;$('#inspection').textContent='جارٍ قراءة أنواع الموافقات وحقول الطلب…';try{const d=await call('/odoo-connection',{action:'inspect'});$('#inspection').textContent='تم فحص أودو للقراءة فقط. أنواع الموافقات: '+d.categories.map(x=>x.name+' ('+x.id+')').join('، ')+'\nحقول الطلب: '+Object.entries(d.fields).map(([k,v])=>v.string+' ['+k+']').join('، ')+'. لم يُنشأ أي طلب.';}catch(e){$('#inspection').textContent=e.message;}finally{b.disabled=false;}};
(async()=>{try{const me=await call('/api/me');if(me.role!=='owner')throw new Error('إعداد الاتصال متاح لمالك مدار فقط');csrf=me.csrf;$('#connect').disabled=false;await refresh();}catch(e){$('#state').textContent=e.message+' — سجّل دخول حساب المالك في مدار ثم افتح هذه الصفحة.';}})();`;
const html=`<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>مدار | الاتصال بأودو</title><link rel="stylesheet" href="/styles.css"><script src="/odoo-connection?asset=js" defer></script><body><main class="content"><section class="panel"><div class="brand"><img src="/icons/madar.svg" width="48" height="48" alt="شعار مدار"><strong>مدار</strong></div><h1>الاتصال بأودو</h1><p>ربط مدار بقاعدة لانا. هذه الخطوة تختبر الدخول وقراءة بيانات الحساب فقط، ولا تنشئ طلبات أو تغيّر الموافقين.</p><p id="state" role="status">جارٍ التحقق من حساب مدار…</p><form id="connection"><div class="form-grid"><label>عنوان أودو<input value="${ODOO}" readonly></label><label>قاعدة البيانات<input id="database" value="${DATABASE}" readonly></label><label>بريد أودو أو اسم المستخدم<input id="login" required maxlength="254" autocomplete="username"></label><label>كلمة مرور أودو<input id="password" type="password" required maxlength="500" autocomplete="current-password"></label></div><p class="note">أدخل بيانات أودو هنا فقط. تُحفظ مشفرة في تخزين مدار الخاص ولا تظهر في GitHub أو في الردود. نجاح هذا الاتصال لا يعني تفعيل إرسال الطلبات بعد.</p><button id="connect" class="primary section-space" disabled>اختبار الاتصال وحفظه</button><p id="message" role="status" aria-live="polite"></p></form><hr><h2>فحص مسار الطلبات</h2><p>قراءة أنواع موافقات أودو وحقول الطلبات دون إنشاء أو تعديل أي سجل.</p><button id="inspect" class="primary">فحص مسارات أودو</button><p id="inspection" role="status" aria-live="polite"></p><p><a href="/app">العودة إلى مدار</a></p></section></main></body></html>`;

export default async function connection(request){
 const url=new URL(request.url);
 if(request.method==='GET'&&url.searchParams.get('asset')==='js')return new Response(script,{headers:{...headers,'Content-Type':'text/javascript; charset=utf-8'}});
 if(request.method==='GET'&&!url.searchParams.has('status'))return new Response(html,{headers:{...headers,'Content-Type':'text/html; charset=utf-8'}});
 if(!['GET','POST'].includes(request.method))return json({error:'طريقة غير مدعومة'},405);
 try{
  const handler=createHandler({stateStore:getStore({name:'madar-trial-state',consistency:'strong'}),fileStore:getStore({name:'madar-trial-documents',consistency:'strong'}),setupToken:process.env.MADAR_SETUP_TOKEN||'',secure:true});
  const meResponse=await handler(new Request(url.origin+'/api/me',{headers:request.headers}));
  if(!meResponse.ok)return json({error:'سجّل الدخول إلى مدار أولًا'},401);
  const me=await meResponse.json();if(me.role!=='owner')return json({error:'إعداد الاتصال متاح لمالك مدار فقط'},403);
  const store=getStore({name:'madar-odoo-connection',consistency:'strong'});
  if(request.method==='GET'){
   const record=await store.get(KEY,{type:'json',consistency:'strong'});
   return json(record?{configured:true,account:record.account}:{configured:false});
  }
  if(request.headers.get('origin')!==url.origin||!same(request.headers.get('x-csrf-token'),me.csrf))return json({error:'حدّث الصفحة وأعد المحاولة من مدار'},403);
  if(Number(request.headers.get('content-length')||0)>4096)return json({error:'حجم بيانات غير صالح'},413);
  const reader=request.body?.getReader();let size=0,chunks=[];
  if(!reader)return json({error:'بيانات الاتصال مطلوبة'},400);
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4096){await reader.cancel();return json({error:'حجم بيانات غير صالح'},413);}chunks.push(Buffer.from(value));}
  let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return json({error:'بيانات غير صالحة'},400);}
  if(body.action==='inspect'){
   const record=await store.get(KEY,{type:'json',consistency:'strong'});
   if(!record)return json({error:'احفظ اتصال أودو أولًا'},409);
   const credentials=unseal(record.encrypted,process.env.MADAR_SETUP_TOKEN);
   try{return json(await testOdoo({...credentials,inspect:true}));}catch{return json({error:'تعذرت قراءة مسارات الموافقات. تحقق من صلاحية حساب الربط لقراءة الموافقات في أودو.'},400);}
  }
  // Encrypt BEFORE contacting Odoo so invalid storage settings cannot cause a partial success.
  const encrypted=seal({login:body.login,password:body.password,database:body.database},process.env.MADAR_SETUP_TOKEN);
  let account;try{account=await testOdoo(body);}catch(e){return json({error:e.message.startsWith('أدخل')?e.message:'لم ينجح اختبار الاتصال بأودو. تحقق من بيانات الدخول وإمكانية اتصال الخادم.'},400);}
  await store.setJSON(KEY,{encrypted,account,updated_by:me.id});
  return json({connected:true,saved:true,account});
 }catch{return json({error:'تعذر حفظ اتصال أودو؛ راجع إعدادات تشغيل مدار'},503);}
}
export const config={path:'/odoo-connection'};
