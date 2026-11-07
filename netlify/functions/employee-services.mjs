import {createHash,randomUUID} from 'node:crypto';
import {getStore} from '@netlify/blobs';
import {createHandler} from '../../trial/core.mjs';
import {unseal,testOdoo} from './odoo-connection.mjs';
const allowed=[47,48,55,56,60,64,88], now=()=>new Date().toISOString();
const H={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'};
const reply=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{...H,'Content-Type':'application/json; charset=utf-8'}});
const fail=(m,s=400)=>{throw Object.assign(new Error(m),{status:s});};
export function beneficiary(me,b,employees){
 const id=me.role==='employee'?me.employee_id:b.employee_id;
 if(!id||!employees.some(e=>e.id===id))fail('اختر ملف موظف متاحًا لحسابك',403);
 return id;
}
export function values(b,partner,uid,ref){
 if(!allowed.includes(Number(b.category_id)))fail('نوع الطلب غير متاح');
 if(typeof b.subject!=='string'||!b.subject.trim()||b.subject.length>150)fail('اكتب عنوانًا حتى 150 حرفًا');
 if(typeof b.reason!=='string'||!b.reason.trim()||b.reason.length>4000)fail('اكتب تفاصيل الطلب حتى 4000 حرف');
 const amount=Number(b.amount);if(!Number.isFinite(amount)||amount<=0||amount>1000000||Math.abs(Math.round(amount*100)-amount*100)>0.00001)fail('المبلغ من 0.01 إلى 1,000,000 ريال');
 for(const k of ['date','date_start','date_end'])if(typeof b[k]!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(b[k])||!Number.isFinite(Date.parse(b[k]))||new Date(b[k]).toISOString().slice(0,10)!==b[k])fail('حدد تواريخ صحيحة');
 if(b.date_end<b.date_start)fail('نهاية الفترة تسبق بدايتها');
 // reason is an Odoo HTML field: escape all user text.
 const esc=x=>x.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const v={name:b.subject.trim(),category_id:Number(b.category_id),request_owner_id:uid,partner_id:partner,amount,date:b.date+' 12:00:00',date_start:b.date_start+' 00:00:00',date_end:b.date_end+' 23:59:59',reason:'<p>'+esc(b.reason).replace(/\n/g,'<br>')+'</p><p>'+ref+'</p>',reference:ref};
 for(const k of ['bank_name','account_iban'])if(b[k]){if(typeof b[k]!=='string'||b[k].length>100)fail('بيانات البنك غير صالحة');v[k]=b[k].trim();}
 return v;
}
export async function deliver(rpc,v,save){
 // This function is invoked once after a durable claim; never retry create on an uncertain result.
 const id=await rpc('approval.request','create',[v]);if(!Number.isSafeInteger(id)||id<=0)fail('لم يرجع أودو رقم الطلب',502);
 await save({odoo_id:id,phase:'draft'});
 const before=await rpc('approval.request','read',[[id]],{fields:['id','partner_id','category_id','approver_ids']});
 if(before.length!==1||before[0].partner_id?.[0]!==v.partner_id||before[0].category_id?.[0]!==v.category_id||!before[0].approver_ids?.length){await save({phase:'needs_review'});return {id,phase:'needs_review'};}
 try{await rpc('approval.request','action_confirm',[[id]]);}
 catch{await save({phase:'needs_review'});return {id,phase:'needs_review'};}
 const rows=await rpc('approval.request','read',[[id]],{fields:['id','name','request_status','partner_id']});
 if(rows.length!==1||rows[0].partner_id?.[0]!==v.partner_id)fail('تعذر التحقق من الطلب',502);
 if(!['pending','approved','refused','cancel'].includes(rows[0].request_status)){await save({phase:'needs_review'});return {id,phase:'needs_review'};}
 await save({phase:'sent',odoo_status:rows[0].request_status,odoo_name:rows[0].name});
 return {id,phase:'sent',status:rows[0].request_status};
}
export default async function service(req){
 const url=new URL(req.url);
 if(req.method==='GET'&&!url.searchParams.has('data'))return new Response(page,{headers:{...H,'Content-Type':'text/html; charset=utf-8'}});
 if(req.method==='GET'&&url.searchParams.get('data')==='script')return new Response(script,{headers:{...H,'Content-Type':'text/javascript; charset=utf-8'}});
 if(!['GET','POST'].includes(req.method))return reply({error:'طريقة غير مدعومة'},405);
 try{
 const handler=createHandler({stateStore:getStore({name:'madar-trial-state',consistency:'strong'}),fileStore:getStore('madar-trial-documents'),setupToken:process.env.MADAR_SETUP_TOKEN||'',secure:true});
 const read=async path=>{const r=await handler(new Request(url.origin+path,{headers:req.headers}));if(!r.ok)fail('سجّل الدخول إلى مدار أولًا',401);return r.json();};
 const me=await read('/api/me');if(!['owner','employee'].includes(me.role))fail('الخدمة متاحة لمالك المنصة والموظف',403);
 const data=await read('/api/data'),employees=data.employees||[];
 const store=getStore({name:'madar-self-service',consistency:'strong'});
 let entry=await store.getWithMetadata('state',{type:'json',consistency:'strong'}),state=entry?.data||{maps:{},requests:[]};
 const commit=async()=>{const r=await store.setJSON('state',state,entry?{onlyIfMatch:entry.etag}:{onlyIfNew:true});if(!r.modified)fail('حدث تعديل متزامن؛ حدّث الشاشة',409);entry=await store.getWithMetadata('state',{type:'json',consistency:'strong'});state=entry.data;};
 if(req.method==='GET')return reply({me:{name:me.name,role:me.role},employees:employees.map(e=>({id:e.id,name:e.name})),maps:me.role==='owner'?state.maps:{},requests:state.requests.filter(r=>me.role==='owner'||r.employee_id===me.employee_id)});
 if(req.headers.get('origin')!==url.origin||req.headers.get('x-csrf-token')!==me.csrf)fail('حدّث الصفحة وأعد المحاولة',403);
 const text=await req.text();if(text.length>12000)fail('الطلب كبير',413);
 let b;try{b=JSON.parse(text);}catch{fail('طلب غير صالح');}
 const saved=await getStore('madar-odoo-connection').get('connection-v1',{type:'json',consistency:'strong'});if(!saved)fail('أكمل إعداد اتصال أودو أولًا',409);
 const creds=unseal(saved.encrypted,process.env.MADAR_SETUP_TOKEN);
 const use=fn=>testOdoo(creds,fetch,fn);
 if(b.action==='catalog')return reply(await use(async rpc=>({categories:await rpc('approval.category','search_read',[[['id','in',allowed]]],{fields:['id','name'],order:'id'})})));
 if(b.action==='search'){
 if(me.role!=='owner')fail('للمالك فقط',403);
 if(typeof b.q!=='string'||b.q.trim().length<3||b.q.length>100)fail('اكتب ثلاثة أحرف على الأقل');
 return reply({partners:await use(async rpc=>{
 const f=await rpc('hr.employee','fields_get',[],{attributes:['type','relation']});
 const rels=['work_contact_id','address_home_id','user_partner_id'].filter(k=>f[k]?.relation==='res.partner');
 if(!rels.length)fail('لا توجد علاقة موظف مدعومة؛ راجع إعداد أودو',409);
 const staff=await rpc('hr.employee','search_read',[[['name','ilike',b.q.trim()]]],{fields:['id','name',...rels],limit:20});
 const results=[];for(const e of staff)for(const k of rels)if(e[k]?.[0]&&!results.some(x=>x.id===e[k][0]))results.push({id:e[k][0],name:e.name+' — '+e[k][1]});
 return results;
 })});
 }
 if(b.action==='map'){
 if(me.role!=='owner')fail('للمالك فقط',403);
 const eid=beneficiary(me,b,employees),pid=Number(b.partner_id);
 if(!Number.isSafeInteger(pid)||pid<=0)fail('اختر جهة الموظف من نتائج أودو');
 if(Object.entries(state.maps).some(([k,v])=>k!==eid&&v.partner_id===pid))fail('ملف أودو مرتبط بموظف آخر');
 if(state.requests.some(r=>r.employee_id===eid))fail('لا يمكن تبديل الربط بعد تقديم طلب؛ راجع مسؤول النظام',409);
 const rows=await use(async rpc=>{
 const f=await rpc('hr.employee','fields_get',[],{attributes:['relation']});
 const rels=['work_contact_id','address_home_id','user_partner_id'].filter(k=>f[k]?.relation==='res.partner');
 if(!rels.length)fail('تعذر التحقق من ملف الموظف',409);
 const domain=[...Array(rels.length-1).fill('|'),...rels.map(k=>[k,'=',pid])];
 const employees=await rpc('hr.employee','search_read',[domain],{fields:['id'],limit:2});
 if(employees.length!==1)fail('ملف أودو ليس مرتبطًا بموظف واحد؛ راجع الربط',409);
 return rpc('res.partner','read',[[pid]],{fields:['id','name','is_company']});
 });
 if(rows.length!==1||rows[0].is_company)fail('ملف أودو غير صالح');
 state.maps[eid]={partner_id:pid,name:rows[0].name,linked_by:me.id,linked_at:now()};await commit();return reply({ok:true});
 }
 if(b.action==='submit'){
 const eid=beneficiary(me,b,employees),mapping=state.maps[eid];if(!mapping)fail('لم يربط المسؤول هذا الموظف بملفه في أودو',409);
 if(typeof b.key!=='string'||! /^[a-f0-9-]{36}$/.test(b.key))fail('معرف الطلب غير صالح');
 const key=createHash('sha256').update(me.id+':'+b.key).digest('hex');
 const prior=state.requests.find(x=>x.key===key);if(prior)return reply({request:prior,duplicate:true});
 if(state.requests.length>=1000)fail('بلغت التجربة حد الطلبات',409);
 // Validate before claiming the operation or contacting Odoo.
 values(b,mapping.partner_id,1,'preview');
 const ref='MADAR-'+randomUUID(),record={key,id:randomUUID(),employee_id:eid,employee_name:employees.find(e=>e.id===eid).name,subject:b.subject,amount:Number(b.amount),phase:'processing',created:now(),created_by:me.id,reference:ref};
 state.requests.unshift(record);await commit();
 const save=async patch=>{const target=state.requests.find(r=>r.key===key);Object.assign(target,patch,{updated:now()});await commit();};
 try{const result=await use(async(rpc,uid)=>{const v=values(b,mapping.partner_id,uid,ref);const fields=await rpc('approval.request','fields_get',[],{attributes:['type']});for(const k of Object.keys(v)){if(!fields[k])delete v[k];else if(fields[k].type==='date'&&['date','date_start','date_end'].includes(k))v[k]=v[k].slice(0,10);}if(!v.partner_id||!v.category_id||!v.reference)fail('حقول ربط أودو غير متاحة');return deliver(rpc,v,save);});return reply({result});}
 catch{try{await save({phase:'needs_review'});}catch{}return reply({error:'لم نتمكن من تأكيد الإرسال. احتفظنا بالطلب للمراجعة؛ لا تنشئ نسخة جديدة قبل التحقق في أودو.'},409);}
 }
 if(b.action==='refresh'){
 const rows=state.requests.filter(r=>(me.role==='owner'||r.employee_id===me.employee_id)&&r.odoo_id).slice(0,100);
 if(!rows.length)return reply({ok:true});
 const result=await use(rpc=>rpc('approval.request','read',[rows.map(r=>r.odoo_id)],{fields:['id','name','request_status','partner_id']}));
 for(const r of rows){const x=result.find(x=>x.id===r.odoo_id);if(x&&x.partner_id?.[0]===state.maps[r.employee_id]?.partner_id)Object.assign(r,{odoo_status:x.request_status,odoo_name:x.name,checked_at:now()});}
 await commit();return reply({ok:true});
 }
 fail('إجراء غير متاح');
 }catch(e){return reply({error:e.status?e.message:'تعذرت العملية؛ تحقق من الاتصال والصلاحيات ثم حدّث الشاشة'},e.status||503);}
}
const page='<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>مدار | الخدمات الذاتية</title><link rel="stylesheet" href="/styles.css"><script defer src="/employee-services?data=script"></script><body><main class="content"><section class="panel"><div class="brand"><img src="/icons/madar.svg" width="48" height="48" alt="مدار"><strong>مدار</strong></div><h1>الخدمات الذاتية</h1><p id="welcome">جارٍ التحقق من حسابك…</p><p id="message" role="status" aria-live="polite"></p><div id="owner" hidden><h2>ربط ملف الموظف</h2><p>اختر الموظف ثم ابحث عن ملفه الصحيح في أودو وراجعه قبل الحفظ.</p><label>الموظف<select id="map-employee"></select></label><label>البحث في أودو<input id="q" minlength="3"></label><button id="search">بحث</button><label>ملف أودو<select id="partners"></select></label><button id="map">حفظ الربط</button><p id="mappings"></p></div><hr><h2>طلب جديد</h2><p>الاعتماد داخل أودو وفق المسار الموجود. إرسال الطلب لا يعني اعتماده أو صرفه.</p><form id="request"><div class="form-grid"><label id="employee-label">الموظف<select id="employee"></select></label><label>نوع الطلب<select id="category" required></select></label><label>العنوان<input id="subject" required maxlength="150"></label><label>المبلغ بالريال<input id="amount" type="number" min="0.01" max="1000000" step="0.01" required></label><label>تاريخ الطلب<input id="date" type="date" required></label><label>بداية الفترة<input id="date_start" type="date" required></label><label>نهاية الفترة<input id="date_end" type="date" required></label><label>البنك (إذا تطلبه نوع الطلب)<input id="bank_name" maxlength="100"></label><label>الآيبان (إذا تطلبه نوع الطلب)<input id="account_iban" maxlength="100" dir="ltr"></label><label>التفاصيل<textarea id="reason" required maxlength="4000"></textarea></label></div><button id="send" class="primary" disabled>إرسال إلى أودو</button></form><hr><h2>متابعة الطلبات</h2><button id="refresh">تحديث الحالات من أودو</button><div id="requests"></div><p><a href="/app">العودة إلى مدار</a> · <a href="/odoo-connection">إعداد الاتصال</a></p></section></main></body></html>';
const script=String.raw`'use strict';
const $=s=>document.querySelector(s);let csrf='',key=crypto.randomUUID(),busy=false;
async function call(body){const r=await fetch('/employee-services'+(body?'':'?data=1'),{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(55000)});const d=await r.json();if(!r.ok)throw Error(d.error||'تعذرت العملية');return d;}
function option(el,value,label){const x=document.createElement('option');x.value=value;x.textContent=label;el.append(x);}
const labels={processing:'جارٍ التحقق من الإرسال',needs_review:'يحتاج مراجعة في أودو',sent:'أُرسل إلى أودو',new:'مسودة في أودو',pending:'بانتظار الموافقة',approved:'موافق',refused:'مرفوض',cancel:'ملغى'};
async function load(){const d=await call();$('#welcome').textContent='أهلًا '+d.me.name;$('#owner').hidden=d.me.role!=='owner';$('#employee-label').hidden=d.me.role==='employee';for(const id of ['#employee','#map-employee']){const el=$(id),v=el.value;el.replaceChildren();for(const e of d.employees)option(el,e.id,e.name);if(v)el.value=v;}
$('#mappings').textContent=Object.entries(d.maps).map(([id,m])=>(d.employees.find(e=>e.id===id)?.name||id)+' ← '+m.name).join('، ');
$('#requests').replaceChildren();for(const r of d.requests){const box=document.createElement('article');box.className='panel';const title=document.createElement('h3');title.textContent=r.subject;const p=document.createElement('p');p.textContent=r.employee_name+' · '+r.amount+' ر.س · '+(labels[r.odoo_status]||labels[r.phase]||'غير معروف')+' · '+(r.odoo_name||r.reference);box.append(title,p);$('#requests').append(box);}if(!d.requests.length)$('#requests').textContent='لا توجد طلبات مقدمة من مدار بعد.';}
async function run(fn){if(busy)return;busy=true;$('#message').textContent='جارٍ التنفيذ…';try{await fn();$('#message').textContent='تمت العملية';}catch(e){$('#message').textContent=e.message;}finally{busy=false;}}
$('#search').onclick=()=>run(async()=>{const d=await call({action:'search',q:$('#q').value});$('#partners').replaceChildren();for(const p of d.partners)option($('#partners'),p.id,p.name+' ('+p.id+')');if(!d.partners.length)$('#message').textContent='لا توجد نتائج';});
$('#map').onclick=()=>run(async()=>{await call({action:'map',employee_id:$('#map-employee').value,partner_id:Number($('#partners').value)});await load();});
$('#refresh').onclick=()=>run(async()=>{await call({action:'refresh'});await load();});
$('#request').onsubmit=e=>{e.preventDefault();run(async()=>{const b={action:'submit',key,employee_id:$('#employee').value};for(const f of ['category','subject','amount','date','date_start','date_end','bank_name','account_iban','reason'])b[f==='category'?'category_id':f]=$('#'+f).value;$('#send').disabled=true;try{const d=await call(b);await load();const phase=d.request?.phase||d.result?.phase;if(phase==='sent'){key=crypto.randomUUID();$('#request').reset();}else throw Error('الطلب محفوظ للمراجعة في أودو؛ لم نؤكد إرساله للموافقين.');}finally{$('#send').disabled=false;}});};
(async()=>{try{const r=await fetch('/api/me');if(!r.ok)throw Error('سجّل دخولك في مدار أولًا');const me=await r.json();csrf=me.csrf;await load();const d=await call({action:'catalog'});for(const c of d.categories)option($('#category'),c.id,c.name);$('#send').disabled=!d.categories.length;}catch(e){$('#message').textContent=e.message;}})();
`;
export const config={path:'/employee-services'};
