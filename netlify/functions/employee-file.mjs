import {createHash,randomBytes} from 'node:crypto';
import {getStore} from '@netlify/blobs';
import {createHandler} from '../../trial/core.mjs';
import {testOdoo,unseal} from './odoo-connection.mjs';
const H={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const out=(d,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{...H,'Content-Type':'application/json; charset=utf-8'}});
const die=(m,s=400)=>{throw Object.assign(Error(m),{status:s});};
const sha=s=>createHash('sha256').update(s).digest('hex');
const fields=['name','identification_id','barcode','work_email','work_phone','mobile_phone','private_email','private_phone','job_id','job_title','department_id','parent_id','coach_id','company_id','address_id','work_location_id','country_id','birthday','gender','marital','children','passport_id','visa_no','visa_expire','permit_no','work_permit_expiration_date','country_of_birth','place_of_birth','bank_account_id','resource_calendar_id','contract_id','first_contract_date','departure_date','departure_reason_id','active','remaining_leaves','work_contact_id','address_home_id','user_partner_id','certificate','study_field','study_school','emergency_contact','emergency_phone'];
const specs=[
 ['contracts','العقود','hr.contract','employee_id',['name','date_start','date_end','state','wage','currency_id','job_id','department_id','resource_calendar_id']],
 ['payroll','كشوف الرواتب','hr.payslip','employee_id',['name','number','date_from','date_to','state','net_wage','basic_wage','gross_wage','currency_id','contract_id']],
 ['leave','الإجازات','hr.leave','employee_id',['name','date_from','date_to','number_of_days','state','holiday_status_id']],
 ['allocations','أرصدة واستحقاقات الإجازة','hr.leave.allocation','employee_id',['name','date_from','date_to','number_of_days','state','holiday_status_id']],
 ['loans','السلف والقروض','hr.loan','employee_id',['name','date','state','loan_amount','total_amount','total_paid_amount','balance_amount']],
 ['attendance','الحضور والانصراف','hr.attendance','employee_id',['check_in','check_out','worked_hours']],
 ['custody','العهد العينية','asset.account.request','employee_id',['name','state','date','description','date_request','date_return','asset_id','asset_description','date_delivery','end_date']],
 ['documents','المستندات (بيانات وصفية)','ir.attachment','res_id',['name','mimetype','file_size','create_date','res_model']]
];
export async function readProfile(rpc,eid){
 const schema=await rpc('hr.employee','fields_get',[],{attributes:['string','type','relation']});
 const selected=fields.filter(k=>schema[k]);const rows=await rpc('hr.employee','read',[[eid]],{fields:selected,context:{active_test:false}});
 if(rows.length!==1)die('ملف الموظف غير متاح',404);
 const sections=[];
 for(const [key,label,model,relation,wanted] of specs){
  try{
   const f=await rpc(model,'fields_get',[],{attributes:['string','type','relation']});
   if(!f[relation])throw Error('Unsupported relation');
   const cols=wanted.filter(k=>f[k]);
   const related=f[relation].relation;
   const lookup=related==='res.partner'?rows[0].address_home_id?.[0]:eid;
   if(related&& !['hr.employee','res.partner'].includes(related))throw Error('Unexpected employee relation');
   if(!lookup)throw Error('Missing source employee contact');
   const domain=[[relation,'=',lookup],...(model==='ir.attachment'?[['res_model','=','hr.employee']]:[])];
   const records=await rpc(model,'search_read',[domain],{fields:cols,limit:501,order:'id desc',context:{active_test:false}});
   sections.push({key,label,status:records.length>500?'partial':'ok',rows:records.slice(0,500),columns:Object.fromEntries(cols.map(k=>[k,f[k].string]))});
  }catch{sections.push({key,label,status:'unavailable',rows:[],columns:{}});}
 }
 return {employee:rows[0],labels:Object.fromEntries(selected.map(k=>[k,schema[k].string])),sections,synced_at:new Date().toISOString(),note:'المزامنة قراءة من أودو. المستندات بيانات وصفية؛ الملفات المرفقة والصور غير منسوخة.'};
}
export async function readProfiles(rpc,ids){
 const schema=await rpc('hr.employee','fields_get',[],{attributes:['string','type','relation']});
 const selected=fields.filter(k=>schema[k]),rows=await rpc('hr.employee','read',[ids],{fields:selected,context:{active_test:false}});
 const result=rows.map(e=>({employee:e,labels:Object.fromEntries(selected.map(k=>[k,schema[k].string])),sections:[],synced_at:new Date().toISOString(),note:'قراءة من أودو؛ المستندات متاحة بالتنزيل المحمي من أودو؛ الصور الشخصية غير منسوخة.'}));
 for(const [key,label,model,relation,wanted] of specs){
  try{
   const f=await rpc(model,'fields_get',[],{attributes:['string','type','relation']});if(!f[relation])throw Error('Unsupported relation');
   const related=f[relation].relation;
   if(related&&!['hr.employee','res.partner'].includes(related))throw Error('Unexpected relation');
   const sourceIds=related==='res.partner'?result.map(p=>p.employee.address_home_id?.[0]).filter(Boolean):ids;
   const cols=[...new Set([relation,...wanted.filter(k=>f[k])])],all=[];let cursor=0,partial=false;
   for(;;){const domain=[[relation,'in',sourceIds],['id','>',cursor],...(model==='ir.attachment'?[['res_model','=','hr.employee']]:[])];const page=await rpc(model,'search_read',[domain],{fields:cols,limit:1000,order:'id',context:{active_test:false}});all.push(...page);if(page.length<1000)break;if(all.length>=10000){partial=true;break;}const next=page.at(-1).id;if(next<=cursor)throw Error('No progress');cursor=next;}
   for(const profile of result){const mine=all.filter(r=>(Array.isArray(r[relation])?r[relation][0]:r[relation])===(related==='res.partner'?profile.employee.address_home_id?.[0]:profile.employee.id));profile.sections.push({key,label,status:partial||mine.length>500?'partial':'ok',rows:mine.slice(0,500),columns:Object.fromEntries(wanted.filter(k=>f[k]).map(k=>[k,f[k].string]))});}
  }catch{for(const profile of result)profile.sections.push({key,label,status:'unavailable',rows:[],columns:{}});}
 }
 return result;
}
export function nationalId(value){const s=String(value||'').trim().replace(/[٠-٩]/g,c=>String('٠١٢٣٤٥٦٧٨٩'.indexOf(c)));return /^[12][0-9]{9}$/.test(s)?s:null;}
export default async function employeeFile(req){
 const url=new URL(req.url);
 if(req.method==='GET'&&!url.searchParams.has('data'))return new Response(page,{headers:{...H,'Content-Type':'text/html; charset=utf-8'}});
 if(req.method==='GET'&&url.searchParams.get('data')==='script')return new Response(script,{headers:{...H,'Content-Type':'text/javascript; charset=utf-8'}});
 try{
  if(!['POST','GET'].includes(req.method))die('طريقة غير متاحة',405);
  const ws=getStore({name:'madar-trial-state',consistency:'strong'}),profiles=getStore({name:'madar-employee-profiles',consistency:'strong'});
  const handler=createHandler({stateStore:ws,fileStore:getStore('madar-trial-documents'),setupToken:process.env.MADAR_SETUP_TOKEN||'',secure:true});
  const auth=await handler(new Request(url.origin+'/api/me',{headers:req.headers}));if(!auth.ok)die('سجّل دخول مدار أولًا',401);const me=await auth.json();
  if(!['owner','employee'].includes(me.role))die('الخدمة للمالك والموظف',403);
  const entry=await ws.getWithMetadata('workspace-v1',{type:'json',consistency:'strong'}),s=entry.data;
  const accessible=s.records.filter(x=>x.module==='employees'&&(me.role==='owner'||x.id===me.employee_id));
  if(req.method==='GET'){
   const id=me.role==='employee'?me.employee_id:url.searchParams.get('employee');
   if(!id)return out({role:me.role,employees:accessible.map(e=>({id:e.id,name:e.name,imported:!!e.odoo_id})),issues:me.role==='owner'?accessible.filter(e=>e.odoo_id&&!s.users.some(u=>u.role==='employee'&&u.employee_id===e.id)).map(e=>e.name+': راجع الهوية الناقصة أو المكررة'):[],accounts:me.role==='owner'?s.users.filter(u=>u.role==='employee'&&u.odoo_id).map(u=>({id:u.id,name:u.name,employee_id:u.employee_id,active:!!u.active,identity_ending:u.username?.slice(-4)})):[]});
   if(!accessible.some(x=>x.id===id))die('ليست لديك صلاحية لهذا الملف',403);
   if(url.searchParams.has('download')){
    const doc=Number(url.searchParams.get('download')),employee=accessible.find(e=>e.id===id);
    if(!Number.isSafeInteger(doc)||doc<=0||!employee.odoo_id)die('مستند غير صالح',404);
    const conn=await getStore('madar-odoo-connection').get('connection-v1',{type:'json',consistency:'strong'});if(!conn)die('الاتصال غير متاح',503);
    const file=await testOdoo(unseal(conn.encrypted,process.env.MADAR_SETUP_TOKEN),fetch,async rpc=>{
     const rows=await rpc('ir.attachment','read',[[doc]],{fields:['id','name','res_id','res_model','file_size']});
     if(rows.length!==1||rows[0].res_model!=='hr.employee'||rows[0].res_id!==employee.odoo_id)die('لا تملك صلاحية لهذا المستند',403);
     if(rows[0].file_size>4*1024*1024)die('المستند يتجاوز حد تنزيل التجربة (4 ميغابايت)',413);
     const content=await rpc('ir.attachment','read',[[doc]],{fields:['datas']});
     if(!content[0]?.datas)die('محتوى المستند غير متاح',404);
     const bytes=Buffer.from(content[0].datas,'base64');if(bytes.length>4*1024*1024)die('المستند كبير',413);
     return {bytes,name:String(rows[0].name||'document').replace(/[\r\n]/g,'')};
    });
    return new Response(file.bytes,{headers:{...H,'Content-Type':'application/octet-stream','Content-Disposition':"attachment; filename*=UTF-8''"+encodeURIComponent(file.name)}});
   }
   return out({profile:await profiles.get(id,{type:'json',consistency:'strong'})});
  }
  if(req.headers.get('origin')!==url.origin||req.headers.get('x-csrf-token')!==me.csrf)die('حدّث الصفحة وأعد المحاولة',403);
  if(me.role!=='owner')die('إدارة المزامنة والتفعيل للمالك فقط',403);
  const raw=await req.text();if(raw.length>4096)die('طلب كبير',413);const b=JSON.parse(raw);
  const commit=async()=>{if(Buffer.byteLength(JSON.stringify(s))>4*1024*1024)die('مساحة بيانات التجربة ممتلئة',413);const r=await ws.setJSON('workspace-v1',s,{onlyIfMatch:entry.etag});if(!r.modified)die('تعديل متزامن؛ أعد المحاولة',409);};
  if(b.action==='activation'){
   const user=s.users.find(x=>x.id===b.user_id&&x.role==='employee'&&x.odoo_id);
   if(!user||!s.records.some(e=>e.module==='employees'&&e.id===user.employee_id&&e.status==='نشط'))die('الحساب غير متاح للتفعيل',404);if(user.active)die('الحساب مفعل بالفعل؛ إعادة كلمة المرور من إدارة الحسابات',409);
   const code=randomBytes(18).toString('base64url');user.activation_hash=sha(code);user.activation_expires=Date.now()+24*3600000;
   s.audit.push({user_id:me.id,actor:me.name,action:'إصدار رمز تفعيل',module:'users',record_id:user.id,created:new Date().toISOString()});await commit();
   return out({code,expires:'24 ساعة',name:user.name});
  }
  const connection=await getStore('madar-odoo-connection').get('connection-v1',{type:'json',consistency:'strong'});if(!connection)die('أكمل اتصال أودو أولًا',409);
  const credentials=unseal(connection.encrypted,process.env.MADAR_SETUP_TOKEN);
  if(b.action==='sync'){
   const cursor=Number(b.cursor||0);if(!Number.isSafeInteger(cursor)||cursor<0)die('نقطة استئناف غير صالحة');
   const data=await testOdoo(credentials,fetch,async rpc=>{
    const f=await rpc('hr.employee','fields_get',[],{attributes:['type']});
    const cols=['name','identification_id','work_email','work_phone','job_title','department_id','company_id','active','address_home_id'].filter(k=>f[k]);
    return rpc('hr.employee','search_read',[[['id','>',cursor]]],{fields:cols,limit:25,order:'id asc',context:{active_test:false}});
   });
   const conflicts=[],imported=[];let accounts=0;
   await profiles.setJSON('workspace-before-first-import',s,{onlyIfNew:true});
   const services=getStore({name:'madar-self-service',consistency:'strong'});
   const mapEntry=await services.getWithMetadata('state',{type:'json',consistency:'strong'}),mapState=mapEntry?.data||{maps:{},requests:[]};
   for(const e of data){
    const eid='odoo-employee-'+e.id,cid=s.settings?.mode==='self-service'?s.settings.company_id:'odoo-company-'+e.company_id?.[0],identity=nationalId(e.identification_id);
    if(s.records.length>=2000&&!s.records.some(r=>r.id===eid)){conflicts.push(e.name+': حد السجلات التجريبية');continue;}
    if(!e.company_id?.[0]){conflicts.push(e.name+': لا توجد شركة');continue;}
    if(!s.records.some(r=>r.id===cid))s.records.push({id:cid,module:'companies',company_id:null,name:e.company_id[1],status:'نشط',version:1,created:new Date().toISOString()});
    const existing=s.records.find(r=>r.id===eid);
    if(existing&&existing.odoo_id!==e.id){conflicts.push(e.name+': تعارض مصدر');continue;}
    const basic={...(s.settings?.mode==='self-service'?{company_id:cid}:{}),odoo_company_id:e.company_id?.[0],name:e.name,email:e.work_email||'',phone:e.work_phone||'',title:e.job_title||'غير مسجل',department:e.department_id?.[1]||'',status:e.active?'نشط':'غير نشط',odoo_id:e.id,source:'lanamed.odoo.com',updated:new Date().toISOString()};
    if(existing)Object.assign(existing,basic,{version:existing.version+1});
    else s.records.push({...basic,id:eid,module:'employees',company_id:cid,base:null,allowance:null,deduction:null,leave_balance:null,start_date:'',version:1,created:new Date().toISOString()});
    imported.push({id:eid,odoo_id:e.id});
    const pid=e.address_home_id?.[0];
    if(pid&&!mapState.maps[eid]&&!Object.values(mapState.maps).some(m=>m.partner_id===pid))mapState.maps[eid]={partner_id:pid,name:e.address_home_id[1],odoo_employee_id:e.id,linked_by:me.id,linked_at:new Date().toISOString(),source:'hr.employee.address_home_id'};
    if(!identity){conflicts.push(e.name+': الهوية غير مسجلة أو غير صالحة');continue;}
    const old=s.users.find(u=>u.username===identity||u.odoo_id===e.id);
    if(old){if(s.settings?.mode==='self-service')old.company_id=cid;if(old.odoo_id!==e.id||old.employee_id!==eid){conflicts.push(e.name+': هوية مستخدمة بحساب آخر');continue;}if(!e.active){old.active=0;s.sessions=s.sessions.filter(x=>x.user_id!==old.id);}if(old.username!==identity)conflicts.push(e.name+': تغير رقم الهوية؛ يحتاج مراجعة');continue;}
    s.users.push({id:randomBytes(12).toString('hex'),name:e.name,email:'odoo-'+e.id+'@employee.madar.invalid',username:identity,password:'disabled',role:'employee',company_id:cid,employee_id:eid,odoo_id:e.id,active:0});accounts++;
   }
   s.audit.push({user_id:me.id,actor:me.name,action:'مزامنة ملفات أودو',module:'employees',count:imported.length,created:new Date().toISOString()});s.audit=s.audit.slice(-1000);await commit();
   const mapped=await services.setJSON('state',mapState,mapEntry?{onlyIfMatch:mapEntry.etag}:{onlyIfNew:true});if(!mapped.modified)conflicts.push('تعارض تحديث ربط الطلبات؛ أعد المزامنة');
   return out({count:imported.length,accounts,conflicts,employees:imported,next:data.at(-1)?.id||cursor,done:data.length<25});
  }
  if(b.action==='details-batch'){
   const offset=Number(b.offset||0);if(!Number.isSafeInteger(offset)||offset<0)die('نقطة استئناف غير صالحة');
   const all=accessible.filter(e=>e.odoo_id).sort((a,b)=>a.odoo_id-b.odoo_id),batch=all.slice(offset,offset+100);
   if(!batch.length)return out({done:true,count:0,next:offset});
   const results=await testOdoo(credentials,fetch,rpc=>readProfiles(rpc,batch.map(e=>e.odoo_id)));
   for(const profile of results)await profiles.setJSON('odoo-employee-'+profile.employee.id,profile);
   return out({count:results.length,next:offset+batch.length,done:offset+batch.length>=all.length,sections:results[0]?.sections.map(s=>({label:s.label,status:s.status}))});
  }
  if(b.action==='details'){
   const e=accessible.find(e=>e.id===b.employee_id&&e.odoo_id);if(!e)die('اختر ملفًا مستوردًا');
   const profile=await testOdoo(credentials,fetch,rpc=>readProfile(rpc,e.odoo_id));
   await profiles.setJSON(e.id,profile);
   return out({ok:true,sections:profile.sections.map(x=>({label:x.label,status:x.status,count:x.rows.length}))});
  }
  die('إجراء غير متاح');
 }catch(e){return out({error:e.status?e.message:'تعذرت المزامنة؛ راجع الاتصال والصلاحيات ثم أعد المحاولة'},e.status||503);}
}
const page='<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>مدار | ملف الموظف</title><link rel="stylesheet" href="/styles.css"><script defer src="/employee-file?data=script"></script><body><main class="content"><section class="panel"><div class="brand"><img alt="مدار" width="48" height="48" src="/icons/madar.svg"><strong>مدار — الخدمات الذاتية</strong></div><h1>ملف الموظف</h1><p id="message" role="status" aria-live="polite"></p><section id="activation"><h2>تفعيل حساب الموظف</h2><p>بعد إصدار المسؤول رمز تفعيل خاص، أدخل رقم هويتك والرمز واختر كلمة مرورك. الرمز صالح ليوم ويستخدم مرة واحدة.</p><form id="activate"><label>رقم الهوية<input id="identity" inputmode="numeric" autocomplete="username" required></label><label>رمز التفعيل<input id="code" autocomplete="off" required></label><label>كلمة المرور الجديدة<input id="newpassword" type="password" autocomplete="new-password" minlength="12" maxlength="200" required></label><button>تفعيل الحساب</button></form></section><section id="admin" hidden><h2>إدارة ملفات الموظفين</h2><button id="sync" class="primary">مزامنة الموظفين من أودو</button><p>تستورد الحسابات بحالة غير مفعلة. لن تتغير كلمات مرور الحسابات القائمة. البيانات المالية الناقصة لا تعتبر صفرًا.</p><label>ملف الموظف<select id="employee"></select></label><button id="details">مزامنة تفاصيل الملف المحدد</button><button id="all-details">مزامنة تفاصيل جميع الملفات</button><button id="view">عرض الملف</button><h3>حالات تحتاج مراجعة</h3><p id="syncissues"></p><h3>تفعيل حساب</h3><label>الحساب<select id="accounts"></select></label><button id="issue">إصدار رمز تفعيل</button><p id="issued" role="status"></p></section><div id="profile"></div><p><a href="/app">دخول مدار</a> · <a href="/employee-services">الطلبات والخدمات الذاتية</a></p></section></main></body></html>';
const script=String.raw`'use strict';const $=s=>document.querySelector(s);let csrf='',state={},busy=false;
async function call(body,employee){const r=await fetch('/employee-file?data=1'+(employee?'&employee='+encodeURIComponent(employee):''),{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(55000)});const d=await r.json();if(!r.ok)throw Error(d.error||'تعذرت العملية');return d;}
function opt(el,v,t){const o=document.createElement('option');o.value=v;o.textContent=t;el.append(o);}
async function list(){state=await call();$('#syncissues').textContent=state.issues?.length?state.issues.length+' حالة: '+state.issues.join('، '):'لا توجد حسابات مستوردة تحتاج مطابقة هوية.';for(const id of ['#employee','#accounts'])$(id).replaceChildren();for(const e of state.employees||[])if(e.imported)opt($('#employee'),e.id,e.name);for(const a of state.accounts||[])opt($('#accounts'),a.id,a.name+' · '+(a.active?'مفعل':'ينتظر التفعيل')+' · هوية تنتهي '+a.identity_ending);}
function text(v){return v===false||v===null||v===undefined?'غير مسجل':Array.isArray(v)?(v.length===2&&typeof v[0]==='number'?v[1]:v.join('، ')):String(v);}
async function view(id){const d=await call(null,id);$('#profile').replaceChildren();if(!d.profile){$('#profile').textContent='تفاصيل الملف لم تزامن بعد.';return;}const p=d.profile;const h=document.createElement('h2');h.textContent=p.employee.name;$('#profile').append(h);const note=document.createElement('p');note.textContent='آخر مزامنة: '+new Date(p.synced_at).toLocaleString('ar-SA')+' · '+p.note;$('#profile').append(note);
function table(title,rows,cols){const section=document.createElement('section');section.className='panel';const heading=document.createElement('h3');heading.textContent=title;section.append(heading);const wrap=document.createElement('div');wrap.className='table-wrap';const table=document.createElement('table');const head=document.createElement('tr');for(const label of Object.values(cols)){const th=document.createElement('th');th.textContent=label;head.append(th);}table.append(head);for(const row of rows){const tr=document.createElement('tr');for(const k of Object.keys(cols)){const td=document.createElement('td');if(k==='download'){const a=document.createElement('a');a.textContent='تنزيل';a.href='/employee-file?data=1&employee='+encodeURIComponent(id)+'&download='+encodeURIComponent(row.id);td.append(a);}else td.textContent=text(row[k]);tr.append(td);}table.append(tr);}wrap.append(table);section.append(wrap);$('#profile').append(section);}
table('الملف الوظيفي والشخصي',Object.entries(p.labels).map(([k,v])=>({label:v,value:text(p.employee[k])})),{label:'البيان',value:'القيمة'});
for(const s of p.sections){if(s.status==='unavailable'){const x=document.createElement('p');x.textContent=s.label+': غير متاح بالحساب الحالي أو غير مثبت في أودو';$('#profile').append(x);}else table(s.label+' — سجلات متاحة: '+s.rows.length+(s.status==='partial'?' (عرض جزئي)':''),s.rows,s.key==='documents'?{...s.columns,download:'الملف'}:s.columns);}}
async function run(fn){if(busy)return;busy=true;$('#message').textContent='جارٍ التنفيذ…';try{await fn();}catch(e){$('#message').textContent=e.message;}finally{busy=false;}}
$('#activate').onsubmit=async e=>{e.preventDefault();run(async()=>{const r=await fetch('/api/activate-employee',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identity:$('#identity').value,code:$('#code').value,password:$('#newpassword').value})});const d=await r.json();if(!r.ok)throw Error(d.error);$('#activate').reset();$('#message').textContent='تم التفعيل. ادخل مدار برقم الهوية وكلمة المرور التي اخترتها.';});};
$('#sync').onclick=()=>run(async()=>{let cursor=0,total=0,conflicts=[];do{const d=await call({action:'sync',cursor});total+=d.count;conflicts.push(...d.conflicts);$('#message').textContent='تمت مزامنة '+total+' ملفًا…';if(d.done)break;if(d.next<=cursor)throw Error('توقف تقدم المزامنة');cursor=d.next;}while(true);await list();$('#message').textContent='تمت مزامنة '+total+' ملفًا. الحالات التي تحتاج مراجعة: '+conflicts.join('، ');});
$('#details').onclick=()=>run(async()=>{const d=await call({action:'details',employee_id:$('#employee').value});await view($('#employee').value);$('#message').textContent=d.sections.map(s=>s.label+': '+(s.status==='ok'?'تمت المزامنة ('+s.count+')':s.status==='partial'?'جزئي':'غير متاح')).join('، ');});
$('#all-details').onclick=()=>run(async()=>{let offset=0,n=0,issues=new Set();do{const d=await call({action:'details-batch',offset});n+=d.count;for(const x of d.sections||[])if(x.status!=='ok')issues.add(x.label+': '+(x.status==='partial'?'جزئي':'غير متاح'));$('#message').textContent='مزامنة التفاصيل: '+n+' ملفًا…';if(d.done)break;offset=d.next;}while(true);$('#message').textContent='اكتملت مزامنة تفاصيل '+n+' ملفًا. '+(issues.size?'أقسام تحتاج مراجعة: '+[...issues].join('، '):'تمت قراءة الأقسام المتاحة.');});
$('#view').onclick=()=>run(()=>view($('#employee').value));
$('#issue').onclick=()=>run(async()=>{const d=await call({action:'activation',user_id:$('#accounts').value});$('#issued').textContent='رمز '+d.name+': '+d.code+' — صالح '+d.expires+'. سلّمه للموظف مباشرة عبر وسيلة خاصة.';$('#message').textContent='أُصدر رمز التفعيل.';});
(async()=>{try{const r=await fetch('/api/me');if(!r.ok){$('#message').textContent='لتفعيل حسابك استخدم الرمز الذي استلمته من المسؤول. للمزامنة سجّل دخول حساب المالك.';return;}const me=await r.json();csrf=me.csrf;$('#activation').hidden=true;if(me.role==='owner'){$('#admin').hidden=false;await list();}else if(me.role==='employee')await view(me.employee_id);else throw Error('الخدمة للموظف والمالك');}catch(e){$('#message').textContent=e.message;}})();
`;
export const config={path:'/employee-file'};
