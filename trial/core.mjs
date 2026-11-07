import {odooConnectionCheck,odooEmployeeById} from './odoo-readonly.mjs';
import {randomBytes,createHash,scrypt as scryptCallback,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import C from './config.json' with {type:'json'};
const scrypt=promisify(scryptCallback);
export const MAX_FILE=2*1024*1024,MAX_STATE=4*1024*1024,MAX_RECORDS=2000,MAX_FILES_TOTAL=20*1024*1024;
const BODY_LIMIT=3*1024*1024,SESSION_MS=8*3600000;
const id=()=>randomBytes(12).toString('hex'),token=()=>randomBytes(32).toString('base64url');
const sha=s=>createHash('sha256').update(s).digest('hex');
const stamp=()=>new Date().toISOString();
const day=()=>new Date(Date.now()+3*3600000).toISOString().slice(0,10);
export class Problem extends Error{constructor(message,status=400,persist=false){super(message);this.status=status;this.persist=persist;}}
const fail=(message,status=400)=>{throw new Problem(message,status);};
const same=(a,b)=>{const x=Buffer.isBuffer(a)?a:Buffer.from(String(a??'')),y=Buffer.isBuffer(b)?b:Buffer.from(String(b??''));return x.length===y.length&&timingSafeEqual(x,y);};
export async function hashPassword(password){if(typeof password!=='string'||password.length<12||password.length>200)fail('كلمة المرور من 12 إلى 200 حرف');const salt=randomBytes(16).toString('hex');return salt+':'+Buffer.from(await scrypt(password,Buffer.from(salt,'hex'),64,{N:16384,r:8,p:1})).toString('hex');}
async function verify(password,stored){if(typeof password!=='string'||password.length>200)return false;const [salt,digest]=String(stored||'').split(':');if(!/^[a-f0-9]{32}$/.test(salt)||!/^[a-f0-9]{128}$/.test(digest))return false;const result=Buffer.from(await scrypt(password,Buffer.from(salt,'hex'),64,{N:16384,r:8,p:1}));return same(result,Buffer.from(digest,'hex'));}
export const emptyState=()=>({format:'madar-trial-v1',users:[],sessions:[],records:[],audit:[],attempts:{}});
export function convertToSelfService(s){
 if(s.settings?.mode==='self-service')return {already:true,removed:0};
 const names=new Set(['شركة أفق التجريبية','شركة نواة التجريبية','شركة مدى التجريبية']);
 const demoCompanies=new Set(s.records.filter(r=>r.module==='companies'&&names.has(r.name)&&r.email==='demo@example.test'&&r.contact==='مسؤول تجريبي').map(r=>r.id));
 const removed=s.records.filter(r=>demoCompanies.has(r.id)||(!r.odoo_id&&demoCompanies.has(r.company_id)));
 const removedIds=new Set(removed.map(r=>r.id));
 const sourceCompanies=s.records.filter(r=>r.module==='companies'&&!removedIds.has(r.id));
 const companyName=sourceCompanies.find(r=>r.id.startsWith('odoo-company-'))?.name||sourceCompanies[0]?.name||'جهة العمل';
 const cid='madar-organization';
 s.records=s.records.filter(r=>!removedIds.has(r.id)&&r.module!=='companies');
 for(const r of s.records){if(r.company_id){r.source_company_id??=r.company_id;r.company_id=cid;}}
 s.records.push({id:cid,module:'companies',company_id:null,name:companyName,status:'نشط',version:1,created:stamp()});
 const removedUsers=new Set(s.users.filter(u=>u.role!=='owner'&&removedIds.has(u.employee_id)).map(u=>u.id));
 s.users=s.users.filter(u=>!removedUsers.has(u.id));for(const u of s.users){if(u.company_id){u.source_company_id??=u.company_id;u.company_id=cid;}}
 s.sessions=s.sessions.filter(x=>!removedUsers.has(x.user_id));
 s.settings={...s.settings,mode:'self-service',company_id:cid,company_name:companyName,converted_at:stamp(),removed_demo_records:removed.length};
 return {already:false,removed:removed.length};
}
const HEADERS={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'; base-uri 'none'"};
function response(data,status=200,extra={}){return new Response(JSON.stringify(data),{status,headers:{...HEADERS,...extra}});}
function cookie(value,secure,clear=false){return `madar_session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${clear?0:28800}${secure?'; Secure':''}`;}
function required(d,k){if(typeof d[k]!=='string'||!d[k].trim()||d[k].length>12000)fail('حقل مطلوب أو طويل: '+k);}
function date(d,k,optional=false){if(optional&&!d[k])return;if(typeof d[k]!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(d[k])||!Number.isFinite(Date.parse(d[k]))||new Date(d[k]).toISOString().slice(0,10)!==d[k])fail('تاريخ غير صالح: '+k);}
function integer(d,k,defaultValue=0){d[k]??=defaultValue;if(!Number.isSafeInteger(d[k])||d[k]<0||d[k]>100000000)fail('قيمة رقمية غير صالحة: '+k);}
const email=e=>typeof e==='string'&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)&&e.length<=254;
function publicUser(u){const {password,activation_hash,activation_expires,...out}=u;return out;}
function visible(u,r,m){if(['owner','hr'].includes(u.role))return true;if(r.company_id!==u.company_id)return false;if(u.role==='employee'){if(m==='employees')return r.id===u.employee_id;if(['requests','attendance','contracts','documents'].includes(m))return r.employee_id===u.employee_id;if(m==='tickets')return r.created_by===u.id;}return true;}
function get(s,m,rid){const r=s.records.find(r=>r.module===m&&r.id===rid);if(!r)fail('السجل غير موجود',404);return r;}
function permitted(u,m,write=false){if(!(write?C.write:C.read)[u.role]?.includes(m))fail('ليست لديك صلاحية',403);}
function list(s,u,m){permitted(u,m);return s.records.filter(r=>r.module===m&&visible(u,r,m)).map(r=>{const {module,...out}=structuredClone(r);if(m==='payroll'&&u.role==='employee'){if(r.status!=='معتمد')return null;out.items=out.items.filter(x=>x.employee_id===u.employee_id);if(!out.items.length)return null;out.total=out.items.reduce((n,x)=>n+x.net,0);}return out;}).filter(Boolean).reverse();}
function audit(s,u,action,module,rid=null,cid=null){s.audit.push({actor:u.name,user_id:u.id,action,module,record_id:rid,company_id:cid,created:stamp()});s.audit=s.audit.slice(-1000);}
function insert(s,m,cid,d){if(s.records.length>=MAX_RECORDS)fail('بلغت التجربة حد 2000 سجل؛ صدّر بياناتك قبل التوسع',413);const now=stamp(),r={...d,id:id(),module:m,company_id:cid||null,version:1,created:now,updated:now};s.records.push(r);return r;}
function update(r,d,version){if(version!==r.version)fail('السجل تغير؛ حدّث الصفحة ثم أعد المحاولة',409);const keep={id:r.id,module:r.module,company_id:r.company_id,created:r.created,version:r.version+1,updated:stamp()};Object.keys(r).forEach(k=>delete r[k]);Object.assign(r,d,keep);return r;}
function dataOnly(r){return Object.fromEntries(Object.entries(r).filter(([k])=>!['id','module','company_id','created','updated','version'].includes(k)));}
function cleanRecord(r){const {module,...out}=r;return out;}
function validate(s,u,m,b,old){
 const allowed=new Set([...C.modules[m],'company_id','version']);if(Object.keys(b).some(k=>!allowed.has(k)))fail('حقول غير مدعومة');
 const d=Object.fromEntries(Object.entries(b).filter(([k])=>C.modules[m].includes(k)));
 for(const [k,v]of Object.entries(d)){if(['base','allowance','deduction','leave_balance','openings','amount','tax_bps'].includes(k))continue;if(typeof v!=='string'||v.length>12000)fail('نوع بيانات غير صالح: '+k);}
 let cid=old?.company_id||b.company_id;
 if(m==='companies')cid=null;else{if(!['owner','hr'].includes(u.role))cid=u.company_id;if(!cid)fail('اختر الشركة');const co=get(s,'companies',cid);if(!old&&co.status==='موقوف')fail('الشركة موقوفة');}
 if(C.states[m]){const key=m==='candidates'?'stage':'status';d[key]??=old?.[key]||(m==='requests'?'معلق':['candidates','tickets'].includes(m)?'جديد':['companies','employees'].includes(m)?'نشط':m==='jobs'?'مفتوحة':'مسودة');if(!C.states[m].includes(d[key]))fail('حالة غير صالحة');}
 if(['companies','employees','candidates'].includes(m))required(d,'name');
 if(['jobs','contracts','tickets','invoices'].includes(m))required(d,'title');
 if(m==='companies')required(d,'contact');
 if(m==='employees'){required(d,'title');date(d,'start_date');for(const k of ['base','allowance','deduction','leave_balance'])integer(d,k,k==='leave_balance'?21:0);}
 if(m==='jobs')integer(d,'openings',1);
 if(m==='candidates'&&get(s,'jobs',d.job_id).company_id!==cid)fail('الوظيفة خارج الشركة',403);
 if(['contracts','requests','attendance','documents'].includes(m)){d.employee_id=u.role==='employee'?u.employee_id:d.employee_id;if(!d.employee_id)fail('اختر الموظف');if(get(s,'employees',d.employee_id).company_id!==cid)fail('الموظف خارج الشركة',403);}
 if(['requests','contracts'].includes(m)){date(d,'start_date');date(d,'end_date');if(d.end_date<d.start_date)fail('تاريخ النهاية يسبق البداية');}
 if(m==='requests'){if(!['إجازة','خطاب تعريف','طلب عام'].includes(d.kind))fail('نوع الطلب غير صالح');d.status='معلق';}
 if(m==='attendance'){if(old)fail('استخدم إجراء الانصراف');if(d.day||d.check_in||d.check_out)fail('وقت الحضور يسجل تلقائيًا');d.day=day();d.check_in=stamp();d.check_out='';if(s.records.some(r=>r.module===m&&r.employee_id===d.employee_id&&r.company_id===cid&&r.day===d.day))fail('تم تسجيل حضور اليوم',409);}
 if(m==='invoices'){integer(d,'amount');integer(d,'tax_bps');date(d,'due_date');if(d.tax_bps>10000)fail('نسبة الضريبة غير صالحة');}
 if(m==='tickets'&&!['عادي','عاجل'].includes(d.priority))fail('الأولوية غير صالحة');
 d.created_by=old?.created_by||u.id;return {cid,d};
}
function createRecord(s,u,m,b,rid){permitted(u,m,true);const old=rid?get(s,m,rid):null;if(old&&!visible(u,old,m))fail('ليست لديك صلاحية',403);if(old&&(m==='requests'||u.role==='employee'))fail('لا يسمح بتعديل الطلب بعد إرساله');const {cid,d}=validate(s,u,m,b,old);const out=old?update(old,d,b.version):insert(s,m,cid,d);audit(s,u,old?'تعديل':'إنشاء',m,out.id,cid);return cleanRecord(out);}
function payroll(s,u,b){if(!['owner','hr'].includes(u.role))fail('ليست لديك صلاحية',403);const cid=b.company_id;get(s,'companies',cid);if(typeof b.period!=='string'||!/^\d{4}-\d{2}$/.test(b.period))fail('الفترة بصيغة YYYY-MM');date({d:b.period+'-01'},'d');if(s.records.some(r=>r.module==='payroll'&&r.company_id===cid&&r.period===b.period))fail('مسير الشهر موجود بالفعل',409);
 const employees=s.records.filter(r=>r.module==='employees'&&r.company_id===cid&&r.status==='نشط');if(!employees.length)fail('لا يوجد موظفون نشطون');const items=employees.map(e=>{if(e.odoo_id&&e.base==null)fail('رواتب ملفات أودو تعرض من كشف أودو؛ لم يستورد راتب أساسي لهذا المسير');const net=e.base+e.allowance-e.deduction;if(net<0)fail('الخصومات تتجاوز المستحقات: '+e.name);return{employee_id:e.id,name:e.name,base:e.base,allowance:e.allowance,deduction:e.deduction,net};});const r=insert(s,'payroll',cid,{period:b.period,status:'مسودة',items,total:items.reduce((n,x)=>n+x.net,0),created_by:u.id});audit(s,u,'إعداد مسير','payroll',r.id,cid);return cleanRecord(r);}
function action(s,u,m,rid,b){permitted(u,m);const r=get(s,m,rid);if(!visible(u,r,m))fail('ليست لديك صلاحية',403);if(b.version!==r.version)fail('السجل تغير؛ حدّث الصفحة',409);const d=dataOnly(r);
 if(m==='requests'&&['approve','reject'].includes(b.action)){
  if(!['owner','hr','client'].includes(u.role))fail('ليست لديك صلاحية',403);if(r.status!=='معلق')fail('تم البت في الطلب',409);if(u.employee_id===r.employee_id)fail('لا يمكن اعتماد طلبك الشخصي',403);
  if(b.action==='approve'&&r.kind==='إجازة'){const days=(Date.parse(r.end_date)-Date.parse(r.start_date))/86400000+1,emp=get(s,'employees',r.employee_id);if(emp.leave_balance<days)fail('رصيد الإجازات غير كافٍ');if(s.records.some(x=>x.module==='requests'&&x.employee_id===r.employee_id&&x.kind==='إجازة'&&x.status==='موافق'&&x.start_date<=r.end_date&&x.end_date>=r.start_date))fail('توجد إجازة معتمدة في الفترة نفسها');update(emp,{...dataOnly(emp),leave_balance:emp.leave_balance-days},emp.version);}
  Object.assign(d,{status:b.action==='approve'?'موافق':'مرفوض',reviewed_by:u.id,reviewed_at:stamp()});
 }else if(m==='attendance'&&b.action==='checkout'){
  if(!['owner','hr','employee'].includes(u.role))fail('ليست لديك صلاحية',403);if(r.check_out)fail('تم تسجيل الانصراف',409);d.check_out=stamp();
 }else if(m==='payroll'&&b.action==='approve'){
  if(!['owner','client'].includes(u.role))fail('الاعتماد للمالك أو مسؤول العميل',403);if(r.status!=='مسودة')fail('المسير معتمد بالفعل',409);if(r.created_by===u.id)fail('يجب أن يعتمد المسير مستخدم آخر',403);Object.assign(d,{status:'معتمد',approved_by:u.id,approved_at:stamp()});
 }else fail('إجراء غير مدعوم');
 update(r,d,b.version);audit(s,u,b.action,m,r.id,r.company_id);return cleanRecord(r);
}
function attempt(s,key){const a=s.attempts[key];if(a&&a.reset>Date.now()&&a.count>=10)fail('محاولات كثيرة؛ أعد المحاولة بعد 15 دقيقة',429);return a&&a.reset>Date.now()?a:{count:0,reset:Date.now()+900000};}
function prune(s){s.sessions=s.sessions.filter(x=>x.expires>Date.now()).slice(-499);for(const [k,v]of Object.entries(s.attempts))if(v.reset<Date.now())delete s.attempts[k];}
function failedAttempt(s,key){const a=attempt(s,key);if(Object.keys(s.attempts).length>=500&&!s.attempts[key])fail('محاولات كثيرة؛ حاول لاحقًا',429);s.attempts[key]={count:a.count+1,reset:a.reset};throw new Problem('بيانات التحقق غير صحيحة',403,true);}
function session(s,req){const raw=req.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith('madar_session='))?.slice(14);const sess=s.sessions.find(x=>x.token===sha(raw||'')&&x.expires>Date.now());const u=sess&&s.users.find(x=>x.id===sess.user_id&&x.active);if(!u)fail('سجل الدخول أولًا',401);return {u,sess};}
async function readBody(req){const length=Number(req.headers.get('content-length')||0);if(!Number.isFinite(length)||length<0||length>BODY_LIMIT)fail('حجم الطلب أكبر من المسموح',413);const chunks=[];let size=0;const reader=req.body?.getReader();if(!reader)fail('بيانات JSON مطلوبة');while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>BODY_LIMIT){await reader.cancel();fail('حجم الطلب أكبر من المسموح',413);}chunks.push(Buffer.from(value));}let data;try{data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail('صيغة JSON غير صالحة');}if(!data||typeof data!=='object'||Array.isArray(data))fail('بيانات غير صالحة');return data;}
async function upload(s,u,b,files){if(!['owner','hr','client'].includes(u.role))fail('ليست لديك صلاحية',403);required(b,'title');required(b,'filename');const cid=['owner','hr'].includes(u.role)?b.company_id:u.company_id;get(s,'companies',cid);if(get(s,'employees',b.employee_id).company_id!==cid)fail('الموظف خارج الشركة',403);date(b,'expires',true);if(typeof b.content!=='string'||!/^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b.content))fail('ملف غير صالح');const data=Buffer.from(b.content,'base64');if(!data.length||data.length>MAX_FILE)fail('الملف فارغ أو يتجاوز 2 ميغابايت',413);const total=s.records.filter(x=>x.module==='documents').reduce((n,x)=>n+(x.size||0),0);if(total+data.length>MAX_FILES_TOTAL)fail('بلغت التجربة حد 20 ميغابايت للمستندات',413);
 const ext=b.filename.split('.').pop().toLowerCase(),types={pdf:['255044462d','application/pdf'],png:['89504e470d0a1a0a','image/png'],jpg:['ffd8ff','image/jpeg'],jpeg:['ffd8ff','image/jpeg']},t=types[ext];if(!t||!data.subarray(0,t[0].length/2).equals(Buffer.from(t[0],'hex')))fail('المسموح PDF أو PNG أو JPG مطابق لنوعه');const storage=id()+'.'+ext;const r=insert(s,'documents',cid,{title:b.title,employee_id:b.employee_id,expires:b.expires||'',filename:b.filename.split(/[\\/]/).pop(),mime:t[1],storage,size:data.length,created_by:u.id});await files.set(storage,data);audit(s,u,'رفع مستند','documents',r.id,cid);return{record:cleanRecord(r),storage};}

export function createHandler({stateStore,fileStore,setupToken='',recoveryKey='',secure=true}){
 return async function handle(req){let s,etag,wroteFile;let committed=false;
  async function commit(){if(Buffer.byteLength(JSON.stringify(s))>MAX_STATE)fail('حجم بيانات التجربة تجاوز الحد؛ صدّرها قبل التوسع',413);const result=await stateStore.setJSON('workspace-v1',s,etag?{onlyIfMatch:etag}:{onlyIfNew:true});if(!result.modified)fail('تزامن تعديل آخر؛ حدّث الصفحة وأعد المحاولة',409);committed=true;}
  try{
   const path=new URL(req.url).pathname;if(!path.startsWith('/api/'))fail('المسار غير موجود',404);if(!['GET','POST'].includes(req.method))fail('طريقة الطلب غير مسموحة',405);
   const origin=req.headers.get('origin');if(req.method==='POST'&&origin&&origin!==new URL(req.url).origin)fail('مصدر الطلب غير مسموح',403);
   const entry=await stateStore.getWithMetadata('workspace-v1',{type:'json',consistency:'strong'});s=entry?structuredClone(entry.data):emptyState();etag=entry?.etag;if(s.format!=='madar-trial-v1')fail('تنسيق البيانات غير متوافق',503);
   if(path==='/api/health'&&req.method==='GET')return response({status:'ok',version:'0.2.0-trial',mode:'trial',max_upload_bytes:MAX_FILE,setup_required:setupToken.length>=32&&!s.users.length});
   // Phase 1: employee-only preview. Keep existing stored records intact but disable all legacy HR and admin API routes.
   const allowed=new Set(['/api/health','/api/setup','/api/login','/api/me','/api/logout','/api/password','/api/odoo-status','/api/employee-profile']);
   if(!allowed.has(path))fail('الوظائف الإدارية القديمة معطلة في بوابة الموظف',410);
   const b=req.method==='POST'?await readBody(req):null;if(b)prune(s);
   if(path==='/api/setup'&&b){if(setupToken.length<32)fail('التهيئة غير مفعلة؛ اضبط MADAR_SETUP_TOKEN في الاستضافة',503);if(s.users.length)fail('تمت تهيئة المنصة مسبقًا',409);attempt(s,'setup');if(typeof b.token!=='string'||!same(b.token,setupToken))failedAttempt(s,'setup');required(b,'name');if(!email(b.email))fail('بريد غير صالح');const u={id:id(),email:b.email.trim().toLowerCase(),name:b.name,password:await hashPassword(b.password),role:'owner',company_id:null,employee_id:null,active:1};s.users.push(u);delete s.attempts.setup;audit(s,u,'تهيئة المنصة','users',u.id);await commit();return response({ok:true},201);}
   if(path==='/api/recover-owner'&&b){
    const [expires, secret] = recoveryKey.split(':');
    const recoveryId = sha(recoveryKey);
    if(!secret || secret.length<32 || !(Number(expires)>Date.now()) || s.usedOwnerRecovery===recoveryId)
     fail('رمز الاستعادة غير متاح أو انتهت صلاحيته',403);
    attempt(s,'owner-recovery');
    const owner = typeof b.email==='string' && s.users.find(user =>
     user.role==='owner' && user.active && user.email===b.email.trim().toLowerCase());
    if(!owner || typeof b.token!=='string' || !same(b.token,secret))
     failedAttempt(s,'owner-recovery');
    const username = typeof b.username==='string' ? b.username.trim().toLowerCase() : '';
    if(username && !/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(username))
     fail('اسم المستخدم من 3 إلى 32 حرفًا إنجليزيًا أو رقمًا، ويمكن إضافة نقطة أو شرطة');
    if(username && s.users.some(user => user.id!==owner.id && user.username===username))
     fail('اسم المستخدم مستخدم بالفعل',409);
    owner.password = await hashPassword(b.password);
    if(username)owner.username=username;
    s.usedOwnerRecovery = recoveryId;
    delete s.attempts['owner-recovery'];
    delete s.attempts[sha(owner.email)];
    s.sessions = s.sessions.filter(session => session.user_id!==owner.id);
    audit(s,owner,'استعادة كلمة مرور المالك','users',owner.id);
    await commit();
    return response({ok:true},200,{'Set-Cookie':cookie('',secure,true)});
   }
   if(path==='/api/activate-employee'&&b){
    const identity=String(b.identity||'').trim().replace(/[٠-٩]/g,c=>String('٠١٢٣٤٥٦٧٨٩'.indexOf(c)));
    if(!/^[12][0-9]{9}$/.test(identity)||typeof b.code!=='string'||b.code.length>100)fail('بيانات التفعيل غير صحيحة');
    const key='activate:'+sha(identity);attempt(s,key);
    const user=s.users.find(x=>x.role==='employee'&&x.username===identity);
    if(!user?.activation_hash||user.activation_expires<Date.now()||!same(sha(b.code),user.activation_hash))failedAttempt(s,key);
    if(!s.records.some(e=>e.module==='employees'&&e.id===user.employee_id&&e.status==='نشط'))fail('الحساب غير متاح للتفعيل؛ راجع المسؤول',403);
    user.password=await hashPassword(b.password);user.active=1;delete user.activation_hash;delete user.activation_expires;s.sessions=s.sessions.filter(x=>x.user_id!==user.id);delete s.attempts[key];audit(s,user,'تفعيل حساب الموظف','users',user.id,user.company_id);await commit();return response({ok:true});
   }
   if(path==='/api/login'&&b){if(typeof b.email!=='string'||b.email.length>254)fail('بيانات غير صالحة');const identifier=b.email.trim().toLowerCase().replace(/[٠-٩]/g,c=>String('٠١٢٣٤٥٦٧٨٩'.indexOf(c))).replace(/[۰-۹]/g,c=>String('۰۱۲۳۴۵۶۷۸۹'.indexOf(c)));const u=s.users.find(x=>x.active&&(x.email===identifier||x.username===identifier));const key=sha(u?.email||identifier);attempt(s,key);if(!u||!await verify(b.password,u.password)){failedAttempt(s,key);}delete s.attempts[key];const raw=token();s.sessions.push({token:sha(raw),csrf:token(),user_id:u.id,expires:Date.now()+SESSION_MS});audit(s,u,'تسجيل دخول','users');await commit();return response({ok:true},200,{'Set-Cookie':cookie(raw,secure)});}
   const {u,sess}=session(s,req);if(b&&!same(req.headers.get('x-csrf-token'),sess.csrf))fail('رمز الحماية غير صالح؛ حدّث الصفحة',403);
   if(path==='/api/employee-profile'&&!b){
    if(u.role!=='employee'||!u.employee_id)fail('لا يوجد ملف موظف مرتبط بهذا الحساب',403);
    const record=s.records.find(x=>x.module==='employees'&&x.id===u.employee_id&&x.status==='نشط');
    const remoteId=Number(record?.odoo_id||u.odoo_id);
    if(!record||!Number.isSafeInteger(remoteId)||remoteId<1)fail('لا يوجد ملف موظف متصل بأودو',404);
    try{const profile=await odooEmployeeById(remoteId);if(!profile||profile.active===false)fail('الملف الوظيفي غير متاح',404);
     return response({source:'odoo',profile});
    }catch(e){if(e instanceof Problem)throw e;fail('تعذر قراءة الملف الوظيفي من أودو',503);}
   }
   if(path==='/api/odoo-status'&&!b){if(u.role!=='owner')fail('للمسؤول فقط',403);try{return response(await odooConnectionCheck());}catch{return response({configured:true,connected:false,error:'تعذر التحقق من اتصال أودو'},503);}}
   if(path==='/api/me'&&!b)return response({...publicUser(u),csrf:sess.csrf,trial:true,mode:s.settings?.mode||'legacy'});
   if(path==='/api/self-service-config'){
    if(u.role!=='owner')fail('للمسؤول فقط',403);
    if(!b)return response({mode:s.settings?.mode||'legacy',company:s.settings?.company_name||'',employees:s.records.filter(r=>r.module==='employees'&&r.odoo_id).length,accounts:s.users.filter(x=>x.role==='employee'&&x.odoo_id).length,removed_demo_records:s.settings?.removed_demo_records||0});
    if(b.action==='convert'){
     if(s.settings?.mode!=='self-service')await stateStore.setJSON('workspace-before-self-service-v1',s,{onlyIfNew:true});
     const result=convertToSelfService(s);if(!result.already){audit(s,u,'تحويل إلى خدمات ذاتية وحذف الأمثلة مع نسخة استعادة','settings');await commit();}return response({ok:true,...result});
    }
    if(b.action==='restore'){
     const backup=await stateStore.getWithMetadata('workspace-before-self-service-v1',{type:'json',consistency:'strong'});if(!backup?.data)fail('لا توجد نسخة استعادة',404);
     const restored=structuredClone(backup.data);restored.sessions=s.sessions.filter(x=>restored.users.some(v=>v.id===x.user_id));s=restored;audit(s,u,'استعادة النسخة السابقة للتحويل','settings');await commit();return response({ok:true});
    }
    fail('إجراء غير متاح');
   }
   if(path==='/api/demo')fail('الأمثلة التجريبية غير متاحة في مدار للخدمات الذاتية',410);
   if(s.settings?.mode==='self-service'&&b&&(!['/api/logout','/api/password'].includes(path)))fail('استخدم بوابة الخدمات الذاتية؛ إدارة الشركات والعمليات القديمة متوقفة',410);
   if(path==='/api/data'&&!b)return response(Object.fromEntries(C.read[u.role].map(m=>[m,list(s,u,m)])));
   if(path==='/api/logout'&&b){s.sessions=s.sessions.filter(x=>x.token!==sess.token);await commit();return response({ok:true},200,{'Set-Cookie':cookie('',secure,true)});}
   if(path==='/api/password'&&b){if(!await verify(b.current,u.password))fail('كلمة المرور الحالية غير صحيحة',403);u.password=await hashPassword(b.password);s.sessions=s.sessions.filter(x=>x.user_id!==u.id);audit(s,u,'تغيير كلمة المرور','users',u.id);await commit();return response({ok:true},200,{'Set-Cookie':cookie('',secure,true)});}
   if(path==='/api/users'){
    if(u.role!=='owner')fail('للمالك فقط',403);if(!b)return response(s.users.map(publicUser));if(s.users.length>=50)fail('حد التجربة 50 مستخدمًا',413);required(b,'name');if(!email(b.email)||!Object.hasOwn(C.read,b.role))fail('البريد أو الدور غير صالح');const e=b.email.trim().toLowerCase();if(s.users.some(x=>x.email===e))fail('البريد موجود بالفعل',409);let cid=null,eid=null;
    if(['client','employee'].includes(b.role)){cid=b.company_id;get(s,'companies',cid);if(b.role==='employee'){eid=b.employee_id;if(get(s,'employees',eid).company_id!==cid)fail('الموظف خارج الشركة',403);}}
    const user={id:id(),email:e,name:b.name,password:await hashPassword(b.password),role:b.role,company_id:cid,employee_id:eid,active:1};s.users.push(user);audit(s,u,'إنشاء مستخدم','users',user.id,cid);await commit();return response({id:user.id},201);
   }
   if(path.startsWith('/api/users/')&&b){if(u.role!=='owner')fail('للمالك فقط',403);const target=s.users.find(x=>x.id===path.split('/').pop());if(!target)fail('المستخدم غير موجود',404);if(target.id===u.id)fail('لا يمكنك تعديل حسابك من هنا');if(b.action==='disable')target.active=0;else if(b.action==='reset'){target.password=await hashPassword(b.password);target.active=1;}else fail('إجراء غير صالح');s.sessions=s.sessions.filter(x=>x.user_id!==target.id);audit(s,u,b.action,'users',target.id,target.company_id);await commit();return response({ok:true});}
   if(path==='/api/audit'&&!b){if(!['owner','hr'].includes(u.role))fail('ليست لديك صلاحية',403);return response(s.audit.slice(-500).reverse());}
   if(path==='/api/backup'&&!b){if(u.role!=='owner')fail('للمالك فقط',403);return response({format:'madar-portable-v1',exported_at:stamp(),users:s.users.map(publicUser),audit:s.audit,records:Object.fromEntries(Object.keys(C.modules).map(m=>[m,list(s,u,m)])),note:'لا يشمل كلمات المرور أو الملفات؛ صدّر المستندات من روابط التنزيل أو ملف الترحيل الكامل.'});}
   if(path==='/api/transfer'&&!b){if(u.role!=='owner')fail('للمالك فقط',403);const docs=s.records.filter(r=>r.module==='documents');let bytes=0;const files=[];for(const r of docs){const data=await fileStore.get(r.storage,{type:'arrayBuffer',consistency:'strong'});if(!data)fail('مستند مفقود؛ راجع الاستضافة',503);bytes+=data.byteLength;if(bytes>3*1024*1024)fail('صدّر المستندات منفردة لأن مجموعها يتجاوز حد ملف النقل الواحد',413);files.push({record_id:r.id,filename:r.filename,mime:r.mime,content:Buffer.from(data).toString('base64')});}const payload={format:'madar-transfer-v1',exported_at:stamp(),users:s.users.map(publicUser),audit:s.audit,records:Object.fromEntries(Object.keys(C.modules).map(m=>[m,list(s,u,m)])),files,note:'ملف حساس يحتوي بياناتك ومستنداتك. أعد تعيين كلمات المرور عند نقل الحسابات.'};if(Buffer.byteLength(JSON.stringify(payload))>5*1024*1024)fail('ملف النقل كبير؛ صدّر JSON والمستندات منفردة',413);return response(payload,200,{'Content-Disposition':'attachment; filename="madar-transfer.json"'});}
   const parts=path.split('/').filter(Boolean),m=parts[1],rid=parts[2];if(!Object.hasOwn(C.modules,m))fail('المسار غير موجود',404);
   if(parts.length===2){if(!b)return response(list(s,u,m));let result;if(m==='payroll')result=payroll(s,u,b);else if(m==='documents'){const uploaded=await upload(s,u,b,fileStore);result=uploaded.record;wroteFile=uploaded.storage;}else result=createRecord(s,u,m,b);await commit();return response(result,201);}
   if(parts.length===4&&parts[3]==='download'&&m==='documents'&&!b){permitted(u,m);const r=get(s,m,rid);if(!visible(u,r,m))fail('ليست لديك صلاحية',403);const data=await fileStore.get(r.storage,{type:'arrayBuffer',consistency:'strong'});if(!data)fail('الملف غير موجود',404);return new Response(data,{headers:{...HEADERS,'Content-Type':r.mime,'Content-Disposition':`attachment; filename="document.${r.storage.split('.').pop()}"`}});}
   let result;if(parts.length===3&&b)result=createRecord(s,u,m,b,rid);else if(parts.length===4&&parts[3]==='action'&&b)result=action(s,u,m,rid,b);else fail('المسار غير موجود',404);await commit();return response(result);
  }catch(e){
   if(wroteFile&&!committed){try{await fileStore.delete(wroteFile);}catch{}}
   if(e instanceof Problem){if(e.persist&&s){try{await commit();}catch(err){return response({error:err.message||'تعذر حفظ العملية'},err.status||503);}}return response({error:e.message},e.status);}
   // Do not expose request payloads, storage paths or service credentials.
   console.error('Madar operation failed',e?.name||'Error');return response({error:'تعذر إكمال العملية؛ تحقق من إعدادات الاستضافة'},503);
  }
 };
}
