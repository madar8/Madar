// Read-only Odoo JSON-2 integration. Credentials must live in Netlify environment variables.
const fields=['id','name','work_email','work_phone','mobile_phone','job_title','department_id','company_id','work_location_id','parent_id','active','barcode'];
export function odooConfigured(env=process.env){return Boolean(env.ODOO_URL&&env.ODOO_API_KEY);}
export async function odooEmployeeById(employeeId,{env=process.env,fetcher=fetch}={}){
 if(!odooConfigured(env))throw Error('اتصال أودو غير مهيأ في الاستضافة');
 if(!Number.isSafeInteger(employeeId)||employeeId<1)throw Error('معرّف موظف غير صالح');
 const origin=new URL(env.ODOO_URL);
 if(origin.protocol!=='https:')throw Error('اتصال أودو يتطلب HTTPS');
 const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);
 try{
  const res=await fetcher(new URL('/json/2/hr.employee/read',origin),{
   method:'POST',headers:{'Content-Type':'application/json','Authorization':'bearer '+env.ODOO_API_KEY},
   body:JSON.stringify({ids:[employeeId],fields}),signal:controller.signal,redirect:'error'
  });
  if(!res.ok)throw Error('فشل الاتصال بأودو: '+res.status);
  const rows=await res.json();
  if(!Array.isArray(rows))throw Error('استجابة أودو غير متوقعة');
  return rows.find(row=>row?.id===employeeId)||null;
 }finally{clearTimeout(timeout);}
}
// National ID lookup is server-side only. No identity numbers or API credentials are logged.
export async function odooEmployeeByNationalId(identity,{env=process.env,fetcher=fetch}={}){
 if(!/^[12][0-9]{9}$/.test(String(identity)))return null;
 if(!odooConfigured(env))throw Error('اتصال أودو غير مهيأ في الاستضافة');
 const origin=new URL(env.ODOO_URL);if(origin.protocol!=='https:')throw Error('اتصال أودو يتطلب HTTPS');
 const field=env.ODOO_NATIONAL_ID_FIELD||'identification_id';
 if(!/^[a-z][a-z0-9_]{1,63}$/.test(field))throw Error('حقل الهوية غير صالح');
 const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);
 try{
  const res=await fetcher(new URL('/json/2/hr.employee/search_read',origin),{
   method:'POST',headers:{'Content-Type':'application/json','Authorization':'bearer '+env.ODOO_API_KEY},
   body:JSON.stringify({domain:[[field,'=',identity],['active','=',true]],fields,limit:2}),
   signal:controller.signal,redirect:'error'});
  if(!res.ok)throw Error('تعذر البحث عن الموظف في أودو');
  const rows=await res.json();if(!Array.isArray(rows))throw Error('استجابة أودو غير متوقعة');
  if(rows.length!==1)return null;
  return rows[0];
 }finally{clearTimeout(timeout);}
}
export async function odooConnectionCheck({env=process.env,fetcher=fetch}={}){
 if(!odooConfigured(env))return {connected:false,configured:false};
 const origin=new URL(env.ODOO_URL);if(origin.protocol!=='https:')throw Error('اتصال أودو يتطلب HTTPS');
 const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);
 try{
  const res=await fetcher(new URL('/json/2/res.company/search_count',origin),{method:'POST',
   headers:{'Content-Type':'application/json','Authorization':'bearer '+env.ODOO_API_KEY},
   body:JSON.stringify({domain:[]}),signal:controller.signal,redirect:'error'});
  return {configured:true,connected:res.ok,status:res.status};
 }finally{clearTimeout(timeout);}
}
