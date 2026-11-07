import test from 'node:test';
import assert from 'node:assert/strict';
import {odooConfigured,odooEmployeeById,odooEmployeeByNationalId,odooConnectionCheck} from '../trial/odoo-readonly.mjs';
const env={ODOO_URL:'https://example.odoo.com',ODOO_API_KEY:'test-only-key'};
test('configuration is required',async()=>{
 assert.equal(odooConfigured({}),false);
 await assert.rejects(odooEmployeeById(1,{env:{}}),/غير مهيأ/);
 assert.deepEqual(await odooConnectionCheck({env:{}}),{connected:false,configured:false});
});
test('employee profile is read only from Odoo over HTTPS',async()=>{
 let called=false;
 const row={id:42,name:'موظف تجريبي',barcode:'E0042'};
 const result=await odooEmployeeById(42,{env,fetcher:async(url,opts)=>{
  called=true;
  assert.equal(url.pathname,'/json/2/hr.employee/read');
  assert.equal(opts.method,'POST');
  assert.equal(opts.headers.Authorization,'bearer test-only-key');
  assert.deepEqual(JSON.parse(opts.body).ids,[42]);
  return {ok:true,json:async()=>[row]};
 }});
 assert.equal(called,true);
 assert.deepEqual(result,row);
});
test('national ID lookup requires unique active Odoo record',async()=>{
 const id='1234567890';
 const result=await odooEmployeeByNationalId(id,{env,fetcher:async(url,opts)=>{
  assert.equal(url.pathname,'/json/2/hr.employee/search_read');
  const payload=JSON.parse(opts.body);
  assert.deepEqual(payload.domain,[['identification_id','=',id],['active','=',true]]);
  assert.equal(payload.limit,2);
  return {ok:true,json:async()=>[{id:9,barcode:'A9'}]};
 }});
 assert.equal(result.id,9);
 const duplicates=await odooEmployeeByNationalId(id,{env,fetcher:async()=>({ok:true,json:async()=>[{id:1},{id:2}]})});
 assert.equal(duplicates,null);
 assert.equal(await odooEmployeeByNationalId('bad',{env,fetcher:()=>{throw Error('must not call network')}}),null);
});
test('Odoo connection status distinguishes HTTP failure',async()=>{
 const result=await odooConnectionCheck({env,fetcher:async()=>({ok:false,status:401})});
 assert.deepEqual(result,{configured:true,connected:false,status:401});
});
