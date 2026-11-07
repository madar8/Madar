import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createHandler,emptyState} from '../trial/core.mjs';
import {nationalId,readProfile,readProfiles} from '../netlify/functions/employee-file.mjs';
test('identity normalizes Arabic digits and rejects missing or invalid identity',()=>{assert.equal(nationalId('١٢٣٤٥٦٧٨٩٠'),'1234567890');for(const v of [null,'','123','passport123'])assert.equal(nationalId(v),null);});
test('profile reads only allowed fields and reports unavailable sections',async()=>{const calls=[];const p=await readProfile(async(model,method,args,kwargs)=>{calls.push({model,method,args,kwargs});if(model!=='hr.employee')throw Error('access denied');if(method==='fields_get')return {name:{string:'Name'},identification_id:{string:'ID'},pin:{string:'Private credential'}};return [{id:777,name:'Employee'}];},777);assert.equal(p.employee.id,777);assert(!p.labels.pin);assert(p.sections.every(s=>s.status==='unavailable'));assert(calls.every(c=>['read','search_read','fields_get'].includes(c.method)));assert.deepEqual(calls.find(c=>c.method==='read').args,[[777]]);});
test('activation requires valid unexpired code, is single use and permits identity login',async()=>{
 let data=emptyState(),version=1;
 data.records.push({id:'e',module:'employees',status:'نشط'});
 data.users.push({id:'u',role:'employee',username:'1234567890',email:'one@employee.test',name:'Test',employee_id:'e',company_id:'c',active:0,password:'disabled',activation_hash:createHash('sha256').update('test-private-activation-code').digest('hex'),activation_expires:Date.now()+100000});
 const store={async getWithMetadata(){return {data:structuredClone(data),etag:String(version)};},async setJSON(k,v,opts){if(opts.onlyIfMatch!==String(version))return {modified:false};data=structuredClone(v);version++;return {modified:true};}};
 const api=createHandler({stateStore:store,fileStore:{},secure:true});
 const call=async(path,b)=>{const r=await api(new Request('https://madar.test/api/'+path,{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://madar.test'},body:JSON.stringify(b)}));return {r,d:await r.json()};};
 assert.equal((await call('login',{email:'1234567890',password:'NewEmployeePassword123!'})).r.status,403);
 assert.equal((await call('activate-employee',{identity:'1234567890',code:'wrong',password:'NewEmployeePassword123!'})).r.status,403);
 const b={identity:'1234567890',code:'test-private-activation-code',password:'NewEmployeePassword123!'};
 assert.equal((await call('activate-employee',b)).r.status,200);assert.equal(data.users[0].active,1);assert(!data.users[0].activation_hash);
 assert.equal((await call('activate-employee',b)).r.status,403);
 assert.equal((await call('login',{email:'١٢٣٤٥٦٧٨٩٠',password:b.password})).r.status,200);
});

test('batch profiles isolate related records by employee id',async()=>{const profiles=await readProfiles(async(model,method,args,kwargs)=>{if(model==='hr.employee')return method==='fields_get'?{name:{string:'Name'}}:[{id:1,name:'A'},{id:2,name:'B'}];if(model!=='hr.contract')throw Error('denied');if(method==='fields_get')return {employee_id:{string:'Employee'},name:{string:'Contract'}};return [{id:1,name:'Only A',employee_id:[1,'A']},{id:2,name:'Only B',employee_id:[2,'B']}];},[1,2]);assert.deepEqual(profiles[0].sections[0].rows.map(r=>r.name),['Only A']);assert.deepEqual(profiles[1].sections[0].rows.map(r=>r.name),['Only B']);});
test('custody partner relation uses employee source contact, never employee numeric id',async()=>{let used;const profiles=await readProfiles(async(model,method,args)=>{if(model==='hr.employee')return method==='fields_get'?{name:{string:'Name'},address_home_id:{string:'Employee contact'}}:[{id:7,name:'A',address_home_id:[700,'A']}];if(model!=='asset.account.request')throw Error('denied');if(method==='fields_get')return {employee_id:{string:'Employee',relation:'res.partner'},name:{string:'Custody'}};used=args[0];return [{id:1,name:'Own',employee_id:[700,'A']},{id:2,name:'Other',employee_id:[7,'Other']}];},[7]);assert.deepEqual(used[0],['employee_id','in',[700]]);const custody=profiles[0].sections.find(x=>x.key==='custody');assert.deepEqual(custody.rows.map(x=>x.name),['Own']);});
