import {test} from 'node:test';
import assert from 'node:assert/strict';
import {seal,unseal,testOdoo} from '../netlify/functions/odoo-connection.mjs';
const secret='test-private-key-'.repeat(4);
const input={login:'test@example.test',password:'NotARealPassword',database:'telenocodoo-lanamedicalco-main-4789102'};
test('stored credentials are encrypted and authenticated',()=>{const encrypted=seal(input,secret);assert(!JSON.stringify(encrypted).includes(input.password));assert.deepEqual(unseal(encrypted,secret),input);assert.throws(()=>unseal(encrypted,'wrong'.repeat(20)));});
test('rejects missing encryption secret',()=>{assert.throws(()=>seal(input,''));});
test('connection test only authenticates and reads own user',async()=>{const calls=[];const result=await testOdoo(input,async(url,opts)=>{const body=JSON.parse(opts.body);calls.push({url,opts,body});return new Response(JSON.stringify({result:calls.length===1?{uid:180}:[{id:180,name:'Test User',login:input.login}]}),{headers:calls.length===1?{'set-cookie':'session_id=fake; HttpOnly; Secure'}:{}});});assert.equal(result.uid,180);assert.equal(result.read_only_test,true);assert.equal(calls.length,2);assert.equal(calls[1].body.params.method,'read');assert.deepEqual(calls[1].body.params.args,[[180]]);assert.equal(calls[1].opts.headers.Cookie,'session_id=fake');assert(!JSON.stringify(result).includes(input.password));assert(calls.every(c=>c.url.startsWith('https://lanamed.odoo.com/')));});
test('failed Odoo auth does not produce a connected result',async()=>{await assert.rejects(testOdoo(input,async()=>new Response(JSON.stringify({error:{data:'SECRET'}}))),/رفض أودو/);});
test('rejects changed database without sending credentials',async()=>{let calls=0;await assert.rejects(testOdoo({...input,database:'other'},async()=>{calls++;}),/أدخل/);assert.equal(calls,0);});
test('requires a real session and matching user response',async()=>{await assert.rejects(testOdoo(input,async()=>new Response(JSON.stringify({result:{uid:180}}))),/لم ينجح/);let count=0;await assert.rejects(testOdoo(input,async()=>new Response(JSON.stringify({result:++count===1?{uid:180}:[{id:999,name:'Other'}]}),{headers:{'set-cookie':'session_id=fake'}})),/تعذر التحقق/);});
test('discovery reads categories and schema without writing any records',async()=>{
 const methods=[];
 const result=await testOdoo({...input,inspect:true},async(url,opts)=>{
  const p=JSON.parse(opts.body).params;methods.push(p.method||'authenticate');
  const result=methods.length===1?{uid:180}:methods.length===2?[{id:180,name:'Test',login:input.login}]:methods.length===3?[{id:64,name:'Overtime'}]:{amount:{type:'monetary',string:'Amount'},secret_field:{type:'char'}};
  return new Response(JSON.stringify({result}),{headers:{'set-cookie':'session_id=fake'}});
 });
 assert.deepEqual(methods,['authenticate','read','search_read','fields_get']);
 assert.equal(result.read_only,true);assert.equal(result.categories[0].id,64);
 assert.equal(result.fields.secret_field,undefined);assert(!JSON.stringify(result).includes(input.password));
});
