import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileStore} from '../trial/file-store.mjs';
test('portable store persists snapshots and enforces conditional writes',async()=>{const dir=await mkdtemp(join(tmpdir(),'madar-'));try{const a=fileStore(dir,'state');assert.equal((await a.setJSON('workspace-v1',{a:1},{onlyIfNew:true})).modified,true);const saved=await a.getWithMetadata('workspace-v1',{type:'json'});const b=fileStore(dir,'state');assert.equal((await b.getWithMetadata('workspace-v1',{type:'json'})).data.a,1);assert.equal((await b.setJSON('workspace-v1',{a:2},{onlyIfNew:true})).modified,false);assert.equal((await b.setJSON('workspace-v1',{a:2},{onlyIfMatch:'old'})).modified,false);assert.equal((await b.setJSON('workspace-v1',{a:3},{onlyIfMatch:saved.etag})).modified,true);}finally{await rm(dir,{recursive:true,force:true});}});
test('portable store roundtrips binary documents without a public path',async()=>{const dir=await mkdtemp(join(tmpdir(),'madar-'));try{const s=fileStore(dir,'docs'),data=Buffer.from('%PDF-example');await s.set('private.pdf',data);assert.equal(Buffer.from(await s.get('private.pdf',{type:'arrayBuffer'})).toString(),data.toString());await s.delete('private.pdf');assert.equal(await s.get('private.pdf'),null);}finally{await rm(dir,{recursive:true,force:true});}});
