// Imports an OWNER-exported trial bundle into a fresh portable single-process installation.
// Never sends data to a third party. Other user accounts are disabled until reset by the owner.
import {readFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileStore} from '../trial/file-store.mjs';
import {hashPassword,emptyState,MAX_FILE,MAX_RECORDS,MAX_STATE} from '../trial/core.mjs';
import C from '../trial/config.json' with {type:'json'};
const [input,destination,ownerEmail]=process.argv.slice(2);
if(!input||!destination||!ownerEmail||!process.env.MADAR_IMPORT_PASSWORD){console.error('Usage: MADAR_IMPORT_PASSWORD=<private new password> node scripts/import-transfer.mjs <madar-transfer.json> <empty-data-directory> <owner-email>');process.exit(1);}
const bundle=JSON.parse(await readFile(input,'utf8'));if(bundle.format!=='madar-transfer-v1'||!Array.isArray(bundle.users)||!Array.isArray(bundle.files)||!bundle.records)throw new Error('Invalid transfer bundle');
const owner=bundle.users.find(x=>x.email===ownerEmail.toLowerCase()&&x.role==='owner');if(!owner)throw new Error('Selected owner email is not an owner in this bundle');
const s=emptyState();s.audit=Array.isArray(bundle.audit)?bundle.audit.slice(-1000):[];s.users=bundle.users.map(u=>{if(!Object.hasOwn(C.read,u.role))throw new Error('Invalid role');return{...u,active:0,password:''};});const target=s.users.find(x=>x.id===owner.id);target.active=1;target.password=await hashPassword(process.env.MADAR_IMPORT_PASSWORD);
for(const [module,records]of Object.entries(bundle.records)){if(!Object.hasOwn(C.modules,module)||!Array.isArray(records))throw new Error('Invalid module');s.records.push(...records.map(r=>({...r,module})));}
if(s.records.length>MAX_RECORDS||Buffer.byteLength(JSON.stringify(s))>MAX_STATE)throw new Error('Bundle exceeds trial limits');
const dir=resolve(destination);await mkdir(dir,{recursive:true,mode:0o700});const state=fileStore(dir,'state'),documents=fileStore(dir,'documents');if(await state.getWithMetadata('workspace-v1'))throw new Error('Destination already contains a workspace; import refused');
const docs=s.records.filter(r=>r.module==='documents');const pending=[];
for(const r of docs){const file=bundle.files.find(x=>x.record_id===r.id);if(!file||typeof file.content!=='string')throw new Error('Document missing from bundle');const data=Buffer.from(file.content,'base64');if(!data.length||data.length>MAX_FILE)throw new Error('Invalid file size');pending.push([r.storage,data]);}
for(const [key,data]of pending)await documents.set(key,data);
const result=await state.setJSON('workspace-v1',s,{onlyIfNew:true});if(!result.modified)throw new Error('Destination changed; import refused');
console.log('Imported records and documents. Owner enabled with the new private password. Reset and enable other accounts after review. Run with MADAR_TRIAL_DATA_DIR='+dir);
