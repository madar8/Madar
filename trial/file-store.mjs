import {readFileSync,writeFileSync,mkdirSync,renameSync,existsSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
export function fileStore(data,name){const dir=join(data,name);mkdirSync(dir,{recursive:true,mode:0o700});const path=k=>join(dir,createHash('sha256').update(k).digest('hex'));return {
 async getWithMetadata(k,{type}={}){const p=path(k);if(!existsSync(p))return null;const raw=readFileSync(p);return{data:type==='json'?JSON.parse(raw):raw,etag:createHash('sha256').update(raw).digest('hex')};},
 async get(k,{type}={}){const e=await this.getWithMetadata(k);if(!e)return null;return type==='arrayBuffer'?new Uint8Array(e.data).buffer:e.data.toString();},
 async setJSON(k,value,options={}){const p=path(k),current=existsSync(p)?readFileSync(p):null,etag=current?createHash('sha256').update(current).digest('hex'):null;if(options.onlyIfNew&&current||options.onlyIfMatch&&options.onlyIfMatch!==etag)return{modified:false};const raw=JSON.stringify(value),temp=p+'.'+randomBytes(6).toString('hex');writeFileSync(temp,raw,{mode:0o600});renameSync(temp,p);return{modified:true,etag:createHash('sha256').update(raw).digest('hex')};},
 async set(k,value){writeFileSync(path(k),Buffer.from(value),{mode:0o600});return{modified:true};},async delete(k){if(existsSync(path(k)))unlinkSync(path(k));}
};}
