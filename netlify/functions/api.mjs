import {getStore} from '@netlify/blobs';
import {createHandler} from '../../trial/core.mjs';
export default async function api(request){
 try{return await createHandler({
  stateStore:getStore({name:'madar-trial-state',consistency:'strong'}),
  fileStore:getStore({name:'madar-trial-documents',consistency:'strong'}),
  setupToken:process.env.MADAR_SETUP_TOKEN||'',
  recoveryKey:process.env.MADAR_OWNER_RECOVERY||'',
  secure:true,
 })(request);}catch{
  return new Response(JSON.stringify({error:'تعذر الاتصال بتخزين التجربة؛ راجع إعدادات Netlify'}),{status:503,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
 }
}
export const config={path:'/api/*'};
