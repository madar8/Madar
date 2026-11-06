import {readFile} from 'node:fs/promises';
// Fail a build on an invalid dependency/source configuration rather than publish a static mock.
for(const file of ['web/index.html','web/app.js','web/styles.css','trial/core.mjs','netlify/functions/api.mjs'])await readFile(file);
if(process.env.NETLIFY&&(!process.env.MADAR_SETUP_TOKEN||process.env.MADAR_SETUP_TOKEN.length<32)){
 throw new Error('Set private MADAR_SETUP_TOKEN (32+ random characters) in Netlify environment variables for Builds and Functions before the first deploy.');
}
console.log('Madar trial: static UI + authenticated serverless API. Persistent state and documents use private site-scoped Netlify Blobs.');
