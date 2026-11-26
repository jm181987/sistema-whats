import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import {randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
const {Pool}=pg;
if(!process.env.DATABASE_URL) throw Error('DATABASE_URL required');
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
async function saveWhatsAppProfile(c:pg.PoolClient,company:string,phone:string,item:any){const name=typeof item?.pushName==='string'?item.pushName.trim().slice(0,160):'';await c.query("INSERT INTO contacts(company_id,name,phone,whatsapp_name) VALUES($1,$2,$3,$4) ON CONFLICT(company_id,phone) DO UPDATE SET whatsapp_name=CASE WHEN EXCLUDED.whatsapp_name<>'' THEN EXCLUDED.whatsapp_name ELSE contacts.whatsapp_name END WHERE EXCLUDED.whatsapp_name<>'' AND contacts.whatsapp_name IS DISTINCT FROM EXCLUDED.whatsapp_name",[company,phone,phone,name]);}
async function initialize(){
 const c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(782019)');
 const role=await c.query('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user');
 if(role.rows[0].rolsuper||role.rows[0].rolbypassrls) throw Error('Unsafe database role');
 await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)');
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=1')).rowCount){await c.query(await readFile('migrations/001.sql','utf8'));await c.query('INSERT INTO schema_migrations VALUES(1)');}
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=3')).rowCount){await c.query("ALTER TABLE contacts ADD COLUMN IF NOT EXISTS labels text[] NOT NULL DEFAULT ARRAY[]::text[]");await c.query('INSERT INTO schema_migrations VALUES(3)');}
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=2')).rowCount){await c.query("ALTER TABLE contacts ADD COLUMN stage text NOT NULL DEFAULT 'nuevo', ADD COLUMN value numeric(14,2) NOT NULL DEFAULT 0, ADD COLUMN company_name text NOT NULL DEFAULT '', ADD COLUMN email text NOT NULL DEFAULT '', ADD COLUMN notes text NOT NULL DEFAULT ''");await c.query('INSERT INTO schema_migrations VALUES(2)');}
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=4')).rowCount){await c.query("ALTER TABLE contacts ADD COLUMN IF NOT EXISTS whatsapp_name text NOT NULL DEFAULT ''");await c.query('INSERT INTO schema_migrations VALUES(4)');}
 const {BOOTSTRAP_EMAIL:e,BOOTSTRAP_PASSWORD:p,BOOTSTRAP_COMPANY:n}=process.env;
 if(!(await c.query('SELECT 1 FROM users LIMIT 1')).rowCount){
 if(!e||!p||p.length<14||!n)throw Error('Bootstrap email, company and password (14+ chars) required');
 const u=(await c.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id',[e.trim().toLowerCase(),await bcrypt.hash(p,12)])).rows[0];
 const t=(await c.query('INSERT INTO companies(name) VALUES($1) RETURNING id',[n])).rows[0];
 await c.query("INSERT INTO memberships VALUES($1,$2,'owner')",[t.id,u.id]);}
 await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
await initialize();
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'23mb'}));
app.use('/api',(req,res,next)=>{res.set('Cache-Control','no-store');if(!['GET','HEAD'].includes(req.method)&&!req.is('application/json')){res.sendStatus(415);return;}next();});
app.get('/health',async(_q,r)=>{await pool.query('SELECT 1');r.json({ok:true});});
app.post('/api/login',rateLimit({windowMs:900000,limit:15}),async(q,r)=>{
 const {email,password}=q.body??{};if(typeof email!=='string'||typeof password!=='string'||password.length>256){r.sendStatus(400);return;}
 const u=(await pool.query('SELECT * FROM users WHERE email=$1',[email.trim().toLowerCase()])).rows[0];
 if(!u||!await bcrypt.compare(password,u.password_hash)){r.sendStatus(401);return;}
 const token=randomBytes(32).toString('hex');await pool.query("INSERT INTO sessions VALUES($1,$2,now()+interval '8 hours')",[hash(token),u.id]);
 r.cookie('sw_session',token,{httpOnly:true,secure:true,sameSite:'strict',maxAge:28800000,path:'/'}).json({ok:true});
});
function token(q:express.Request){return (q.headers.cookie??'').match(/(?:^|;\s*)sw_session=([a-f0-9]{64})(?:;|$)/)?.[1]??'';}
function mediaInfo(m:any){
 const msg=m?.message??{};for(const kind of ['image','video','audio','document']){const item=msg[kind+'Message'];if(item)return {kind,text:typeof item.caption==='string'?item.caption:'['+kind+']',mime:typeof item.mimetype==='string'?item.mimetype.split(';')[0]:'',ptt:kind==='audio'&&item.ptt===true};}return null;
}
const mediaTypes:Record<string,string[]>={image:['image/jpeg','image/png','image/webp'],video:['video/mp4','video/webm'],document:['application/pdf'],audio:['audio/ogg','audio/mpeg','audio/mp4','audio/wav','audio/webm','audio/aac']};
function kindDisposition(kind:string){return kind==='document'?'inline; filename="documento.pdf"':'inline';}
function validMedia(kind:string,mime:string,b64:string){return !!mediaTypes[kind]?.includes(mime)&&typeof b64==='string'&&b64.length>0&&b64.length<=22369624&&/^[A-Za-z0-9+/]+={0,2}$/.test(b64)&&Buffer.from(b64,'base64').length<=16777216&&(kind!=='document'||Buffer.from(b64.slice(0,12),'base64').subarray(0,5).toString()==='%PDF-');}
function directPhone(key:any):string|null{
 if(typeof key?.remoteJid==='string'&&!/@(?:s\.whatsapp\.net|lid)$/.test(key.remoteJid))return null;
 for(const jid of [key?.remoteJidAlt,key?.remoteJid,key?.senderPn,key?.participantAlt]){if(typeof jid==='string'&&/^\d{8,15}(?::\d+)?@s\.whatsapp\.net$/.test(jid))return jid.split('@')[0].split(':')[0];}return null;
}
function unwrapMessage(m:any){let msg=m?.message??{};for(let i=0;i<5;i++){const nested=msg.ephemeralMessage?.message??msg.viewOnceMessage?.message??msg.viewOnceMessageV2?.message??msg.documentWithCaptionMessage?.message;if(!nested)break;msg=nested;}return {...m,message:msg};}
app.post(['/api/webhooks/evolution/:secret','/api/webhooks/evolution/:secret/:event'],async(q,r)=>{
 const secret=process.env.EVOLUTION_WEBHOOK_SECRET;
 if(!secret||secret.length<32||typeof q.params.secret!=='string'||hash(q.params.secret)!==hash(secret)){console.warn('Evolution webhook rejected: configuration or token');r.sendStatus(404);return;}
 const event=q.body,source=typeof event?.instance==='string'?event.instance:event?.instance?.instanceName??event?.instance?.name;
 const company=typeof source==='string'&&/^sw-[0-9a-f-]{36}$/.test(source)?source.slice(3):'';if(!company||!await configuredInstance(company)){r.json({ok:true});return;}const instance=instanceName(company);
 const type=String(event?.event??q.params.event??'').toLowerCase().replace(/[_-]/g,'.');
 if(source===instance&&type==='messages.update'){
 const raw=event.data?.messages??event.data;const items=Array.isArray(raw)?raw:[raw];r.locals.company=company;
 await tenant(r,async c=>{for(const item of items){const id=item?.key?.id??item?.keyId??item?.id;const status=item?.update?.status??item?.status;const rank=({SERVER_ACK:1,DELIVERY_ACK:2,READ:3,PLAYED:3,'2':1,'3':2,'4':3,'5':3} as Record<string,number>)[String(status).toUpperCase()];if(typeof id!=='string'||id.length>200||!rank)continue;
 await c.query("UPDATE conversations SET data=jsonb_set(data,'{deliveryRank}',to_jsonb($2::int),true) WHERE data->>'providerId'=$1 AND data->>'direction'='sent' AND COALESCE((data->>'deliveryRank')::int,0)<$2",[id,rank]);}});r.json({ok:true});return;
 }
 if(source!==instance||type!=='messages.upsert'){console.info('Evolution webhook ignored',{instanceMatches:source===instance,event:type.slice(0,80)});r.json({ok:true});return;}
 const raw=event.data?.messages??event.data;const items=Array.isArray(raw)?raw:[raw];let imported=0,skipped=0;
 r.locals.company=company;
 await tenant(r,async c=>{for(const item of items){const m=unwrapMessage(item),key=m?.key,phone=directPhone(key);if(key?.fromMe!==false||!phone||typeof key.id!=='string'||key.id.length>200){skipped++;continue;}
 const media=mediaInfo(m),message=media?.text||m.message?.conversation||m.message?.extendedTextMessage?.text;if(typeof message!=='string'||!message.trim()){skipped++;continue;}
 await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[company+':'+key.id]);
 await saveWhatsAppProfile(c,company,phone,m);
 const x=await c.query("INSERT INTO conversations(company_id,title,data) SELECT $1,$2,$3::jsonb WHERE NOT EXISTS(SELECT 1 FROM conversations WHERE data->>'providerId'=$4)",[company,phone,JSON.stringify({phone,text:message.slice(0,16000),direction:'received',providerId:key.id,media,pushName:typeof m.pushName==='string'?m.pushName.slice(0,160):''}),key.id]);imported+=x.rowCount??0;
 }});console.info('Evolution inbound processed',{received:items.length,imported,skipped});r.json({ok:true,imported,skipped});
});
app.use('/api',async(q,r,next)=>{const s=(await pool.query('SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at>now()',[hash(token(q))])).rows[0];if(!s){r.sendStatus(401);return;}r.locals.user=s.user_id;next();});
app.post('/api/logout',async(q,r)=>{await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hash(token(q))]);r.clearCookie('sw_session',{secure:true,httpOnly:true,sameSite:'strict',path:'/'}).json({ok:true});});
app.get('/api/companies',async(_q,r)=>{r.json((await pool.query('SELECT c.id,c.name,m.role FROM companies c JOIN memberships m ON m.company_id=c.id WHERE m.user_id=$1',[r.locals.user])).rows);});
app.use('/api/tenant/:company',async(q,r,next)=>{const id=q.params.company;if(!/^[0-9a-f-]{36}$/i.test(id)){r.sendStatus(400);return;}const m=(await pool.query('SELECT role FROM memberships WHERE company_id=$1 AND user_id=$2',[id,r.locals.user])).rows[0];if(!m){r.sendStatus(403);return;}r.locals.company=id;r.locals.role=m.role;next();});
type TenantContext={locals:{company?:string;[key:string]:any}};
async function tenant(r:TenantContext,fn:(c:pg.PoolClient)=>Promise<unknown>){const c=await pool.connect();try{await c.query('BEGIN');await c.query("SELECT set_config('app.company_id',$1,true)",[r.locals.company]);const result=await fn(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
app.get('/api/tenant/:company/contacts',async(_q,r)=>r.json(await tenant(r,async c=>(await c.query('SELECT * FROM contacts ORDER BY created_at DESC LIMIT 500')).rows)));
app.post('/api/tenant/:company/contacts',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {name,phone}=q.body??{};if(typeof name!=='string'||!name.trim()||name.length>200||typeof phone!=='string'||!/^\+?[1-9]\d{7,14}$/.test(phone)){r.sendStatus(400);return;}r.status(201).json(await tenant(r,async c=>(await c.query('INSERT INTO contacts(company_id,name,phone) VALUES($1,$2,$3) RETURNING *',[r.locals.company,name.trim(),phone.replace(/^\+/,'')])).rows[0]));});
app.post('/api/tenant/:company/contacts/import',async(q,r)=>{
 if(!['owner','admin'].includes(r.locals.role)){r.sendStatus(403);return;}
 const rows=q.body?.leads;if(!Array.isArray(rows)||rows.length>100){r.sendStatus(400);return;}
 let added=0,skipped=0;
 await tenant(r,async c=>{for(const l of rows){const phone=typeof l?.phone==='string'?l.phone.replace(/[+ ()-]/g,''):'',name=typeof l?.name==='string'?l.name.trim():'',value=Number(l?.value??0),stage=l?.stage??'nuevo';
 if(!name||name.length>200||!/^[1-9]\d{7,14}$/.test(phone)||!Number.isFinite(value)||value<0||value>999999999999||!['nuevo','calificado','propuesta','cierre','cliente'].includes(stage)){skipped++;continue;}
 const fields=[l.company_name??l.company??'',l.email??'',l.notes??''];if(!fields.every(x=>typeof x==='string'&&x.length<=2000)){skipped++;continue;}
 const date=new Date(l.createdAt??l.created_at??Date.now());if(!Number.isFinite(date.getTime())){skipped++;continue;}
 const x=await c.query('INSERT INTO contacts(company_id,name,phone,stage,value,company_name,email,notes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(company_id,phone) DO NOTHING',[r.locals.company,name,phone,stage,value,...fields,date]);added+=x.rowCount??0;skipped+=1-(x.rowCount??0);
 }});r.json({added,skipped});
});
app.get('/api/tenant/:company/contacts/export',async(_q,r)=>{r.json({leads:await tenant(r,async c=>(await c.query('SELECT name,phone,stage,value,company_name AS company,email,notes,created_at AS "createdAt" FROM contacts ORDER BY created_at')).rows),exportDate:new Date().toISOString()});});
app.get('/api/tenant/:company/activity',async(_q,r)=>{
 const rows=await tenant(r,async c=>(await c.query("SELECT data->>'phone' AS phone,max(created_at) AS last_contact,count(*) FILTER (WHERE data->>'direction'='received')::int AS received,count(*) FILTER (WHERE data->>'direction'='sent')::int AS sent FROM conversations WHERE data->>'phone' IS NOT NULL GROUP BY data->>'phone'")).rows);r.json(rows);
});
app.patch('/api/tenant/:company/contacts/:id',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {stage,value,company_name,email,notes,name}=q.body??{};if(name!==undefined&&(typeof name!=='string'||!name.trim()||name.length>200)){r.sendStatus(400);return;}if(!['nuevo','calificado','propuesta','cierre','cliente'].includes(stage)||typeof value!=='number'||!Number.isFinite(value)||value<0||value>999999999999||![company_name,email,notes].every(x=>typeof x==='string'&&x.length<=2000)){r.sendStatus(400);return;}const x=await tenant(r,async c=>(await c.query('UPDATE contacts SET stage=$1,value=$2,company_name=$3,email=$4,notes=$5,name=COALESCE($7,name) WHERE id=$6 RETURNING *',[stage,value,company_name,email,notes,q.params.id,name?.trim()??null])).rows[0]);if(!x){r.sendStatus(404);return;}r.json(x);});
app.post('/api/tenant/:company/contacts/:id/labels',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const labels=q.body?.labels;if(!Array.isArray(labels)||labels.length>20||!labels.every(x=>typeof x==='string'&&x.trim().length>0&&x.trim().length<=40)){r.sendStatus(400);return;}const clean=[...new Set(labels.map(x=>x.trim()))];const row=await tenant(r,async c=>(await c.query('UPDATE contacts SET labels=$1 WHERE id=$2 RETURNING labels',[clean,q.params.id])).rows[0]);if(!row){r.sendStatus(404);return;}r.json(row);});
app.delete('/api/tenant/:company/contacts/:id',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}await tenant(r,async c=>c.query('DELETE FROM contacts WHERE id=$1',[q.params.id]));r.json({ok:true});});
async function evolutionGlobal(path:string,body?:unknown,method?:string){
 const {EVOLUTION_URL:base,EVOLUTION_API_KEY:key}=process.env;
 if(!base||!key)throw Error('Revisá EVOLUTION_URL y EVOLUTION_API_KEY global');
 const endpoint=new URL(base.trim());
 if(endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw Error('EVOLUTION_URL debe ser una URL base sin credenciales ni parámetros');
 if(endpoint.protocol!=='https:'&&!(endpoint.origin==='http://167.86.122.123:8080'&&endpoint.pathname==='/'))throw Error('EVOLUTION_URL debe usar HTTPS o el servidor HTTP autorizado 167.86.122.123:8080');
 const response=await fetch(endpoint.href.replace(/\/$/,'')+path,{method:method??(body===undefined?'GET':'POST'),headers:{apikey:key,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Evolution respondió HTTP '+response.status);return response.json();
}

function instanceName(company:string){return 'sw-'+company.toLowerCase();}
async function configuredInstance(company:string){return !!(await tenant({locals:{company}},async c=>(await c.query("SELECT id FROM connections WHERE data->>'kind'='evolution' LIMIT 1")).rows[0]));}
async function evolution(r:TenantContext,path:string,body?:unknown,method?:string){const company=r.locals.company;if(!company||!await configuredInstance(company))throw Error('Creá una instancia de WhatsApp primero');return evolutionGlobal(path+'/'+encodeURIComponent(instanceName(company)),body,method);}
app.get('/api/tenant/:company/whatsapp/config',async(_q,r)=>{const configured=await configuredInstance(r.locals.company);r.json({url:process.env.EVOLUTION_URL??'',instance:configured?instanceName(r.locals.company):'',keyConfigured:!!process.env.EVOLUTION_API_KEY});});
app.post('/api/tenant/:company/whatsapp/create-instance',rateLimit({windowMs:60000,limit:5}),async(_q,r)=>{
 if(!['owner','admin'].includes(r.locals.role)){r.sendStatus(403);return;}
 const company=r.locals.company,name=instanceName(company),secret=process.env.EVOLUTION_WEBHOOK_SECRET,base=process.env.PUBLIC_APP_URL;
 if(!secret||secret.length<32||!base||!base.startsWith('https://')){r.status(400).json({error:'Configurá PUBLIC_APP_URL HTTPS y EVOLUTION_WEBHOOK_SECRET'});return;}
 try{await tenant(r,async c=>{await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[name]);const exists=(await c.query("SELECT id FROM connections WHERE data->>'kind'='evolution'")).rowCount;if(!exists){await evolutionGlobal('/instance/create',{instanceName:name,integration:'WHATSAPP-BAILEYS',qrcode:true});await c.query('INSERT INTO connections(company_id,title,data) VALUES($1,$2,$3)',[company,name,JSON.stringify({kind:'evolution'})]);}});
 await evolution(r,'/webhook/set',{webhook:{enabled:true,url:base.replace(/\/$/,'')+'/api/webhooks/evolution/'+encodeURIComponent(secret),byEvents:false,base64:false,events:['MESSAGES_UPSERT','MESSAGES_UPDATE','CONNECTION_UPDATE']}});r.json({ok:true,instance:name});
 }catch(e){r.status(502).json({error:e instanceof Error?e.message:'No se pudo crear la instancia'});}
});
app.get('/api/tenant/:company/whatsapp/status',async(_q,r)=>{try{const x=await evolution(r,'/instance/connectionState');r.json({state:x.instance?.state??x.state??'unknown'});}catch{r.json({state:'unavailable'});}});
app.post('/api/tenant/:company/whatsapp/connect',rateLimit({windowMs:60000,limit:10}),async(_q,r)=>{
 if(!['owner','admin'].includes(r.locals.role)){r.sendStatus(403);return;}
 try{const state=await evolution(r,'/instance/connectionState').catch(()=>null);if((state?.instance?.state??state?.state)==='open'){r.json({state:'open'});return;}
 const x=await evolution(r,'/instance/connect');const raw=x.base64??x.qrcode?.base64??x.data?.base64??x.data?.qrcode?.base64;
 const image=typeof raw==='string'&&raw.length<2000000?raw.trim():'';
 const qr=/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(image)?image:/^iVBORw0KGgo[A-Za-z0-9+/=]+$/.test(image)?'data:image/png;base64,'+image:null;
 if(qr){r.json({state:'connecting',qr});return;}
 const code=x.code??x.qrcode?.code??x.data?.code??x.data?.qrcode?.code;
 if(typeof code==='string'&&code.length>0&&code.length<4096){r.json({state:'connecting',code});return;}
 if((x.instance?.state??x.state)==='open'){r.json({state:'open'});return;}
 r.status(502).json({error:'Evolution no devolvió QR. Verificá que la instancia exista y esté desconectada.'});
 }catch(e){const msg=e instanceof Error?e.message:'';r.status(502).json({error:/^(Revisá EVOLUTION_|EVOLUTION_URL debe|Evolution respondió HTTP \d{3}$)/.test(msg)?msg:'No se pudo comunicar con Evolution. Revisá red, puerto, certificado si usás HTTPS y disponibilidad.'});}
});
app.post('/api/tenant/:company/whatsapp/disconnect',rateLimit({windowMs:60000,limit:5}),async(_q,r)=>{
 if(!['owner','admin'].includes(r.locals.role)){r.sendStatus(403);return;}
 try{await evolution(r,'/instance/logout',undefined,'DELETE');r.json({ok:true});}catch{r.status(502).json({error:'No se pudo desvincular WhatsApp'});}
});
async function syncEvolution(r:TenantContext){
 const result=await evolution(r,'/chat/findMessages',{where:{},page:1,offset:100});
 const records=Array.isArray(result)?result:result.messages?.records??result.records??result.messages;
 if(!Array.isArray(records))throw Error('Unexpected Evolution response');
 let imported=0;
 await tenant(r,async c=>{for(const item of records.slice(0,100)){const m=unwrapMessage(item),k=m?.key,phone=directPhone(k);
 if(!phone||typeof k.id!=='string'||k.id.length>200||typeof k.fromMe!=='boolean')continue;
 const media=mediaInfo(m),message=media?.text||m.message?.conversation||m.message?.extendedTextMessage?.text;
 if(typeof message!=='string'||!message.trim())continue;
 const ts=Number(m.messageTimestamp),date=Number.isFinite(ts)&&ts>0&&ts<4102444800?new Date(ts*1000):new Date();
 await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[r.locals.company+':'+k.id]);
 if(!k.fromMe)await saveWhatsAppProfile(c,r.locals.company!,phone,m);
 const x=await c.query("INSERT INTO conversations(company_id,title,data,created_at) SELECT $1,$2,$3::jsonb,$5 WHERE NOT EXISTS(SELECT 1 FROM conversations WHERE data->>'providerId'=$4)",[r.locals.company,phone,JSON.stringify({phone,text:message.slice(0,16000),direction:k.fromMe?'sent':'received',providerId:k.id,media,pushName:!k.fromMe&&typeof m.pushName==='string'?m.pushName.slice(0,160):''}),k.id,date]);imported+=x.rowCount??0;
 }});return {imported};
}
const syncInFlight=new Map<string,Promise<{imported:number}>>();
function sharedSync(company:string){let p=syncInFlight.get(company);if(!p){p=syncEvolution({locals:{company}}).finally(()=>{syncInFlight.delete(company)});syncInFlight.set(company,p);}return p;}
app.post('/api/tenant/:company/whatsapp/sync',async(_q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}r.json(await sharedSync(r.locals.company));});
app.get('/api/tenant/:company/whatsapp/messages',async(_q,r)=>r.json(await tenant(r,async c=>(await c.query("SELECT id,title,data - 'mediaBase64' AS data,created_at FROM conversations ORDER BY created_at DESC LIMIT 500")).rows)));
app.get('/api/tenant/:company/whatsapp/media/:id',async(q,r)=>{
 const row:any=await tenant(r,async c=>(await c.query('SELECT data FROM conversations WHERE id=$1',[q.params.id])).rows[0]);const d=row?.data;if(!d?.media){r.sendStatus(404);return;}
 let b64=d.mediaBase64,mime=d.media.mime;
 if(!b64){const x=await evolution(r,'/chat/getBase64FromMediaMessage',{message:{key:{id:d.providerId}},convertToMp4:false});b64=x.base64;mime=(x.mimetype??mime).split(';')[0];}
 if(typeof b64==='string'&&b64.startsWith('data:'))b64=b64.split(',')[1];
 if(!validMedia(d.media.kind,mime,b64)){r.status(415).json({error:'Formato multimedia no compatible'});return;}
 const bytes=Buffer.from(b64,'base64');r.set({'Content-Type':mime,'X-Content-Type-Options':'nosniff','Content-Disposition':kindDisposition(d.media.kind),'Content-Security-Policy':"sandbox; default-src 'none'",'Accept-Ranges':'bytes'});const range=q.headers.range?.match(/^bytes=(\d+)-(\d*)$/);if(range){const start=Number(range[1]),end=range[2]?Math.min(Number(range[2]),bytes.length-1):bytes.length-1;if(start>end||start>=bytes.length){r.set('Content-Range','bytes */'+bytes.length).sendStatus(416);return;}r.status(206).set('Content-Range','bytes '+start+'-'+end+'/'+bytes.length).send(bytes.subarray(start,end+1));return;}r.send(bytes);
});
app.post('/api/tenant/:company/whatsapp/send-media',rateLimit({windowMs:60000,limit:20}),async(q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {phone,kind,mime,base64,caption='',ptt=false}=q.body??{};
 if(typeof phone!=='string'||!/^[1-9]\d{7,14}$/.test(phone)||typeof kind!=='string'||typeof mime!=='string'||!validMedia(kind,mime,base64)||typeof caption!=='string'||caption.length>4000){r.sendStatus(400);return;}
 const allowed=await tenant(r,async c=>{await c.query('INSERT INTO contacts(company_id,name,phone) VALUES($1,$2,$3) ON CONFLICT(company_id,phone) DO NOTHING',[r.locals.company,phone,phone]);return !!(await c.query('SELECT id FROM contacts WHERE phone=$1 AND NOT opted_out',[phone])).rowCount;});if(!allowed){r.sendStatus(403);return;}
 const result=kind==='audio'&&ptt?await evolution(r,'/message/sendWhatsAppAudio',{number:phone,audio:base64}):await evolution(r,'/message/sendMedia',{number:phone,mediatype:kind,mimetype:mime,media:base64,caption,fileName:'archivo.'+mime.split('/')[1]});
 await tenant(r,async c=>c.query('INSERT INTO conversations(company_id,title,data) VALUES($1,$2,$3)',[r.locals.company,phone,JSON.stringify({phone,text:caption||'['+kind+']',direction:'sent',providerId:result.key?.id,media:{kind,mime,ptt},mediaBase64:base64})]));r.json({ok:true});
});
app.get('/api/tenant/:company/whatsapp/queue',async(_q,r)=>r.json(await tenant(r,async c=>(await c.query("SELECT id,title,created_at,data - 'payload' AS data FROM automations WHERE data->>'kind'='outbound_text' ORDER BY created_at DESC LIMIT 200")).rows)));
app.post('/api/tenant/:company/whatsapp/queue',rateLimit({windowMs:60000,limit:20}),async(q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {phone,text,requestId}=q.body??{};
 if(typeof phone!=='string'||! /^[1-9]\d{7,14}$/.test(phone)||typeof text!=='string'||!text.trim()||text.length>4000||typeof requestId!=='string'||! /^[0-9a-f-]{36}$/i.test(requestId)){r.sendStatus(400);return;}
 if(!await configuredInstance(r.locals.company)){r.status(400).json({error:'Evolution no configurado'});return;}
 const row=await tenant(r,async c=>{await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[r.locals.company+':queue:'+requestId]);const old=(await c.query("SELECT id FROM automations WHERE data->>'kind'='outbound_text' AND data->>'requestId'=$1",[requestId])).rows[0];if(old)return old;
 return (await c.query("INSERT INTO automations(company_id,title,data) VALUES($1,$2,$3) RETURNING id",[r.locals.company,phone,JSON.stringify({kind:'outbound_text',requestId,phone,text,state:'pending'})])).rows[0];});r.status(202).json(row);
});
app.post('/api/tenant/:company/whatsapp/send',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {phone,text,replyId}=q.body??{};if(typeof phone!=='string'||! /^[1-9]\d{7,14}$/.test(phone)||typeof text!=='string'||!text.trim()||text.length>4000){r.sendStatus(400);return;}
 const allowed=await tenant(r,async c=>{
 await c.query('INSERT INTO contacts(company_id,name,phone) VALUES($1,$2,$3) ON CONFLICT(company_id,phone) DO NOTHING',[r.locals.company,phone,phone]);
 return !!(await c.query('SELECT id FROM contacts WHERE phone=$1 AND NOT opted_out',[phone])).rowCount;
 });if(!allowed){r.status(403).json({error:'El destinatario ha solicitado no recibir mensajes.'});return;}
 let quoted:any,replyText:string|undefined;if(replyId!==undefined){if(typeof replyId!=='string'||! /^[0-9a-f-]{36}$/i.test(replyId)){r.sendStatus(400);return;}const row:any=await tenant(r,async c=>(await c.query("SELECT data FROM conversations WHERE id=$1 AND data->>'phone'=$2",[replyId,phone])).rows[0]);if(!row?.data?.providerId||row.data.media){r.status(400).json({error:'Solo se pueden citar mensajes de texto con identificador de WhatsApp'});return;}replyText=String(row.data.text??'').slice(0,4000);quoted={key:{id:row.data.providerId,remoteJid:phone+'@s.whatsapp.net',fromMe:row.data.direction==='sent'},message:{conversation:replyText}};}
 const result=await evolution(r,'/message/sendText',{number:phone,text,...(quoted?{quoted}:{})});await tenant(r,async c=>c.query('INSERT INTO conversations(company_id,title,data) VALUES($1,$2,$3)',[r.locals.company,phone,JSON.stringify({phone,text,direction:'sent',providerId:result.key?.id,replyText})]));r.json({ok:true});});
app.post('/api/tenant/:company/contacts/:id/consent',async(q,r)=>{if(!['owner','admin'].includes(r.locals.role)||typeof q.body?.consent!=='boolean'){r.sendStatus(403);return;}await tenant(r,async c=>c.query('UPDATE contacts SET consent_at=CASE WHEN $1 THEN now() ELSE NULL END,opted_out=NOT $1 WHERE id=$2',[q.body.consent,q.params.id]));r.json({ok:true});});
app.get('/api/tenant/:company/tasks',async(_q,r)=>r.json(await tenant(r,async c=>(await c.query("SELECT a.*,c.name AS contact_name,c.phone FROM appointments a LEFT JOIN contacts c ON c.id::text=a.data->>'contactId' WHERE a.data->>'kind'='task' ORDER BY a.data->>'due' LIMIT 1000")).rows)));
app.post('/api/tenant/:company/tasks',async(q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}
 const {title,contactId,due,priority,notes}=q.body??{};
 if(typeof title!=='string'||!title.trim()||title.length>200||typeof contactId!=='string'||!/^[0-9a-f-]{36}$/i.test(contactId)||typeof due!=='string'||!Number.isFinite(Date.parse(due))||!['low','normal','high'].includes(priority)||typeof notes!=='string'||notes.length>2000){r.sendStatus(400);return;}
 const result=await tenant(r,async c=>(await c.query("INSERT INTO appointments(company_id,title,data) SELECT $1,$2,$3::jsonb WHERE EXISTS(SELECT 1 FROM contacts WHERE id=$4) RETURNING id",[r.locals.company,title.trim(),JSON.stringify({kind:'task',contactId,due:new Date(due).toISOString(),priority,notes,done:false,createdBy:r.locals.user}),contactId])).rows[0]);
 if(!result){r.sendStatus(404);return;}r.status(201).json(result);
});
app.patch('/api/tenant/:company/tasks/:id',async(q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}if(typeof q.body?.done!=='boolean'){r.sendStatus(400);return;}
 const result=await tenant(r,async c=>(await c.query("UPDATE appointments SET data=data || $1::jsonb WHERE id=$2 AND data->>'kind'='task' RETURNING id",[JSON.stringify({done:q.body.done,completedAt:q.body.done?new Date().toISOString():null}),q.params.id])).rows[0]);if(!result){r.sendStatus(404);return;}r.json(result);
});
app.delete('/api/tenant/:company/tasks/:id',async(q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}await tenant(r,async c=>c.query("DELETE FROM appointments WHERE id=$1 AND data->>'kind'='task'",[q.params.id]));r.json({ok:true});
});
app.use('/api',(_q,r)=>r.sendStatus(404));
app.use(express.static('dist/web'));app.get('/',(_q,r)=>r.sendFile('index.html',{root:'dist/web'}));
app.use((e:any,_q:express.Request,r:express.Response,_n:express.NextFunction)=>{console.error('Request failed',e.code??'internal');r.status(e.code==='23505'?409:500).json({error:'Request failed'});});
app.listen(Number(process.env.PORT??3000),'0.0.0.0');
async function activeCompanies(){const rows=(await pool.query('SELECT id FROM companies')).rows;const ids:string[]=[];for(const row of rows)if(await configuredInstance(row.id))ids.push(row.id);return ids;}
async function automaticSync(){try{for(const company of await activeCompanies()){try{await sharedSync(company);}catch{console.warn('Evolution automatic sync failed');}}}catch{console.warn('Evolution sync scan failed');}finally{setTimeout(automaticSync,5000).unref();}}
void automaticSync();
async function outboundWorker(){try{for(const company of await activeCompanies()){const ctx={locals:{company}};
 const job:any=await tenant(ctx,async c=>(await c.query("UPDATE automations SET data=data || jsonb_build_object('state','processing','startedAt',now()) WHERE id=(SELECT id FROM automations WHERE data->>'kind'='outbound_text' AND data->>'state'='pending' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,data")).rows[0]);
 if(job){let state='uncertain',error='Envío sin confirmar; revisar historial antes de reenviar';try{const allowed=await tenant(ctx,async c=>!(await c.query('SELECT id FROM contacts WHERE phone=$1 AND opted_out',[job.data.phone])).rowCount);if(!allowed){state='failed';error='Destinatario excluido';}else{const result=await evolution(ctx,'/message/sendText',{number:job.data.phone,text:job.data.text});await tenant(ctx,async c=>{await c.query('INSERT INTO contacts(company_id,name,phone) VALUES($1,$2,$2) ON CONFLICT(company_id,phone) DO NOTHING',[company,job.data.phone]);await c.query('INSERT INTO conversations(company_id,title,data) VALUES($1,$2,$3)',[company,job.data.phone,JSON.stringify({phone:job.data.phone,text:job.data.text,direction:'sent',providerId:result.key?.id})]);await c.query("UPDATE automations SET data=data || jsonb_build_object('state','sent','finishedAt',now()) WHERE id=$1",[job.id]);});state='sent';}}catch{}if(state!=='sent')await tenant(ctx,async c=>c.query("UPDATE automations SET data=data || jsonb_build_object('state',$2::text,'error',$3::text,'finishedAt',now()) WHERE id=$1",[job.id,state,error]));}
 }}catch{console.warn('Outbound queue worker failed');}finally{setTimeout(outboundWorker,3000).unref();}}
void outboundWorker();
