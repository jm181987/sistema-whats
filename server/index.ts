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
async function initialize(){
 const c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(782019)');
 const role=await c.query('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user');
 if(role.rows[0].rolsuper||role.rows[0].rolbypassrls) throw Error('Unsafe database role');
 await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)');
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=1')).rowCount){await c.query(await readFile('migrations/001.sql','utf8'));await c.query('INSERT INTO schema_migrations VALUES(1)');}
 if(!(await c.query('SELECT 1 FROM schema_migrations WHERE version=2')).rowCount){await c.query("ALTER TABLE contacts ADD COLUMN stage text NOT NULL DEFAULT 'nuevo', ADD COLUMN value numeric(14,2) NOT NULL DEFAULT 0, ADD COLUMN company_name text NOT NULL DEFAULT '', ADD COLUMN email text NOT NULL DEFAULT '', ADD COLUMN notes text NOT NULL DEFAULT ''");await c.query('INSERT INTO schema_migrations VALUES(2)');}
 const {BOOTSTRAP_EMAIL:e,BOOTSTRAP_PASSWORD:p,BOOTSTRAP_COMPANY:n}=process.env;
 if(!(await c.query('SELECT 1 FROM users LIMIT 1')).rowCount){
 if(!e||!p||p.length<14||!n)throw Error('Bootstrap email, company and password (14+ chars) required');
 const u=(await c.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id',[e.trim().toLowerCase(),await bcrypt.hash(p,12)])).rows[0];
 const t=(await c.query('INSERT INTO companies(name) VALUES($1) RETURNING id',[n])).rows[0];
 await c.query("INSERT INTO memberships VALUES($1,$2,'owner')",[t.id,u.id]);}
 await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
await initialize();
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'64kb'}));
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
app.post('/api/webhooks/evolution/:secret',async(q,r)=>{
 const secret=process.env.EVOLUTION_WEBHOOK_SECRET,company=process.env.EVOLUTION_COMPANY_ID,instance=process.env.EVOLUTION_INSTANCE;
 if(!secret||secret.length<32||!company||!instance||hash(q.params.secret)!==hash(secret)){r.sendStatus(404);return;}
 const event=q.body;if(event?.instance!==instance||String(event?.event).toLowerCase().replace(/_/g,'.')!=='messages.upsert'){r.json({ok:true});return;}
 const items=Array.isArray(event.data)?event.data:[event.data];
 r.locals.company=company;
 await tenant(r,async c=>{for(const m of items){const key=m?.key;const jid=key?.remoteJid;if(key?.fromMe!==false||typeof jid!=='string'||!/^\d{8,15}@s\.whatsapp\.net$/.test(jid)||typeof key.id!=='string'||key.id.length>200)continue;
 const phone=jid.split('@')[0],message=m.message?.conversation??m.message?.extendedTextMessage?.text;if(typeof message!=='string'||!message.trim())continue;
 await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[company+':'+key.id]);
 await c.query("INSERT INTO conversations(company_id,title,data) SELECT $1,$2,$3::jsonb WHERE NOT EXISTS(SELECT 1 FROM conversations WHERE data->>'providerId'=$4)",[company,phone,JSON.stringify({phone,text:message.slice(0,16000),direction:'received',providerId:key.id}),key.id]);}});
 r.json({ok:true});
});
app.use('/api',async(q,r,next)=>{const s=(await pool.query('SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at>now()',[hash(token(q))])).rows[0];if(!s){r.sendStatus(401);return;}r.locals.user=s.user_id;next();});
app.post('/api/logout',async(q,r)=>{await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hash(token(q))]);r.clearCookie('sw_session',{secure:true,httpOnly:true,sameSite:'strict',path:'/'}).json({ok:true});});
app.get('/api/companies',async(_q,r)=>{r.json((await pool.query('SELECT c.id,c.name,m.role FROM companies c JOIN memberships m ON m.company_id=c.id WHERE m.user_id=$1',[r.locals.user])).rows);});
app.use('/api/tenant/:company',async(q,r,next)=>{const id=q.params.company;if(!/^[0-9a-f-]{36}$/i.test(id)){r.sendStatus(400);return;}const m=(await pool.query('SELECT role FROM memberships WHERE company_id=$1 AND user_id=$2',[id,r.locals.user])).rows[0];if(!m){r.sendStatus(403);return;}r.locals.company=id;r.locals.role=m.role;next();});
async function tenant(r:express.Response,fn:(c:pg.PoolClient)=>Promise<unknown>){const c=await pool.connect();try{await c.query('BEGIN');await c.query("SELECT set_config('app.company_id',$1,true)",[r.locals.company]);const result=await fn(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
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
app.patch('/api/tenant/:company/contacts/:id',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {stage,value,company_name,email,notes}=q.body??{};if(!['nuevo','calificado','propuesta','cierre','cliente'].includes(stage)||typeof value!=='number'||!Number.isFinite(value)||value<0||value>999999999999||![company_name,email,notes].every(x=>typeof x==='string'&&x.length<=2000)){r.sendStatus(400);return;}const x=await tenant(r,async c=>(await c.query('UPDATE contacts SET stage=$1,value=$2,company_name=$3,email=$4,notes=$5 WHERE id=$6 RETURNING *',[stage,value,company_name,email,notes,q.params.id])).rows[0]);if(!x){r.sendStatus(404);return;}r.json(x);});
app.delete('/api/tenant/:company/contacts/:id',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}await tenant(r,async c=>c.query('DELETE FROM contacts WHERE id=$1',[q.params.id]));r.json({ok:true});});
async function evolution(r:express.Response,path:string,body?:unknown,method?:string){
 const {EVOLUTION_URL:base,EVOLUTION_API_KEY:key,EVOLUTION_INSTANCE:instance,EVOLUTION_COMPANY_ID:company}=process.env;
 if(!base||!key||!instance||company!==r.locals.company)throw Error('Revisá EVOLUTION_URL, EVOLUTION_API_KEY, EVOLUTION_INSTANCE y EVOLUTION_COMPANY_ID');
 const endpoint=new URL(base.trim());
 if(endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw Error('EVOLUTION_URL debe ser una URL base sin credenciales ni parámetros');
 if(endpoint.protocol!=='https:'&&!(endpoint.origin==='http://167.86.122.123:8080'&&endpoint.pathname==='/'))throw Error('EVOLUTION_URL debe usar HTTPS o el servidor HTTP autorizado 167.86.122.123:8080');
 const response=await fetch(endpoint.href.replace(/\/$/,'')+path+'/'+encodeURIComponent(instance),{method:method??(body===undefined?'GET':'POST'),headers:{apikey:key,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Evolution respondió HTTP '+response.status);return response.json();
}
app.get('/api/tenant/:company/whatsapp/config',(_q,r)=>{const configured=process.env.EVOLUTION_COMPANY_ID===r.locals.company;r.json({url:configured?process.env.EVOLUTION_URL??'':'',instance:configured?process.env.EVOLUTION_INSTANCE??'':'',keyConfigured:configured&&!!process.env.EVOLUTION_API_KEY});});
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
app.post('/api/tenant/:company/whatsapp/sync',async(_q,r)=>{
 if(r.locals.role==='viewer'){r.sendStatus(403);return;}
 const result=await evolution(r,'/chat/findMessages',{where:{},page:1,offset:100});
 const records=Array.isArray(result)?result:result.messages?.records??result.records??result.messages;
 if(!Array.isArray(records)){r.status(502).json({error:'Unexpected Evolution response'});return;}
 let imported=0;
 await tenant(r,async c=>{for(const m of records.slice(0,100)){const k=m?.key,jid=k?.remoteJid;
 if(typeof jid!=='string'||!/^\d{8,15}@s\.whatsapp\.net$/.test(jid)||typeof k.id!=='string'||k.id.length>200||typeof k.fromMe!=='boolean')continue;
 const phone=jid.split('@')[0],message=m.message?.conversation??m.message?.extendedTextMessage?.text;
 if(typeof message!=='string'||!message.trim())continue;
 const ts=Number(m.messageTimestamp),date=Number.isFinite(ts)&&ts>0&&ts<4102444800?new Date(ts*1000):new Date();
 await c.query('SELECT pg_advisory_xact_lock(hashtext($1))',[r.locals.company+':'+k.id]);
 const x=await c.query("INSERT INTO conversations(company_id,title,data,created_at) SELECT $1,$2,$3::jsonb,$5 WHERE NOT EXISTS(SELECT 1 FROM conversations WHERE data->>'providerId'=$4)",[r.locals.company,phone,JSON.stringify({phone,text:message.slice(0,16000),direction:k.fromMe?'sent':'received',providerId:k.id}),k.id,date]);imported+=x.rowCount??0;
 }});r.json({imported});
});
app.get('/api/tenant/:company/whatsapp/messages',async(_q,r)=>r.json(await tenant(r,async c=>(await c.query("SELECT id,title,data,created_at FROM conversations ORDER BY created_at DESC LIMIT 500")).rows)));
app.post('/api/tenant/:company/whatsapp/send',async(q,r)=>{if(r.locals.role==='viewer'){r.sendStatus(403);return;}const {phone,text}=q.body??{};if(typeof phone!=='string'||! /^[1-9]\d{7,14}$/.test(phone)||typeof text!=='string'||!text.trim()||text.length>4000){r.sendStatus(400);return;}
 const allowed=await tenant(r,async c=>{
 const existing=(await c.query('SELECT consent_at,opted_out FROM contacts WHERE phone=$1',[phone])).rows[0];
 if(existing?.opted_out)return false;
 if(existing?.consent_at)return true;
 if(q.body.manual!==true||q.body.authorized!==true)return false;
 await c.query('INSERT INTO contacts(company_id,name,phone,consent_at) VALUES($1,$2,$3,now()) ON CONFLICT(company_id,phone) DO NOTHING',[r.locals.company,phone,phone]);
 return !!(await c.query('SELECT id FROM contacts WHERE phone=$1 AND consent_at IS NOT NULL AND NOT opted_out',[phone])).rowCount;
 });if(!allowed){r.status(403).json({error:'El destinatario no tiene autorización registrada o ha solicitado no recibir mensajes.'});return;}
 const result=await evolution(r,'/message/sendText',{number:phone,text});await tenant(r,async c=>c.query('INSERT INTO conversations(company_id,title,data) VALUES($1,$2,$3)',[r.locals.company,phone,JSON.stringify({phone,text,direction:'sent',providerId:result.key?.id})]));r.json({ok:true});});
app.post('/api/tenant/:company/contacts/:id/consent',async(q,r)=>{if(!['owner','admin'].includes(r.locals.role)||typeof q.body?.consent!=='boolean'){r.sendStatus(403);return;}await tenant(r,async c=>c.query('UPDATE contacts SET consent_at=CASE WHEN $1 THEN now() ELSE NULL END,opted_out=NOT $1 WHERE id=$2',[q.body.consent,q.params.id]));r.json({ok:true});});
app.use('/api',(_q,r)=>r.sendStatus(404));
app.use(express.static('dist/web'));app.get('/',(_q,r)=>r.sendFile('index.html',{root:'dist/web'}));
app.use((e:any,_q:express.Request,r:express.Response,_n:express.NextFunction)=>{console.error('Request failed',e.code??'internal');r.status(e.code==='23505'?409:500).json({error:'Request failed'});});
app.listen(Number(process.env.PORT??3000),'0.0.0.0');
