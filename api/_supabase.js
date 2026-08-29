
const crypto = require('crypto');

function env(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}
async function sb(path, options={}) {
  const base=env('SUPABASE_URL').replace(/\/$/,'');
  const key=env('SUPABASE_SECRET_KEY');
  const headers={apikey:key,Authorization:`Bearer ${key}`,'Content-Type':'application/json',...(options.headers||{})};
  const res=await fetch(`${base}/rest/v1/${path}`,{...options,headers});
  const text=await res.text();
  let data=null; try{data=text?JSON.parse(text):null}catch{data=text}
  if(!res.ok) throw new Error(typeof data==='string'?data:JSON.stringify(data));
  return data;
}
function json(res,status,body){res.status(status).setHeader('Content-Type','application/json');res.end(JSON.stringify(body));}
function b64(o){return Buffer.from(JSON.stringify(o)).toString('base64url');}
function sign(payload){
  const raw=b64(payload);
  const sig=crypto.createHmac('sha256',env('SESSION_SECRET')).update(raw).digest('base64url');
  return raw+'.'+sig;
}
function verifyToken(token){
  try{
    const [raw,sig]=String(token||'').split('.');
    if(!raw||!sig) return null;
    const expected=crypto.createHmac('sha256',env('SESSION_SECRET')).update(raw).digest('base64url');
    if(sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) return null;
    const p=JSON.parse(Buffer.from(raw,'base64url').toString());
    if(!p.exp||p.exp<Date.now()) return null;
    return p;
  }catch{return null}
}
function auth(req){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):'';
  if(token && process.env.PANEL_ADMIN_TOKEN && token===process.env.PANEL_ADMIN_TOKEN)
    return {role:'admin',username:'admin',name:''};
  return verifyToken(token);
}
function requireAuth(req,res){
  const s=auth(req);
  if(!s){json(res,401,{error:'unauthorized'});return null}
  return s;
}
function requireAdmin(req,res){
  const s=requireAuth(req,res);
  if(!s) return null;
  if(s.role!=='admin'){json(res,403,{error:'forbidden'});return null}
  return s;
}
function body(req){return typeof req.body==='object'&&req.body?req.body:{}}
function cleanKey(v){return String(v||'').trim().toUpperCase()}
function safeError(e){
  const s=String(e&&e.message||e);
  if(/insufficient_balance/i.test(s)) return ['insufficient_balance','Saldo reseller tidak cukup.'];
  if(/quota_exceeded/i.test(s)) return ['quota_exceeded','Kuota key reseller habis.'];
  if(/reseller_expired/i.test(s)) return ['reseller_expired','Masa aktif reseller habis.'];
  if(/duplicate_key/i.test(s)||/duplicate/i.test(s)) return ['duplicate_key','Key sudah ada.'];
  if(/key_not_found/i.test(s)) return ['not_found','Key tidak ditemukan.'];
  if(/revoked/i.test(s)) return ['revoked','Key sudah dicabut.'];
  if(/reseller_exists/i.test(s)) return ['reseller_exists','Username/nama reseller sudah digunakan.'];
  if(/invalid_amount/i.test(s)) return ['invalid_amount','Jumlah tidak valid.'];
  return ['server_error','Terjadi kesalahan server.'];
}
function hashPassword(password){
  const salt=crypto.randomBytes(16).toString('hex');
  const hash=crypto.scryptSync(String(password),salt,64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}
function verifyPassword(password,stored){
  try{
    const [tag,salt,hex]=String(stored||'').split(':');
    if(tag!=='scrypt'||!salt||!hex)return false;
    const a=Buffer.from(hex,'hex');
    const b=crypto.scryptSync(String(password),salt,a.length);
    return a.length===b.length&&crypto.timingSafeEqual(a,b);
  }catch{return false}
}
module.exports={env,sb,json,auth,requireAuth,requireAdmin,body,cleanKey,sign,hashPassword,verifyPassword,safeError};
