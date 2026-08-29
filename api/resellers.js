
const {sb,json,requireAuth,requireAdmin,body,hashPassword,safeError}=require('./_supabase');
module.exports=async(req,res)=>{
 try{
  const s=requireAuth(req,res);if(!s)return;
  if(req.method==='GET'){
    if(s.role==='admin') return json(res,200,await sb('resellers?select=id,name,username,quota,sold,expires_at,prefix,balance,active,created_at&order=created_at.desc'));
    const r=(await sb(`resellers?id=eq.${encodeURIComponent(s.reseller_id)}&select=id,name,username,quota,sold,expires_at,prefix,balance,active,created_at&limit=1`))[0];
    return json(res,200,r||null);
  }
  if(req.method!=='POST')return json(res,405,{error:'method_not_allowed'});
  const b=body(req), action=String(b.action||'');
  if(action==='create'){
    if(s.role!=='admin')return json(res,403,{error:'forbidden'});
    const name=String(b.name||'').trim(), username=String(b.username||name).trim().toLowerCase();
    const password=String(b.password||''); const quota=Math.max(0,Math.floor(Number(b.quota)||0));
    const days=Math.max(1,Math.min(3650,Math.floor(Number(b.days)||30)));
    const prefix=String(b.prefix||name.slice(0,3)||'RS').toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,3)||'RS';
    const balance=Math.max(0,Math.floor(Number(b.balance)||0));
    if(!name||!username||password.length<6)return json(res,400,{error:'invalid_reseller'});
    const r=await sb('rpc/admin_set_reseller',{method:'POST',body:JSON.stringify({p_name:name,p_username:username,p_password_hash:hashPassword(password),p_quota:quota,p_days:days,p_prefix:prefix,p_balance:balance})});
    return json(res,201,r);
  }
  if(action==='delete'){
    if(s.role!=='admin')return json(res,403,{error:'forbidden'});
    const id=String(b.id||''); if(!id)return json(res,400,{error:'missing_id'});
    await sb(`resellers?id=eq.${encodeURIComponent(id)}`,{method:'PATCH',headers:{Prefer:'return=minimal'},body:JSON.stringify({active:false})});
    return json(res,200,{ok:true});
  }
  if(action==='topup'){
    if(s.role!=='admin')return json(res,403,{error:'forbidden'});
    const id=String(b.id||''), amount=Math.floor(Number(b.amount)||0);
    if(!id||amount<1000)return json(res,400,{error:'invalid_amount'});
    const r=await sb('rpc/admin_topup_reseller',{method:'POST',body:JSON.stringify({p_reseller_id:id,p_amount:amount})});
    return json(res,200,r);
  }
  if(action==='reset-password'){
    if(s.role!=='admin')return json(res,403,{error:'forbidden'});
    const id=String(b.id||''), password=String(b.password||''); if(!id||password.length<6)return json(res,400,{error:'invalid_password'});
    const out=await sb(`resellers?id=eq.${encodeURIComponent(id)}`,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({password_hash:hashPassword(password)})});
    return json(res,200,{ok:true,reseller:out[0]});
  }
  return json(res,400,{error:'unknown_action'});
 }catch(e){const [code,msg]=safeError(e);return json(res,500,{error:code,message:msg})}
};
