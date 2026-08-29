
const {sb,json,requireAuth,requireAdmin,body,cleanKey,safeError}=require('./_supabase');
function keyName(prefix){const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';let s='';for(let i=0;i<8;i++)s+=c[Math.floor(Math.random()*c.length)];return `${(prefix||'FG').toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,6)||'FG'}-${s.slice(0,4)}-${s.slice(4)}`;}
async function oneKey(key, select='*'){const rows=await sb(`keys?key=eq.${encodeURIComponent(cleanKey(key))}&select=${encodeURIComponent(select)}&limit=1`);return rows[0]||null;}
async function canAccess(s,k){return s.role==='admin'||(s.role==='reseller'&&k.reseller_id===s.reseller_id);}
module.exports=async(req,res)=>{
 try{
  const s=requireAuth(req,res); if(!s)return;
  if(req.method==='GET'){
    let path='keys?select=*&order=created_at.desc';
    if(s.role==='reseller')path+=`&reseller_id=eq.${encodeURIComponent(s.reseller_id)}`;
    const rows=await sb(path);
    return json(res,200,rows);
  }
  if(req.method!=='POST')return json(res,405,{error:'method_not_allowed'});
  const b=body(req), action=String(b.action||'');
  if(action==='create'){
    const owner=String(b.owner||'').trim(); if(!owner)return json(res,400,{error:'missing_owner'});
    const days=Math.max(1,Math.min(3650,Math.floor(Number(b.days)||30)));
    const rawDL=Number(b.device_limit); const dl=Math.max(0,Math.min(1000,Number.isFinite(rawDL)?Math.floor(rawDL):1));
    const priceRow=(await sb(`settings?key=eq.key_price_per_day&select=value&limit=1`))[0];
    const price=Math.max(0,Number(priceRow?.value||1000)); const cost=days*price;
    let resellerId=null, resellerName='', key=cleanKey(b.key)||'';
    if(s.role==='reseller'){
      const r=(await sb(`resellers?id=eq.${encodeURIComponent(s.reseller_id)}&select=id,name,prefix&limit=1`))[0];
      if(!r)return json(res,404,{error:'reseller_not_found'});
      resellerId=r.id; resellerName=r.name;
      if(!key)key=keyName(r.prefix);
      const result=await sb('rpc/create_reseller_key',{method:'POST',body:JSON.stringify({p_reseller_id:r.id,p_key:key,p_owner:owner,p_expires_at:new Date(Date.now()+days*86400000).toISOString(),p_cost:cost,p_device_limit:dl})});
      return json(res,201,result);
    }
    const rr=String(b.reseller||'').trim();
    if(rr){
      const r=(await sb(`resellers?name=eq.${encodeURIComponent(rr)}&select=id,name&limit=1`))[0];
      if(!r)return json(res,404,{error:'reseller_not_found'});
      resellerId=r.id;resellerName=r.name;
    }
    if(!key)key=keyName(resellerName?String(resellerName).slice(0,3):'FG');
    const rows=await sb('keys',{method:'POST',headers:{Prefer:'return=representation'},body:JSON.stringify({key,owner,status:'active',expires_at:new Date(Date.now()+days*86400000).toISOString(),reseller:resellerName,reseller_id:resellerId,cost,device_limit:dl,devices:[]})});
    return json(res,201,rows[0]);
  }
  const key=cleanKey(b.key); if(!key)return json(res,400,{error:'missing_key'});
  const k=await oneKey(key); if(!k)return json(res,404,{error:'not_found'});
  if(!await canAccess(s,k))return json(res,403,{error:'forbidden'});
  if(['block','unblock','revoke'].includes(action)){
    if(s.role!=='admin'&&action==='revoke')return json(res,403,{error:'forbidden'});
    const status=action==='block'?'blocked':action==='revoke'?'revoked':'active';
    const out=await sb(`keys?id=eq.${k.id}`,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({status})});
    return json(res,200,out[0]);
  }
  if(action==='delete'){
    // Admin: any key. Reseller: only keys owned by that reseller.
    if(s.role!=='admin' && !(s.role==='reseller' && k.reseller_id===s.reseller_id))
      return json(res,403,{error:'forbidden'});
    await sb(`keys?id=eq.${k.id}`,{method:'DELETE'});
    return json(res,200,{ok:true});
  }
  if(action==='reset-devices'||action==='reset_devices'){
    const out=await sb(`keys?id=eq.${k.id}`,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({devices:[],uid:null})});
    return json(res,200,out[0]);
  }
  if(action==='set-device-limit'){
    const dl=Math.max(0,Math.min(1000,Math.floor(Number(b.device_limit))));
    if(!Number.isFinite(dl))return json(res,400,{error:'invalid_device_limit'});
    const count=Array.isArray(k.devices)?k.devices.length:0;
    if(dl>0&&count>dl)return json(res,400,{error:'limit_below_current_devices',device_count:count,device_limit:dl});
    const out=await sb(`keys?id=eq.${k.id}`,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({device_limit:dl})});
    return json(res,200,out[0]);
  }
  if(action==='extend'){
    const days=Math.max(1,Math.min(3650,Math.floor(Number(b.days)||30)));
    const priceRow=(await sb(`settings?key=eq.key_price_per_day&select=value&limit=1`))[0];
    const cost=days*Math.max(0,Number(priceRow?.value||1000));
    if(s.role==='reseller'){
      const out=await sb('rpc/extend_reseller_key',{method:'POST',body:JSON.stringify({p_key:key,p_reseller_id:s.reseller_id,p_days:days,p_cost:cost})});
      return json(res,200,out);
    }
    const base=Math.max(new Date(k.expires_at).getTime(),Date.now());
    const out=await sb(`keys?id=eq.${k.id}`,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({expires_at:new Date(base+days*86400000).toISOString(),status:k.status==='expired'?'active':k.status,cost:Number(k.cost||0)+cost})});
    return json(res,200,out[0]);
  }
  return json(res,400,{error:'unknown_action'});
 }catch(e){const [code,msg]=safeError(e);return json(res,500,{error:code,message:msg,detail:process.env.NODE_ENV==='development'?String(e.message||e):undefined})}
};
