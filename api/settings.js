
const {sb,json,requireAuth,requireAdmin}=require('./_supabase');
module.exports=async(req,res)=>{
 try{
  const s=requireAuth(req,res);if(!s)return;
  if(req.method==='GET'){
    const rows=await sb('settings?select=key,value');
    const out={};rows.forEach(x=>out[x.key]=x.value);
    return json(res,200,out);
  }
  if(req.method==='POST'){
    if(s.role!=='admin')return json(res,403,{error:'forbidden'});
    const b=typeof req.body==='object'&&req.body?req.body:{};
    const price=Math.max(100,Math.floor(Number(b.key_price_per_day)||0));
    if(!price)return json(res,400,{error:'invalid_price'});
    const out=await sb('settings?key=eq.key_price_per_day',{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({value:String(price),updated_at:new Date().toISOString()})});
    if(!out.length)await sb('settings',{method:'POST',body:JSON.stringify({key:'key_price_per_day',value:String(price)})});
    return json(res,200,{key_price_per_day:String(price)});
  }
  return json(res,405,{error:'method_not_allowed'});
 }catch(e){return json(res,500,{error:'server_error',message:String(e.message||e)})}
};
