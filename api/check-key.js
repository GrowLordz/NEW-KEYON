
const {sb,json}=require('./_supabase');
module.exports=async(req,res)=>{
 try{
  if(req.method!=='POST')return json(res,405,{valid:false,error:'method_not_allowed'});
  const b=typeof req.body==='object'&&req.body?req.body:{};
  const key=String(b.key||'').trim().toUpperCase(), uid=String(b.uid||'').trim();
  if(!key)return json(res,400,{valid:false,error:'missing_key'});
  if(!uid)return json(res,400,{valid:false,error:'missing_uid'});
  const result=await sb('rpc/check_and_bind_device',{method:'POST',body:JSON.stringify({p_key:key,p_uid:uid})});
  if(!result||result.valid!==true)return json(res,200,result||{valid:false,reason:'invalid'});
  const rows=await sb(`keys?key=eq.${encodeURIComponent(key)}&select=key,owner,status,expires_at,device_limit,devices,reseller,cost&limit=1`);
  const k=rows[0]||{}, exp=new Date(k.expires_at).getTime();
  return json(res,200,{
    valid:true,reason:result.reason||'ok',key:k.key||key,owner:k.owner||'',
    expire:k.expires_at||result.expire,days_left:Number.isFinite(exp)?Math.max(0,Math.ceil((exp-Date.now())/86400000)):0,
    device_limit:Number(k.device_limit??result.device_limit??1),
    device_count:Array.isArray(k.devices)?k.devices.length:Number(result.device_count||0),
    uid_bound:true
  });
 }catch(e){return json(res,500,{valid:false,error:'server_error',message:String(e.message||e)})}
};
