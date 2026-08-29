
const {sb,json,body,sign,hashPassword,verifyPassword,auth}=require('./_supabase');
module.exports=async(req,res)=>{
  try{
    if(req.method==='GET'){
      const s=auth(req);
      if(!s)return json(res,401,{error:'unauthorized'});
      return json(res,200,{authenticated:true,role:s.role,username:s.username,name:s.name||''});
    }
    if(req.method!=='POST')return json(res,405,{error:'method_not_allowed'});
    const b=body(req), username=String(b.username||'').trim().toLowerCase(), password=String(b.password||'');
    if(!username||!password)return json(res,400,{error:'missing_credentials'});
    if(username==='admin'){
      if(password!==process.env.PANEL_ADMIN_TOKEN)return json(res,401,{error:'invalid_credentials'});
      return json(res,200,{token:sign({role:'admin',username:'admin',name:'',iat:Date.now(),exp:Date.now()+8*60*60*1000}),role:'admin',username:'admin',name:''});
    }
    const rows=await sb(`resellers?username=eq.${encodeURIComponent(username)}&select=id,name,username,password_hash,active,expires_at&limit=1`);
    const r=rows[0];
    if(!r||!r.active||new Date(r.expires_at).getTime()<=Date.now()||!verifyPassword(password,r.password_hash))
      return json(res,401,{error:'invalid_credentials'});
    return json(res,200,{token:sign({role:'reseller',reseller_id:r.id,username:r.username,name:r.name,iat:Date.now(),exp:Date.now()+8*60*60*1000}),role:'reseller',username:r.username,name:r.name});
  }catch(e){return json(res,500,{error:'server_error',message:String(e.message||e)})}
};
