
const {sb,json,requireAuth}=require('./_supabase');
module.exports=async(req,res)=>{
 try{
  const s=requireAuth(req,res);if(!s)return;
  if(req.method!=='GET')return json(res,405,{error:'method_not_allowed'});
  let path='transactions?select=id,reseller_id,account,type,detail,amount,created_at&order=created_at.desc&limit=500';
  if(s.role==='reseller')path+=`&reseller_id=eq.${encodeURIComponent(s.reseller_id)}`;
  return json(res,200,await sb(path));
 }catch(e){return json(res,500,{error:'server_error',message:String(e.message||e)})}
};
