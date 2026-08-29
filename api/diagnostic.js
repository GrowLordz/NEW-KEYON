const {sb,json,requireAdmin}=require('./_supabase');

module.exports=async(req,res)=>{
  const s=requireAdmin(req,res); if(!s)return;
  const tests=[
    ['settings',"settings?select=key,value&limit=1"],
    ['keys',"keys?select=key&limit=1"],
    ['resellers',"resellers?select=id,name,username,balance&limit=1"],
    ['transactions',"transactions?select=id,account,type,amount,created_at&limit=1"]
  ];
  const out={ok:true,tests:{}};
  for(const [name,path] of tests){
    try{await sb(path);out.tests[name]={ok:true};}
    catch(e){out.ok=false;out.tests[name]={ok:false,error:String(e.message||e)};}
  }
  return json(res,200,out);
};
