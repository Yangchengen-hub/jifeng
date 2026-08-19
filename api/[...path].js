const {json,handler}=require('../lib/api');
const db=require('../lib/db');
const sec=require('../lib/security');
const auth=require('../lib/auth');
const email=require('../lib/email');
const enc=require('../lib/crypto');

module.exports=async function(req,res){
  const segs=req.query.path||[];
  const route=segs.join('/');
  const method=req.method;

  // ── auth: step1 validate credentials only ──
  if(route==='auth/login'&&method==='POST')return handler(req,res,async function(req,res){
    const{username,password}=req.body;
    const AU=process.env.ADMIN_USER||'NUOYAN';
    const AP=process.env.ADMIN_PASS||'JIFENG1457';
    if(username!==AU||password!==AP){
      await sec.logSecurityEvent('auth','登录失败 - 用户: '+username,{ip:req.clientIp});
      const fc=await db.incr('loginfail:'+req.clientIp);
      await db.expire('loginfail:'+req.clientIp,1800);
      if(fc>=5)await sec.ban(req.clientIp,'','暴力破解登录','temporary');
      return json(res,{ok:false,error:'账号或密码错误'});
    }
    await db.del('loginfail:'+req.clientIp);
    return json(res,{ok:true});
  },{skipAttackCheck:true,rateMax:10,rateWindow:60000});

  // ── auth: step2 captcha (server-side) ──
  if(route==='auth/captcha'&&method==='GET')return handler(req,res,async function(req,res){
    const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code='';
    for(let i=0;i<4;i++)code+=chars[Math.floor(Math.random()*chars.length)];
    const token=auth.sign({captcha:code,exp:Date.now()+300000});
    return json(res,{ok:true,token});
  },{skipAttackCheck:true,skipRateLimit:true});

  if(route==='auth/captcha'&&method==='POST')return handler(req,res,async function(req,res){
    return json(res,{ok:true});
  },{skipAttackCheck:true,rateMax:30,rateWindow:60000});

  // ── auth: step3 send email code ──
  if(route==='auth/sendcode'&&method==='POST')return handler(req,res,async function(req,res){
    const code=Math.floor(100000+Math.random()*900000).toString();
    await db.set('emailcode:'+req.clientIp,{code,expires:Date.now()+600000},600);
    const result=await email.verificationCode(code);
    if(!result.ok)return json(res,{ok:false,error:'邮件发送失败，请稍后重试'});
    return json(res,{ok:true});
  },{skipAttackCheck:true,rateMax:5,rateWindow:300000});

  // ── auth: step4 verify code ──
  if(route==='auth/verify'&&method==='POST')return handler(req,res,async function(req,res){
    const{code}=req.body;
    const stored=await db.get('emailcode:'+req.clientIp);
    if(!stored||Date.now()>stored.expires)return json(res,{ok:false,error:'验证码已过期，请重新获取'});
    if(stored.code!==code)return json(res,{ok:false,error:'验证码错误'});
    await db.del('emailcode:'+req.clientIp);
    const token=auth.sign({user:process.env.ADMIN_USER||'NUOYAN',role:'admin',exp:Date.now()+86400000});
    await sec.logSecurityEvent('auth','管理员登录成功',{ip:req.clientIp});
    return json(res,{ok:true,token});
  },{skipAttackCheck:true,rateMax:10,rateWindow:60000});

  if(route==='auth/check')return handler(req,res,async function(req,res){
    const payload=auth.checkAdmin(req);
    if(!payload)return json(res,{ok:false},401);
    return json(res,{ok:true,user:payload.user});
  },{skipAttackCheck:true,skipRateLimit:true});

  // ── visitor tracking ──
  if(route==='visitor'&&method==='POST')return handler(req,res,async function(req,res){
    const{fp,page,ref}=req.body;
    if(!fp||!fp.fid)return json(res,{ok:false},400);
    await sec.logVisitor(req.clientIp,fp,page,ref);
    return json(res,{ok:true});
  },{skipAttackCheck:true,rateMax:30,rateWindow:60000});

  if(route==='visitor/security-event'&&method==='POST')return handler(req,res,async function(req,res){
    const{type,fp}=req.body;
    await sec.addWarning(req.clientIp,(fp&&fp.fid)||'','前端检测: '+(type||'unknown'));
    return json(res,{ok:true});
  },{skipAttackCheck:true,rateMax:20,rateWindow:60000});

  // ── announcement ──
  if(route==='announcement'&&method==='GET')return handler(req,res,async function(req,res){
    const list=await db.lrange('announcements:list',0,0);
    if(list&&list[0]){
      const a=list[0];
      return json(res,{ok:true,data:{title:a.title,content:a.content,time:a.time,time_str:new Date(a.time).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})}});
    }
    return json(res,{ok:true,data:{title:'欢迎访问极风工作室',content:'官网已全面升级，安全体系全面加强。',time:Date.now(),time_str:'刚刚'}});
  },{skipAttackCheck:true,skipRateLimit:true});

  if(route==='announcement/all')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const list=await db.lrange('announcements:list',0,49);
    return json(res,{ok:true,data:list});
  },{skipAttackCheck:true});

  if(route==='announcement/publish'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{title,content}=req.body;
    if(!title||!content)return json(res,{ok:false,error:'标题和内容不能为空'});
    const entry={id:'ann_'+Date.now().toString(36),title,content,time:Date.now()};
    await db.lpush('announcements:list',entry);
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  if(route==='announcement/delete'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{id}=req.body;
    const list=await db.lrange('announcements:list',0,-1);
    const filtered=list.filter(a=>a.id!==id);
    await db.del('announcements:list');
    for(let i=filtered.length-1;i>=0;i--)await db.lpush('announcements:list',filtered[i]);
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  // ── stats ──
  if(route==='stats/overview')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const today=new Date().toISOString().slice(0,10);
    const yesterday=new Date(Date.now()-86400000).toISOString().slice(0,10);
    const visitors=await db.get('stats:visitors:'+today)||0;
    const yv=await db.get('stats:visitors:'+yesterday)||0;
    const attacks=await db.get('stats:attacks:'+today)||0;
    const bans=await db.lrange('bans:list',0,-1);
    const activeBans=bans.filter(b=>b.active);
    const permBans=activeBans.filter(b=>b.type==='permanent').length;
    const trend=yv>0?Math.round((visitors-yv)/yv*100):(visitors>0?100:0);
    const hours=[],traffic=[];const now=new Date();
    for(let i=23;i>=0;i--){
      const d=new Date(now.getTime()-i*3600000);
      const key=d.toISOString().slice(0,13);
      hours.push(d.getHours()+':00');
      traffic.push(await db.get('stats:visitors:hour:'+key)||0);
    }
    return json(res,{ok:true,data:{visitors,attacks,bans:activeBans.length,permBans,visitorTrend:trend,trafficLabels:hours,trafficData:[{data:traffic,color:'#ff6900'}]}});
  },{skipAttackCheck:true});

  if(route==='stats/visitors')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const today=new Date().toISOString().slice(0,10);
    const total=await db.get('stats:visitors:total')||0;
    const mobile=await db.get('stats:mobile:'+today)||0;
    const desktop=await db.get('stats:desktop:'+today)||0;
    const todayNew=await db.get('stats:visitors:'+today)||0;
    const recent=await db.lrange('visitors:recent',0,49);
    const pageKeys=await db.keys('stats:page:*');
    const pageStats=[];
    for(const k of pageKeys.slice(0,10)){
      const v=await db.get(k)||0;
      pageStats.push({page:k.replace('stats:page:',''),count:v});
    }
    pageStats.sort((a,b)=>b.count-a.count);
    return json(res,{ok:true,data:{total,mobile,desktop,todayNew,deviceLabels:['移动端','桌面端'],pageLabels:pageStats.map(p=>p.page),pageData:pageStats.map(p=>p.count),recent}});
  },{skipAttackCheck:true});

  if(route==='stats/security')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const today=new Date().toISOString().slice(0,10);
    const total=await db.get('stats:attacks:total')||0;
    const todayCount=await db.get('stats:attacks:'+today)||0;
    const bans=await db.lrange('bans:list',0,-1);
    const activeBans=bans.filter(b=>b.active);
    const events=await db.lrange('events:list',0,-1);
    const typeMap={};
    events.forEach(e=>{
      if(e.type==='attack'&&e.meta&&e.meta.attack)typeMap[e.meta.attack]=(typeMap[e.meta.attack]||0)+1;
      else if(e.type==='warning'&&e.meta&&e.meta.reason)typeMap[e.meta.reason]=(typeMap[e.meta.reason]||0)+1;
    });
    const typeLabels=Object.keys(typeMap);
    const typeData=Object.values(typeMap);
    const days=[],trend=[];
    for(let i=6;i>=0;i--){
      const d=new Date(Date.now()-i*86400000).toISOString().slice(0,10);
      days.push(d.slice(5));
      trend.push(await db.get('stats:attacks:'+d)||0);
    }
    const visitors=await db.get('stats:visitors:'+today)||1;
    const rate=Math.round(todayCount/(todayCount+visitors)*100)||0;
    return json(res,{ok:true,data:{total,today:todayCount,banned:activeBans.length,permBanned:activeBans.filter(b=>b.type==='permanent').length,rate,typeLabels:typeLabels.length?typeLabels:['暂无'],typeData:typeData.length?typeData:[0],trendLabels:days,trendData:trend,bans:bans.slice(0,50)}});
  },{skipAttackCheck:true});

  // ── logs ──
  if(route==='logs/realtime')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const since=parseInt(req.headers['x-last-time']||'0');
    const events=await db.lrange('events:list',0,20);
    const typeLabels={attack:'攻击拦截',ban:'封禁操作',unban:'解封操作',blocked:'拦截访问',auth:'认证事件',ratelimit:'频率限制',warning:'安全警告',appeal:'申诉提交'};
    const newEvents=events.filter(e=>e.time>since).map(e=>({
      type:e.type==='attack'?'attack':(e.type==='ban'||e.type==='blocked'?'ban':(e.type==='warning'?'attack':(e.type==='appeal'?'appeal':(e.type==='auth'?'auth':'visit')))),
      typeLabel:typeLabels[e.type]||e.type,message:e.message,timeStr:e.timeStr,time:e.time
    }));
    return json(res,{ok:true,data:newEvents});
  },{skipAttackCheck:true});

  // ── security: ban/unban ──
  if(route==='security/ban'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{ip,fid,reason,type}=req.body;
    if(!ip)return json(res,{ok:false,error:'IP不能为空'});
    await sec.ban(ip,fid||'',reason||'管理员手动封禁',type||'temporary');
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  if(route==='security/unban'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{id}=req.body;
    await sec.unban(id);
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  if(route==='security/permanent'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{ip,fid,reason}=req.body;
    if(!ip)return json(res,{ok:false,error:'IP不能为空'});
    await sec.ban(ip,fid||'',reason||'管理员永久封禁','permanent');
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  if(route==='security/warnings'&&method==='GET')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const keys=await db.keys('warnings:*');
    const warnings=[];
    for(const k of keys.slice(0,50)){
      const w=await db.get(k);
      if(w)warnings.push({ip:k.replace('warnings:',''),...w});
    }
    warnings.sort((a,b)=>b.history[b.history.length-1].time-a.history[a.history.length-1].time);
    return json(res,{ok:true,data:warnings});
  },{skipAttackCheck:true});

  // ── appeals ──
  if(route==='appeals')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const list=await db.lrange('appeals:list',0,-1);
    return json(res,{ok:true,data:list.filter(a=>a.status==='pending')});
  },{skipAttackCheck:true});

  if(route==='appeals/submit'&&method==='POST')return handler(req,res,async function(req,res){
    const{content,fid}=req.body;
    if(!content||content.length<20)return json(res,{ok:false,error:'申诉内容至少20字'});
    const existing=await db.lrange('appeals:list',0,-1);
    if(existing.some(a=>a.ip===req.clientIp&&a.status==='pending'))return json(res,{ok:false,error:'您已有待审核的申诉，请耐心等待'});
    const bans=await db.lrange('bans:list',0,-1);
    const br=bans.find(b=>b.ip===req.clientIp&&b.active);
    if(br&&br.type==='permanent')return json(res,{ok:false,error:'永久封禁不可申诉'});
    const entry={id:'appeal_'+Date.now().toString(36),ip:req.clientIp,fid:fid||'',banReason:br?br.reason:'未知',content,time:Date.now(),status:'pending'};
    await db.lpush('appeals:list',entry);
    await sec.logSecurityEvent('appeal','收到来自 '+enc.maskIP(req.clientIp)+' 的申诉',{ip:req.clientIp});
    await email.appealNotice({ip:enc.maskIP(req.clientIp),fid:fid||'',banReason:entry.banReason,content,time:entry.time});
    return json(res,{ok:true,message:'申诉已提交，请等待管理员审核'});
  },{skipAttackCheck:true,rateMax:3,rateWindow:3600000});

  if(route==='appeals/handle'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{id,action}=req.body;
    const list=await db.lrange('appeals:list',0,-1);
    const appeal=list.find(a=>a.id===id);
    if(!appeal)return json(res,{ok:false,error:'申诉不存在'});
    if(action==='approve'){
      appeal.status='approved';appeal.handledAt=Date.now();
      await sec.unbanByIp(appeal.ip);
      await db.set('commitment_pending:'+appeal.ip,true,86400);
    }
    else if(action==='reject'){appeal.status='rejected';appeal.handledAt=Date.now()}
    else if(action==='permanent'){
      appeal.status='permanent';appeal.handledAt=Date.now();
      await sec.ban(appeal.ip,appeal.fid,'申诉后管理员永久封禁','permanent');
    }
    const updated=list.map(a=>a.id===id?appeal:a);
    await db.del('appeals:list');
    for(let i=updated.length-1;i>=0;i--)await db.lpush('appeals:list',updated[i]);
    return json(res,{ok:true});
  },{skipAttackCheck:true});

  // ── commitment letter ──
  if(route==='commitment/check'&&method==='GET')return handler(req,res,async function(req,res){
    const pending=await db.get('commitment_pending:'+req.clientIp);
    return json(res,{ok:true,required:!!pending});
  },{skipAttackCheck:true,skipRateLimit:true});

  if(route==='commitment/submit'&&method==='POST')return handler(req,res,async function(req,res){
    const{content,fid,name}=req.body;
    const pending=await db.get('commitment_pending:'+req.clientIp);
    if(!pending)return json(res,{ok:false,error:'无需提交承诺书'});
    if(!content||content.length<30)return json(res,{ok:false,error:'承诺书内容不完整'});
    const entry={
      id:'commit_'+Date.now().toString(36),
      ip:req.clientIp,fid:fid||'',name:name||'',
      content,time:Date.now()
    };
    await db.lpush('commitments:list',entry);
    await db.del('commitment_pending:'+req.clientIp);
    await db.set('repeat:'+req.clientIp,true);
    await sec.resetWarnings(req.clientIp);
    await email.commitmentNotice({ip:enc.maskIP(req.clientIp),fid:fid||'',content});
    await sec.logSecurityEvent('appeal','IP '+enc.maskIP(req.clientIp)+' 已签署承诺书',{ip:req.clientIp});
    return json(res,{ok:true,message:'承诺书已签署，您的访问已恢复'});
  },{skipAttackCheck:true,rateMax:3,rateWindow:3600000});

  // ── reports ──
  if(route==='reports/generate'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const{type}=req.body;
    const now=new Date();
    const today=now.toISOString().slice(0,10);
    let content='';
    const visitors=await db.get('stats:visitors:'+today)||0;
    const totalVisitors=await db.get('stats:visitors:total')||0;
    const attacks=await db.get('stats:attacks:'+today)||0;
    const totalAttacks=await db.get('stats:attacks:total')||0;
    const bans=await db.lrange('bans:list',0,-1);
    const activeBans=bans.filter(b=>b.active);
    const events=await db.lrange('events:list',0,49);
    const rv=await db.lrange('visitors:recent',0,9);
    if(type==='daily'||type==='full'){
      content+='═══════════════════════════════════\n  极风工作室 · 每日运维报告\n  报告时间: '+now.toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})+'\n═══════════════════════════════════\n\n';
      content+='【访问数据】\n  今日访问量: '+visitors+'\n  累计访问量: '+totalVisitors+'\n  移动端: '+(await db.get('stats:mobile:'+today)||0)+'\n  桌面端: '+(await db.get('stats:desktop:'+today)||0)+'\n\n';
      content+='【安全数据】\n  今日攻击拦截: '+attacks+'\n  累计攻击拦截: '+totalAttacks+'\n  当前封禁数: '+activeBans.length+'\n  永久封禁: '+activeBans.filter(b=>b.type==='permanent').length+'\n  拦截率: '+(visitors+attacks>0?Math.round(attacks/(visitors+attacks)*100):0)+'%\n\n';
      content+='【最近访客】\n';
      rv.forEach(v=>{content+='  '+v.timeStr+' '+v.ip+' '+v.browser+' '+v.page+'\n'});
      content+='\n';
    }
    if(type==='weekly'||type==='full'){
      content+='【近7日趋势】\n';
      for(let i=6;i>=0;i--){
        const d=new Date(Date.now()-i*86400000).toISOString().slice(0,10);
        content+='  '+d.slice(5)+'  访问:'+String(await db.get('stats:visitors:'+d)||0).padStart(5)+'  攻击:'+(await db.get('stats:attacks:'+d)||0)+'\n';
      }
      content+='\n';
    }
    if(type==='attack'||type==='full'){
      content+='【攻击事件记录】\n';
      const ae=events.filter(e=>e.type==='attack'||e.type==='ban'||e.type==='blocked'||e.type==='warning');
      if(!ae.length)content+='  暂无攻击事件\n';
      ae.slice(0,20).forEach(e=>{
        content+='  ['+e.timeStr+'] '+e.message+'\n';
        if(e.meta&&e.meta.ip)content+='    IP: '+e.meta.ip+(e.meta.fid?'  设备: '+e.meta.fid:'')+'\n';
      });
      content+='\n【封禁列表】\n';
      if(!activeBans.length)content+='  暂无封禁\n';
      activeBans.slice(0,20).forEach(b=>{
        content+='  '+new Date(b.time).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})+' '+b.ip+' ['+b.type+'] '+b.reason+'\n';
      });
      content+='\n【法律取证建议】\n  如遇中大型攻击事件，建议：\n  1. 保存服务器日志（含时间戳、IP、请求详情）\n  2. 截图攻击行为与后台记录\n  3. 依据《网络安全法》第二十一条、第二十七条\n  4. 依据《刑法》第二百八十五条、第二百八十六条\n  5. 向属地公安机关网安部门报案\n  6. 提交完整证据链：日志+截图+损失评估\n';
    }
    content+='\n═══════════════════════════════════\n  极风工作室安全系统自动生成\n═══════════════════════════════════';
    return json(res,{ok:true,data:{content}});
  },{skipAttackCheck:true});

  if(route==='reports/send-daily'&&method==='POST')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    const today=new Date().toISOString().slice(0,10);
    const visitors=await db.get('stats:visitors:'+today)||0;
    const attacks=await db.get('stats:attacks:'+today)||0;
    const bans=await db.lrange('bans:list',0,-1);
    const activeBans=bans.filter(b=>b.active).length;
    let content='今日访问: '+visitors+'\n今日攻击: '+attacks+'\n当前封禁: '+activeBans+'\n时间: '+new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});
    const result=await email.dailyReport(content);
    return json(res,{ok:result.ok,error:result.error});
  },{skipAttackCheck:true});

  // ── settings ──
  if(route==='settings')return handler(req,res,async function(req,res){
    if(!auth.checkAdmin(req))return json(res,{ok:false,error:'未授权'},401);
    if(method==='GET'){
      const settings=await db.get('settings')||{};
      return json(res,{ok:true,data:settings});
    }
    if(method==='POST'){
      const{key,value}=req.body;
      const settings=await db.get('settings')||{};
      settings[key]=value;
      await db.set('settings',settings);
      return json(res,{ok:true});
    }
  },{skipAttackCheck:true});

  // 404
  return handler(req,res,async function(req,res){
    return json(res,{ok:false,error:'Not found'},404);
  },{skipAttackCheck:true,skipRateLimit:true});
};
