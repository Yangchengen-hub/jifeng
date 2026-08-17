(function(){
var API=window.JF_API||'';
var $=function(s,p){return(p||document).querySelector(s)};
var $$=function(s,p){return Array.prototype.slice.call((p||document).querySelectorAll(s))};
function toast(msg,type){var t=$('#toast');t.textContent=msg;t.className='toast show'+(type?' '+type:'');setTimeout(function(){t.className='toast'},3000)}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function api(path,opts){opts=opts||{};opts.headers=opts.headers||{};opts.headers['Content-Type']='application/json';var token=sessionStorage.getItem('jf_token');if(token)opts.headers['Authorization']='Bearer '+token;return fetch(API+path,opts).then(function(r){return r.json().catch(function(){return{ok:r.ok}})}).catch(function(){return{ok:false,error:'网络错误，请检查网络或加速器'}})}
function fmtTime(ts){var d=new Date(ts);return d.toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})}

/* ============ LOGIN ============ */
var step=1,captchaCode='';
function showStep(n){
  step=n;
  $$('.step-panel').forEach(function(p,i){p.classList.toggle('active',i===n-1)});
  $('#dot1').className='step-dot'+(n>=1?' active':'');
  $('#dot2').className='step-dot'+(n>=2?' active':'');
  $('#dot3').className='step-dot'+(n>=3?' active':'');
  $('#line1').classList.toggle('done',n>=2);
  $('#line2').classList.toggle('done',n>=3);
}
function genCaptcha(){
  var chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';captchaCode='';
  for(var i=0;i<4;i++)captchaCode+=chars[Math.floor(Math.random()*chars.length)];
  var c=$('#captchaCanvas'),ctx=c.getContext('2d');
  ctx.fillStyle='#1c1c1e';ctx.fillRect(0,0,140,48);
  for(var i=0;i<6;i++){ctx.strokeStyle='rgba(255,105,0,'+(0.15+Math.random()*0.25)+')';ctx.beginPath();ctx.moveTo(Math.random()*140,Math.random()*48);ctx.lineTo(Math.random()*140,Math.random()*48);ctx.stroke()}
  for(var i=0;i<captchaCode.length;i++){
    ctx.save();ctx.font='bold 26px monospace';ctx.fillStyle='#ff6900';
    ctx.translate(22+i*28,33);ctx.rotate((Math.random()-0.5)*0.4);
    ctx.fillText(captchaCode[i],0,0);ctx.restore();
  }
}
function msg(t,c){var m=$('#loginMsg');m.textContent=t;m.className='login-msg'+(c?' '+c:'')}

$('#btnStep1').onclick=function(){
  var u=$('#loginUser').value.trim(),p=$('#loginPass').value;
  if(!u||!p)return msg('请输入账号和密码','err');
  msg('正在验证...','');
  api('/api/auth/login',{method:'POST',body:JSON.stringify({username:u,password:p})}).then(function(d){
    if(d.ok){showStep(2);genCaptcha();msg('')}
    else msg(d.error||'账号或密码错误','err');
  });
};
$('#captchaBox').onclick=genCaptcha;
$('#btnStep2').onclick=function(){
  var v=$('#captchaInput').value.trim().toUpperCase();
  if(!v)return msg('请输入验证码','err');
  if(v!==captchaCode)return msg('验证码错误','err'),genCaptcha();
  api('/api/auth/captcha',{method:'POST',body:JSON.stringify({captcha:v})}).then(function(d){
    if(d.ok){showStep(3);msg('')}
    else msg(d.error||'验证失败','err');
  });
};
$('#btnBack2').onclick=function(){showStep(1)};
$('#btnBack3').onclick=function(){showStep(2)};
var codeTimer=null;
$('#btnSendCode').onclick=function(){
  var btn=this;if(btn.disabled)return;btn.disabled=true;var s=60;
  btn.textContent=s+'s';codeTimer=setInterval(function(){s--;btn.textContent=s+'s';if(s<=0){clearInterval(codeTimer);btn.disabled=false;btn.textContent='发送验证码'}},1000);
  msg('正在发送验证码...','');
  api('/api/auth/sendcode',{method:'POST'}).then(function(d){
    if(d.ok)msg('验证码已发送至邮箱','ok');
    else{msg(d.error||'发送失败','err');clearInterval(codeTimer);btn.disabled=false;btn.textContent='发送验证码'}
  });
};
$('#btnStep3').onclick=function(){
  var c=$('#emailCode').value.trim();
  if(c.length!==6)return msg('请输入6位验证码','err');
  msg('正在登录...','');
  api('/api/auth/verify',{method:'POST',body:JSON.stringify({code:c})}).then(function(d){
    if(d.ok&&d.token){sessionStorage.setItem('jf_token',d.token);enterDashboard()}
    else msg(d.error||'验证码错误','err');
  });
};

function enterDashboard(){
  $('#loginWrap').style.display='none';
  $('#dashboard').style.display='block';
  loadOverview();loadVisitors();loadSecurity();loadAppeals();loadAnnouncements();loadPermBans();
  startRealtime();
}
$('#btnLogout').onclick=function(){sessionStorage.removeItem('jf_token');location.reload()};

/* ============ NAV ============ */
var currentPanel='overview';
function switchPanel(name){
  currentPanel=name;
  $$('.panel').forEach(function(p){p.classList.remove('active')});
  var target=$('#panel-'+name);
  if(target){target.classList.add('active');
    var title=target.dataset.title||'';
    $('#panelTitle').textContent=title;
  }
  $$('.tab-item').forEach(function(t){t.classList.toggle('active',t.dataset.panel===name)});
  closeMore();
  if(name==='overview')loadOverview();
  if(name==='visitors')loadVisitors();
  if(name==='security')loadSecurity();
  if(name==='appeals')loadAppeals();
  if(name==='announce')loadAnnouncements();
  if(name==='permanent')loadPermBans();
}
$$('.tab-item').forEach(function(item){
  item.onclick=function(){
    if(item.dataset.panel==='more'){openMore();return}
    switchPanel(item.dataset.panel);
  };
});
$$('.more-item').forEach(function(item){
  item.onclick=function(){switchPanel(item.dataset.panel)};
});
function openMore(){$('#moreSheet').classList.add('show');$('#moreOverlay').classList.add('show')}
function closeMore(){$('#moreSheet').classList.remove('show');$('#moreOverlay').classList.remove('show')}
$('#moreOverlay').onclick=closeMore;

/* ============ CHARTS ============ */
function setupCanvas(c){
  var dpr=window.devicePixelRatio||2;
  var w=c.offsetWidth,h=parseInt(c.getAttribute('height'))||180;
  c.width=w*dpr;c.height=h*dpr;
  var ctx=c.getContext('2d');ctx.scale(dpr,dpr);
  return{ctx:ctx,W:w,H:h};
}
function drawLine(canvasId,labels,datasets){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,pad=36;
  ctx.clearRect(0,0,W,H);
  var max=0;datasets.forEach(function(ds){ds.data.forEach(function(v){if(v>max)max=v})});max=Math.max(max,1);
  ctx.strokeStyle='rgba(255,255,255,0.06)';ctx.lineWidth=1;
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  ctx.fillStyle='#636366';ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  ctx.textAlign='center';
  var st=(W-pad*2)/(labels.length-1||1);
  labels.forEach(function(l,i){if(i%Math.ceil(labels.length/8)===0)ctx.fillText(l,pad+i*st,H-12)});
  datasets.forEach(function(ds){
    ctx.strokeStyle=ds.color;ctx.lineWidth=2.5;ctx.beginPath();
    ds.data.forEach(function(v,i){var x=pad+i*st,y=pad+(H-pad*2)*(1-v/max);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
    ctx.stroke();
    ctx.lineTo(pad+(ds.data.length-1)*st,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();
    var g=ctx.createLinearGradient(0,pad,0,H-pad);g.addColorStop(0,ds.color+'30');g.addColorStop(1,ds.color+'00');
    ctx.fillStyle=g;ctx.fill();
    ds.data.forEach(function(v,i){var x=pad+i*st,y=pad+(H-pad*2)*(1-v/max);ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fillStyle=ds.color;ctx.fill()});
  });
}
function drawBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,pad=40;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));
  var bw=(W-pad*2)/data.length*0.6,gap=(W-pad*2)/data.length*0.4;
  ctx.strokeStyle='rgba(255,255,255,0.06)';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  ctx.fillStyle='#636366';ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  data.forEach(function(v,i){
    var x=pad+i*(bw+gap)+gap/2,bh=(H-pad*2)*(v/max),y=H-pad-bh;
    var g=ctx.createLinearGradient(0,y,0,H-pad);g.addColorStop(0,color);g.addColorStop(1,color+'60');
    ctx.fillStyle=g;
    if(ctx.roundRect){ctx.beginPath();ctx.roundRect(x,y,bw,bh,4);ctx.fill()}else{ctx.fillRect(x,y,bw,bh)}
    ctx.fillStyle='#98989d';ctx.textAlign='center';ctx.font='9px sans-serif';
    ctx.fillText(labels[i].substring(0,6),x+bw/2,H-12);
  });
}
function drawDoughnut(canvasId,labels,data,colors){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,cx=W*0.35,cy=H/2,r=Math.min(cx,cy)-10,ir=r*0.6;
  ctx.clearRect(0,0,W,H);
  var total=data.reduce(function(a,b){return a+b},0)||1;var start=-Math.PI/2;
  data.forEach(function(v,i){
    var angle=v/total*Math.PI*2;
    ctx.beginPath();ctx.arc(cx,cy,r,start,start+angle);ctx.arc(cx,cy,ir,start+angle,start,true);ctx.closePath();
    ctx.fillStyle=colors[i%colors.length];ctx.fill();start+=angle;
  });
  ctx.font='10px sans-serif';ctx.textAlign='left';
  labels.forEach(function(l,i){
    var y=20+i*22;ctx.fillStyle=colors[i%colors.length];ctx.fillRect(W*0.6,y-8,10,10);
    ctx.fillStyle='#98989d';ctx.fillText(l+' ('+data[i]+')',W*0.6+16,y+2);
  });
}
function drawHBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));var rowH=H/data.length;
  data.forEach(function(v,i){
    var y=i*rowH+8,bw=(W-110)*(v/max),bh=rowH-16;
    ctx.fillStyle='#636366';ctx.font='10px sans-serif';ctx.textAlign='right';ctx.fillText(labels[i].substring(0,8),100,y+bh/2+3);
    var g=ctx.createLinearGradient(110,0,110+bw,0);g.addColorStop(0,color+'80');g.addColorStop(1,color);
    ctx.fillStyle=g;
    if(ctx.roundRect){ctx.beginPath();ctx.roundRect(110,y,bw,bh,4);ctx.fill()}else{ctx.fillRect(110,y,bw,bh)}
    ctx.fillStyle='#98989d';ctx.textAlign='left';ctx.fillText(v,118+bw,y+bh/2+3);
  });
}

/* ============ DATA LOADING ============ */
function loadOverview(){
  api('/api/stats/overview').then(function(d){
    if(!d.ok)return;
    $('#statVisitors').textContent=d.data.visitors||0;
    $('#statAttacks').textContent=d.data.attacks||0;
    $('#statBans').textContent=d.data.bans||0;
    $('#trend-visitors').textContent='+'+(d.data.visitorTrend||0)+'%';
    $('#trend-attacks').textContent='+'+(d.data.attacks||0);
    drawLine('chartTraffic',d.data.trafficLabels||[],d.data.trafficData||[{data:[],color:'#ff6900'}]);
  });
}
function loadVisitors(){
  api('/api/stats/visitors').then(function(d){
    if(!d.ok)return;
    $('#vTotal').textContent=d.data.total||0;
    $('#vMobile').textContent=d.data.mobile||0;
    $('#vDesktop').textContent=d.data.desktop||0;
    $('#vNew').textContent=d.data.todayNew||0;
    drawDoughnut('chartDevice',d.data.deviceLabels||['移动端','桌面端'],[d.data.mobile||0,d.data.desktop||0],['#0a84ff','#bf5af2']);
    drawHBar('chartPages',d.data.pageLabels||[],d.data.pageData||[],'#ff6900');
    var html='';
    (d.data.recent||[]).forEach(function(v){
      html+='<div class="visitor-item"><div class="vi-avatar">'+(v.browser?v.browser.charAt(0):'?')+'</div><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(v.ip)+'</span></div><div class="vi-meta">'+esc(v.browser||'未知')+' · '+esc(v.page||'/')+'</div></div><div class="vi-time">'+(v.timeStr||'')+'</div><button class="vi-action ban" data-ip="'+esc(v.ip)+'" data-fid="'+esc(v.fid||'')+'">封禁</button></div>';
    });
    $('#visitorTable').innerHTML=html||'<div class="empty-state"><p>暂无数据</p></div>';
    $$('#visitorTable .vi-action.ban').forEach(function(b){b.onclick=function(){banIP(b.dataset.ip,b.dataset.fid,'管理员手动封禁')}});
  });
}
function loadSecurity(){
  api('/api/stats/security').then(function(d){
    if(!d.ok)return;
    $('#secTotal').textContent=d.data.total||0;
    $('#secToday').textContent=d.data.today||0;
    $('#secBanned').textContent=d.data.banned||0;
    $('#secRate').textContent=(d.data.rate||0)+'%';
    var badge=$('#secBadge');badge.textContent=d.data.today||0;badge.style.display=d.data.today>0?'flex':'none';
    drawBar('chartAttackType',d.data.typeLabels||[],d.data.typeData||[],'#ff453a');
    drawLine('chartAttackTrend',d.data.trendLabels||[],[{data:d.data.trendData||[],color:'#ff453a'}]);
    var html='';
    (d.data.bans||[]).forEach(function(b){
      if(b.type==='permanent')return;
      html+='<div class="ban-item"><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(b.ip)+'</span><span class="ban-type temporary">临时</span></div><div class="ban-reason">'+esc(b.reason)+'</div><div class="vi-meta">'+fmtTime(b.time)+(b.fid?' · '+esc(b.fid.substring(0,12)):'')+'</div></div>'+(b.active?'<button class="vi-action unban" data-id="'+esc(b.id)+'">解封</button>':'<span class="vi-meta">已解除</span>')+'</div>';
    });
    $('#banTable').innerHTML=html||'<div class="empty-state"><p>暂无临时封禁</p></div>';
    $$('#banTable .vi-action.unban').forEach(function(b){b.onclick=function(){unban(b.dataset.id)}});
  });
}
function loadPermBans(){
  api('/api/stats/security').then(function(d){
    if(!d.ok)return;
    var permBans=(d.data.bans||[]).filter(function(b){return b.type==='permanent'});
    var html='';
    permBans.forEach(function(b){
      html+='<div class="ban-item perm"><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(b.ip)+'</span><span class="ban-type permanent">永久</span></div><div class="ban-reason">'+esc(b.reason)+'</div><div class="vi-meta">'+fmtTime(b.time)+(b.fid?' · '+esc(b.fid.substring(0,12)):'')+'</div></div></div>';
    });
    var el=$('#permBanList');
    if(el)el.innerHTML=html||'<div class="empty-state"><p>暂无永久封禁</p></div>';
  });
}
function loadAppeals(){
  api('/api/appeals').then(function(d){
    if(!d.ok)return;
    var list=d.data||[];
    var badge=$('#appealBadge');badge.textContent=list.length;badge.style.display=list.length>0?'flex':'none';
    var html='';
    list.forEach(function(a){
      html+='<div class="appeal-card"><div class="appeal-head"><div class="appeal-ip">'+esc(a.ip)+'</div><div class="appeal-time">'+fmtTime(a.time)+'</div></div><div class="appeal-reason">封禁原因: '+esc(a.banReason)+'</div><div class="appeal-content">'+esc(a.content)+'</div><div class="appeal-actions"><button data-action="approve" data-id="'+esc(a.id)+'" class="btn-approve">通过解封</button><button data-action="reject" data-id="'+esc(a.id)+'" class="btn-reject">驳回</button><button data-action="permanent" data-id="'+esc(a.id)+'" class="btn-permanent">永封</button></div></div>';
    });
    $('#appealList').innerHTML=html||'<div class="empty-state"><div class="empty-ico">📭</div><p>暂无待审核申诉</p></div>';
    $$('#appealList button').forEach(function(b){b.onclick=function(){handleAppeal(b.dataset.id,b.dataset.action)}});
  });
}
function loadAnnouncements(){
  api('/api/announcement/all').then(function(d){
    if(!d.ok)return;
    var html='';
    (d.data||[]).forEach(function(a){
      html+='<div class="ann-item"><div class="ann-item-title">'+esc(a.title)+'</div><div class="ann-item-content">'+esc(a.content)+'</div><div class="ann-item-time">'+fmtTime(a.time)+' <button class="vi-action ban" data-id="'+esc(a.id)+'" style="margin-left:8px">删除</button></div></div>';
    });
    $('#annTable').innerHTML=html||'<div class="empty-state"><p>暂无公告</p></div>';
    $$('#annTable .vi-action').forEach(function(b){b.onclick=function(){delAnn(b.dataset.id)}});
  });
}
function loadSettings(){
  api('/api/settings').then(function(d){
    if(!d.ok||!d.data)return;
    $$('.toggle').forEach(function(t){
      var key=t.dataset.setting;
      if(d.data[key]!==undefined)t.classList.toggle('on',!!d.data[key]);
    });
  });
}
function banIP(ip,fid,reason){
  api('/api/security/ban',{method:'POST',body:JSON.stringify({ip:ip,fid:fid,reason:reason})}).then(function(d){
    if(d.ok){toast('已封禁','ok');loadSecurity();loadVisitors()}else toast(d.error||'操作失败','err');
  });
}
function permBanIP(ip,fid,reason){
  api('/api/security/permanent',{method:'POST',body:JSON.stringify({ip:ip,fid:fid,reason:reason})}).then(function(d){
    if(d.ok){toast('已永久封禁','ok');loadSecurity();loadPermBans()}else toast(d.error||'操作失败','err');
  });
}
function unban(id){
  api('/api/security/unban',{method:'POST',body:JSON.stringify({id:id})}).then(function(d){
    if(d.ok){toast('已解封','ok');loadSecurity()}else toast(d.error||'操作失败','err');
  });
}
function handleAppeal(id,action){
  api('/api/appeals/handle',{method:'POST',body:JSON.stringify({id:id,action:action})}).then(function(d){
    if(d.ok){toast('操作成功','ok');loadAppeals();loadSecurity();loadPermBans()}else toast(d.error||'操作失败','err');
  });
}
function delAnn(id){
  api('/api/announcement/delete',{method:'POST',body:JSON.stringify({id:id})}).then(function(d){
    if(d.ok){toast('已删除','ok');loadAnnouncements()}else toast(d.error||'失败','err');
  });
}
$('#btnPublishAnn').onclick=function(){
  var t=$('#annTitleInput').value.trim(),c=$('#annContentInput').value.trim();
  if(!t||!c)return toast('请填写标题和内容','err');
  api('/api/announcement/publish',{method:'POST',body:JSON.stringify({title:t,content:c})}).then(function(d){
    if(d.ok){toast('发布成功','ok');$('#annTitleInput').value='';$('#annContentInput').value='';loadAnnouncements()}else toast(d.error||'失败','err');
  });
};

/* ============ PERMANENT BAN ============ */
$('#btnPermBan').onclick=function(){
  var ip=$('#permIp').value.trim(),reason=$('#permReason').value.trim()||'管理员永久封禁';
  if(!ip)return toast('请输入IP','err');
  permBanIP(ip,$('#permFid').value.trim(),reason);
  $('#permIp').value='';$('#permFid').value='';$('#permReason').value='';
};

/* ============ REPORTS ============ */
function genReport(type){
  toast('正在生成报告...');
  api('/api/reports/generate',{method:'POST',body:JSON.stringify({type:type})}).then(function(d){
    if(d.ok&&d.data){$('#reportPreview').textContent=d.data.content;toast('报告已生成','ok')}else toast(d.error||'生成失败','err');
  });
}
$('#btnReportDaily').onclick=function(){genReport('daily')};
$('#btnReportWeekly').onclick=function(){genReport('weekly')};
$('#btnReportAttack').onclick=function(){genReport('attack')};
$('#btnReportFull').onclick=function(){genReport('full')};

/* ============ SETTINGS ============ */
$$('.toggle').forEach(function(t){t.onclick=function(){t.classList.toggle('on');api('/api/settings',{method:'POST',body:JSON.stringify({key:t.dataset.setting,value:t.classList.contains('on')})})}});

/* ============ HEADER REFRESH ============ */
$('#btnRefreshOverview').onclick=function(){
  if(currentPanel==='overview')loadOverview();
  else if(currentPanel==='visitors')loadVisitors();
  else if(currentPanel==='security')loadSecurity();
  else if(currentPanel==='appeals')loadAppeals();
  else if(currentPanel==='announce')loadAnnouncements();
  else if(currentPanel==='permanent')loadPermBans();
  toast('已刷新');
};

/* ============ REALTIME ============ */
var logCount=0;
function startRealtime(){
  setInterval(function(){
    api('/api/logs/realtime').then(function(d){
      if(!d.ok||!d.data)return;
      var stream=$('#logStream');
      d.data.forEach(function(l){
        logCount++;
        var div=document.createElement('div');div.className='log-item';
        div.innerHTML='<span class="log-tag '+l.type+'">'+l.typeLabel+'</span><div class="log-msg">'+esc(l.message)+'</div><span class="log-time">'+l.timeStr+'</span>';
        stream.insertBefore(div,stream.firstChild);
        if(stream.children.length>30)stream.removeChild(stream.lastChild);
      });
      $('#logCount').textContent=logCount+' 条';
    });
  },4000);
  setInterval(loadOverview,30000);
}

/* ============ MANUAL BAN MODAL ============ */
$('#btnBanManual').onclick=function(){
  $('#modalContent').innerHTML='<h3>手动封禁</h3><input type="text" id="banIp" placeholder="IP地址，如 1.2.3.4"><input type="text" id="banFid" placeholder="设备指纹(可选)"><input type="text" id="banReason" placeholder="封禁原因"><div class="modal-actions"><button class="btn-cancel" onclick="document.getElementById(\'modal\').classList.remove(\'show\')">取消</button><button class="btn-confirm" id="btnDoBan">确认封禁</button></div>';
  $('#modal').classList.add('show');
  $('#btnDoBan').onclick=function(){
    var ip=$('#banIp').value.trim(),reason=$('#banReason').value.trim()||'手动封禁';
    if(!ip)return toast('请输入IP','err');
    banIP(ip,$('#banFid').value.trim(),reason);
    $('#modal').classList.remove('show');
  };
};
$('#modal').onclick=function(e){if(e.target===this)this.classList.remove('show')};

/* ============ RIPPLE ============ */
document.addEventListener('click',function(e){
  var btn=e.target.closest('.ripple');if(!btn)return;
  var r=document.createElement('span');r.className='ripple-effect';
  var rect=btn.getBoundingClientRect();
  var size=Math.max(rect.width,rect.height);
  r.style.width=r.style.height=size+'px';
  r.style.left=(e.clientX-rect.left-size/2)+'px';
  r.style.top=(e.clientY-rect.top-size/2)+'px';
  btn.appendChild(r);setTimeout(function(){r.remove()},600);
});

/* ============ INIT ============ */
(function(){
  var token=sessionStorage.getItem('jf_token');
  if(token){
    api('/api/auth/check').then(function(d){if(d.ok)enterDashboard();else showStep(1)});
  }else{showStep(1)}
  window.addEventListener('resize',function(){
    if(currentPanel==='overview')loadOverview();
    if(currentPanel==='visitors')loadVisitors();
    if(currentPanel==='security')loadSecurity();
  });
})();
})();
