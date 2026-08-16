(function(){
var API=window.JF_API||'';
var $=function(s,p){return(p||document).querySelector(s)};
var $$=function(s,p){return Array.prototype.slice.call((p||document).querySelectorAll(s))};
function toast(msg,type){var t=$('#toast');t.textContent=msg;t.className='toast show'+(type?' '+type:'');setTimeout(function(){t.className='toast'},3000)}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function api(path,opts){opts=opts||{};opts.headers=opts.headers||{};opts.headers['Content-Type']='application/json';var token=sessionStorage.getItem('jf_token');if(token)opts.headers['Authorization']='Bearer '+token;return fetch(API+path,opts).then(function(r){return r.json().catch(function(){return{ok:r.ok}})}).catch(function(){return{ok:false,error:'网络错误'}})}
function fmtTime(ts){var d=new Date(ts);return d.toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})}

/* ============ LOGIN ============ */
var step=1, captchaCode='';
function showStep(n){
  step=n;
  $('#step1').style.display=n===1?'block':'none';
  $('#step2').style.display=n===2?'block':'none';
  $('#step3').style.display=n===3?'block':'none';
  $('#dot1').className='step-dot'+(n>=1?(n>1?' done':' active'):'');
  $('#dot2').className='step-dot'+(n>=2?(n>2?' done':' active'):'');
  $('#dot3').className='step-dot'+(n>=3?' active':'');
}
function genCaptcha(){
  var chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';captchaCode='';
  for(var i=0;i<4;i++)captchaCode+=chars[Math.floor(Math.random()*chars.length)];
  var c=$('#captchaCanvas'),ctx=c.getContext('2d');
  ctx.fillStyle='#1c1c1e';ctx.fillRect(0,0,120,40);
  for(var i=0;i<5;i++){ctx.strokeStyle='rgba(255,105,0,'+(0.2+Math.random()*0.3)+')';ctx.beginPath();ctx.moveTo(Math.random()*120,Math.random()*40);ctx.lineTo(Math.random()*120,Math.random()*40);ctx.stroke()}
  for(var i=0;i<captchaCode.length;i++){
    ctx.save();ctx.font='bold 22px monospace';ctx.fillStyle='#ff6900';
    ctx.translate(20+i*25,28);ctx.rotate((Math.random()-0.5)*0.4);
    ctx.fillText(captchaCode[i],0,0);ctx.restore();
  }
}
function msg(t,c){var m=$('#loginMsg');m.textContent=t;m.className='login-msg'+(c?' '+c:'')}

$('#btnStep1').onclick=function(){
  var u=$('#loginUser').value.trim(),p=$('#loginPass').value;
  if(!u||!p)return msg('请输入账号和密码','err');
  api('/api/auth/login',{method:'POST',body:JSON.stringify({username:u,password:p})}).then(function(d){
    if(d.ok){showStep(2);genCaptcha();msg('')}
    else msg(d.error||'账号或密码错误','err');
  });
};
$('#captchaBox').onclick=genCaptcha;
$('#btnStep2').onclick=function(){
  var v=$('#captchaInput').value.trim().toUpperCase();
  if(v!==captchaCode)return msg('验证码错误','err'),genCaptcha();
  api('/api/auth/captcha',{method:'POST',body:JSON.stringify({captcha:v})}).then(function(d){
    if(d.ok){showStep(3);msg('验证码已发送至邮箱','ok')}
    else msg(d.error||'验证失败','err');
  });
};
$('#btnBack2').onclick=function(){showStep(1)};
$('#btnBack3').onclick=function(){showStep(2)};
var codeTimer=null;
$('#btnSendCode').onclick=function(){
  var btn=this;if(btn.disabled)return;btn.disabled=true;var s=60;
  btn.textContent=s+'s后重发';codeTimer=setInterval(function(){s--;btn.textContent=s+'s后重发';if(s<=0){clearInterval(codeTimer);btn.disabled=false;btn.textContent='发送验证码'}},1000);
  api('/api/auth/sendcode',{method:'POST'}).then(function(d){if(!d.ok)toast(d.error||'发送失败','err')});
};
$('#btnStep3').onclick=function(){
  var c=$('#emailCode').value.trim();
  if(c.length!==6)return msg('请输入6位验证码','err');
  api('/api/auth/verify',{method:'POST',body:JSON.stringify({code:c})}).then(function(d){
    if(d.ok&&d.token){sessionStorage.setItem('jf_token',d.token);enterDashboard()}
    else msg(d.error||'验证码错误','err');
  });
};

function enterDashboard(){
  $('#loginWrap').style.display='none';
  $('#dashboard').style.display='flex';
  loadOverview();loadVisitors();loadSecurity();loadAppeals();loadAnnouncements();
  startRealtime();
}

$('#btnLogout').onclick=function(){sessionStorage.removeItem('jf_token');location.reload()};

/* ============ NAV ============ */
$$('.side-item').forEach(function(item){
  item.onclick=function(){
    $$('.side-item').forEach(function(i){i.classList.remove('active')});
    item.classList.add('active');
    $$('.panel').forEach(function(p){p.classList.remove('active')});
    $('#panel-'+item.dataset.panel).classList.add('active');
  };
});

/* ============ CHARTS ============ */
function drawLine(canvasId,labels,datasets){
  var c=$(canvasId);if(!c)return;var ctx=c.getContext('2d');
  var w=c.width=c.offsetWidth*2,h=c.height*2;ctx.scale(2,2);
  var W=c.offsetWidth,H=c.height/2,pad=36;
  ctx.clearRect(0,0,W,H);
  var max=0;datasets.forEach(function(ds){ds.data.forEach(function(v){if(v>max)max=v})});max=Math.max(max,1);
  ctx.strokeStyle='rgba(255,255,255,0.06)';ctx.lineWidth=1;
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  ctx.fillStyle='#6e6e73';ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  ctx.textAlign='center';
  var step=(W-pad*2)/(labels.length-1||1);
  labels.forEach(function(l,i){if(i%Math.ceil(labels.length/8)===0)ctx.fillText(l,pad+i*step,H-12)});
  datasets.forEach(function(ds){
    ctx.strokeStyle=ds.color;ctx.lineWidth=2.5;ctx.beginPath();
    ds.data.forEach(function(v,i){var x=pad+i*step,y=pad+(H-pad*2)*(1-v/max);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
    ctx.stroke();
    ctx.lineTo(pad+(ds.data.length-1)*step,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();
    var g=ctx.createLinearGradient(0,pad,0,H-pad);g.addColorStop(0,ds.color+'30');g.addColorStop(1,ds.color+'00');
    ctx.fillStyle=g;ctx.fill();
    ds.data.forEach(function(v,i){var x=pad+i*step,y=pad+(H-pad*2)*(1-v/max);ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fillStyle=ds.color;ctx.fill()});
  });
}
function drawBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var ctx=c.getContext('2d');
  var w=c.width=c.offsetWidth*2,h=c.height*2;ctx.scale(2,2);
  var W=c.offsetWidth,H=c.height/2,pad=40;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));
  var bw=(W-pad*2)/data.length*0.6,gap=(W-pad*2)/data.length*0.4;
  ctx.strokeStyle='rgba(255,255,255,0.06)';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  ctx.fillStyle='#6e6e73';ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  data.forEach(function(v,i){
    var x=pad+i*(bw+gap)+gap/2,bh=(H-pad*2)*(v/max),y=H-pad-bh;
    var g=ctx.createLinearGradient(0,y,0,H-pad);g.addColorStop(0,color);g.addColorStop(1,color+'60');
    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(x,y,bw,bh,4);ctx.fill();
    ctx.fillStyle='#98989d';ctx.textAlign='center';ctx.font='9px sans-serif';
    ctx.fillText(labels[i].substring(0,6),x+bw/2,H-12);
  });
}
function drawDoughnut(canvasId,labels,data,colors){
  var c=$(canvasId);if(!c)return;var ctx=c.getContext('2d');
  var w=c.width=c.offsetWidth*2,h=c.height*2;ctx.scale(2,2);
  var W=c.offsetWidth,H=c.height/2,cx=W*0.35,cy=H/2,r=Math.min(cx,cy)-10,ir=r*0.6;
  ctx.clearRect(0,0,W,H);
  var total=data.reduce(function(a,b){return a+b},0)||1;var start=-Math.PI/2;
  data.forEach(function(v,i){
    var angle=v/total*Math.PI*2;
    ctx.beginPath();ctx.arc(cx,cy,r,start,start+angle);ctx.arc(cx,cy,ir,start+angle,start,true);ctx.closePath();
    ctx.fillStyle=colors[i%colors.length];ctx.fill();start+=angle;
  });
  ctx.fillStyle='#f5f5f7';ctx.font='bold 11px sans-serif';ctx.textAlign='left';
  labels.forEach(function(l,i){
    var y=20+i*22;ctx.fillStyle=colors[i%colors.length];ctx.fillRect(W*0.65,y-8,10,10);
    ctx.fillStyle='#98989d';ctx.font='10px sans-serif';ctx.fillText(l+' ('+data[i]+')',W*0.65+16,y+2);
  });
}
function drawHBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var ctx=c.getContext('2d');
  var w=c.width=c.offsetWidth*2,h=c.height*2;ctx.scale(2,2);
  var W=c.offsetWidth,H=c.height/2;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));var rowH=H/data.length;
  data.forEach(function(v,i){
    var y=i*rowH+8,bw=(W-120)*(v/max),bh=rowH-16;
    ctx.fillStyle='#6e6e73';ctx.font='10px sans-serif';ctx.textAlign='right';ctx.fillText(labels[i].substring(0,10),100,y+bh/2+3);
    var g=ctx.createLinearGradient(110,0,110+bw,0);g.addColorStop(0,color+'80');g.addColorStop(1,color);
    ctx.fillStyle=g;ctx.beginPath();ctx.roundRect(110,y,bw,bh,4);ctx.fill();
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
      html+='<tr><td>'+fmtTime(v.time)+'</td><td>'+esc(v.ip)+'</td><td style="font-family:monospace;font-size:.72rem">'+esc(v.fid||'')+'</td><td>'+esc(v.browser||'')+'</td><td>'+esc(v.region||'未知')+'</td><td>'+esc(v.page||'')+'</td><td><button class="action-btn ban" data-ip="'+esc(v.ip)+'" data-fid="'+esc(v.fid||'')+'">封禁</button></td></tr>';
    });
    $('#visitorTable').innerHTML=html||'<tr><td colspan="7" style="text-align:center;color:var(--text-3)">暂无数据</td></tr>';
    $$('#visitorTable .action-btn.ban').forEach(function(b){b.onclick=function(){banIP(b.dataset.ip,b.dataset.fid,'手动封禁')}});
  });
}
function loadSecurity(){
  api('/api/stats/security').then(function(d){
    if(!d.ok)return;
    $('#secTotal').textContent=d.data.total||0;
    $('#secToday').textContent=d.data.today||0;
    $('#secBanned').textContent=d.data.banned||0;
    $('#secRate').textContent=(d.data.rate||0)+'%';
    $('#secBadge').textContent=d.data.today||0;
    drawBar('chartAttackType',d.data.typeLabels||[],d.data.typeData||[],'#ff453a');
    drawLine('chartAttackTrend',d.data.trendLabels||[],[{data:d.data.trendData||[],color:'#ff453a'}]);
    var html='';
    (d.data.bans||[]).forEach(function(b){
      html+='<tr><td>'+fmtTime(b.time)+'</td><td>'+esc(b.ip)+'</td><td style="font-family:monospace;font-size:.72rem">'+esc(b.fid||'-')+'</td><td>'+esc(b.reason)+'</td><td><span class="tag '+(b.type==='permanent'?'red':'yellow')+'">'+(b.type==='permanent'?'永久':'临时')+'</span></td><td><span class="tag '+(b.active?'red':'green')+'">'+(b.active?'封禁中':'已解除')+'</span></td><td>'+(b.active?'<button class="action-btn unban" data-id="'+esc(b.id)+'">解封</button>':'-')+'</td></tr>';
    });
    $('#banTable').innerHTML=html||'<tr><td colspan="7" style="text-align:center;color:var(--text-3)">暂无封禁记录</td></tr>';
    $$('#banTable .action-btn.unban').forEach(function(b){b.onclick=function(){unban(b.dataset.id)}});
  });
}
function loadAppeals(){
  api('/api/appeals').then(function(d){
    if(!d.ok)return;
    $('#appealBadge').textContent=(d.data||[]).length;
    var html='';
    (d.data||[]).forEach(function(a){
      html+='<div class="appeal-card"><div class="ac-head"><div><div class="ac-ip">'+esc(a.ip)+'</div><div class="ac-meta">'+fmtTime(a.time)+' · 设备: '+esc(a.fid||'未知')+' · 封禁原因: '+esc(a.banReason)+'</div></div><span class="tag yellow">待审核</span></div><div class="ac-body">'+esc(a.content)+'</div><div class="ac-actions"><button class="btn-sm primary" data-action="approve" data-id="'+esc(a.id)+'">通过解封</button><button class="btn-sm danger" data-action="reject" data-id="'+esc(a.id)+'">驳回</button><button class="btn-sm ghost" data-action="permanent" data-id="'+esc(a.id)+'">永久封禁</button></div></div>';
    });
    $('#appealList').innerHTML=html||'<p style="color:var(--text-3);text-align:center;padding:40px">暂无待审核申诉</p>';
    $$('#appealList button').forEach(function(b){b.onclick=function(){handleAppeal(b.dataset.id,b.dataset.action)}});
  });
}
function loadAnnouncements(){
  api('/api/announcement/all').then(function(d){
    if(!d.ok)return;
    var html='';
    (d.data||[]).forEach(function(a){
      html+='<tr><td>'+fmtTime(a.time)+'</td><td>'+esc(a.title)+'</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">'+esc(a.content)+'</td><td><button class="action-btn ban" data-id="'+esc(a.id)+'">删除</button></td></tr>';
    });
    $('#annTable').innerHTML=html||'<tr><td colspan="4" style="text-align:center;color:var(--text-3)">暂无公告</td></tr>';
    $$('#annTable .action-btn.ban').forEach(function(b){b.onclick=function(){delAnn(b.dataset.id)}});
  });
}

function banIP(ip,fid,reason){
  api('/api/security/ban',{method:'POST',body:JSON.stringify({ip:ip,fid:fid,reason:reason})}).then(function(d){
    if(d.ok){toast('已封禁','ok');loadSecurity();loadVisitors()}else toast(d.error||'操作失败','err');
  });
}
function unban(id){
  api('/api/security/unban',{method:'POST',body:JSON.stringify({id:id})}).then(function(d){
    if(d.ok){toast('已解封','ok');loadSecurity()}else toast(d.error||'操作失败','err');
  });
}
function handleAppeal(id,action){
  api('/api/appeals/handle',{method:'POST',body:JSON.stringify({id:id,action:action})}).then(function(d){
    if(d.ok){toast('操作成功','ok');loadAppeals();loadSecurity()}else toast(d.error||'操作失败','err');
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

/* ============ REPORTS ============ */
function genReport(type){
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

/* ============ REFRESH BUTTONS ============ */
$('#btnRefreshOverview').onclick=function(){loadOverview();toast('已刷新')};
$('#btnRefreshVisitors').onclick=function(){loadVisitors();toast('已刷新')};
$('#btnRefreshSecurity').onclick(function(){loadSecurity();toast('已刷新')});
$('#btnRefreshAppeals').onclick=function(){loadAppeals();toast('已刷新')};

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
        div.innerHTML='<span class="li-tag '+l.type+'">'+l.typeLabel+'</span><div class="li-body"><div class="li-msg">'+esc(l.message)+'</div></div><span class="li-time">'+l.timeStr+'</span>';
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
  $('#modalContent').innerHTML='<button class="modal-close" onclick="document.getElementById(\'modal\').classList.remove(\'show\')">关闭</button><h3>手动封禁</h3><div class="form-group"><label>IP地址</label><input type="text" id="banIp" placeholder="例如 1.2.3.4"></div><div class="form-group"><label>设备指纹(可选)</label><input type="text" id="banFid" placeholder="留空则仅封IP"></div><div class="form-group"><label>原因</label><input type="text" id="banReason" placeholder="封禁原因"></div><button class="btn-login" id="btnDoBan" style="margin-top:10px">确认封禁</button>';
  $('#modal').classList.add('show');
  $('#btnDoBan').onclick=function(){
    var ip=$('#banIp').value.trim(),reason=$('#banReason').value.trim()||'手动封禁';
    if(!ip)return toast('请输入IP','err');
    banIP(ip,$('#banFid').value.trim(),reason);
    $('#modal').classList.remove('show');
  };
};

/* ============ INIT ============ */
(function(){
  var token=sessionStorage.getItem('jf_token');
  if(token){
    api('/api/auth/check').then(function(d){if(d.ok)enterDashboard();else showStep(1)});
  }else{showStep(1)}
})();
})();
