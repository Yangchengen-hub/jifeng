(function(){
var API=window.JF_API||'';
var $=function(s,p){return(p||document).querySelector(s)};
var $$=function(s,p){return Array.prototype.slice.call((p||document).querySelectorAll(s))};

/* ===== UTILS ===== */
function toast(msg,type){var t=$('#toast');t.textContent=msg;t.className='toast show'+(type?' '+type:'');setTimeout(function(){t.className='toast'},3000)}
function island(text,isAlert){var el=$('#dynIsland');$('#diText').textContent=text;el.className='dynamic-island show'+(isAlert?' alert':'');setTimeout(function(){el.className='dynamic-island'},3500)}
function esc(s){if(s==null)return'';var d=document.createElement('div');d.textContent=String(s);return d.innerHTML}
function fmtTime(ts){var d=new Date(ts);return d.toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})}
function fmtDate(ts){var d=new Date(ts);return d.toLocaleDateString('zh-CN',{timeZone:'Asia/Shanghai',month:'2-digit',day:'2-digit'})}

function api(path,opts){
  opts=opts||{};opts.headers=opts.headers||{};opts.headers['Content-Type']='application/json';
  var token=sessionStorage.getItem('jf_token');if(token)opts.headers['Authorization']='Bearer '+token;
  var ctrl=new AbortController();opts.signal=ctrl.signal;
  var timer=setTimeout(function(){ctrl.abort()},12000);
  return fetch(API+path,opts).then(function(r){clearTimeout(timer);return r.json().catch(function(){return{ok:r.ok}})})
  .catch(function(e){clearTimeout(timer);return{ok:false,error:e.name==='AbortError'?'连接超时':'网络错误'}});
}

/* Simple XOR encrypt for device token in localStorage */
function encryptToken(token){
  var key='JF_STUDIO_2024_SECRET_KEY';
  var result='';
  for(var i=0;i<token.length;i++){
    result+=String.fromCharCode(token.charCodeAt(i)^key.charCodeAt(i%key.length));
  }
  return btoa(unescape(encodeURIComponent(result)));
}
function decryptToken(encoded){
  try{
    var key='JF_STUDIO_2024_SECRET_KEY';
    var decoded=decodeURIComponent(escape(atob(encoded)));
    var result='';
    for(var i=0;i<decoded.length;i++){
      result+=String.fromCharCode(decoded.charCodeAt(i)^key.charCodeAt(i%key.length));
    }
    return result;
  }catch(e){return null}
}

/* ===== DEVICE FINGERPRINT ===== */
function getDeviceName(){
  var ua=navigator.userAgent;
  var name='未知设备';
  if(/Android/i.test(ua)){
    var match=ua.match(/Android\s([\d.]+)/);
    name='Android '+(match?match[1]:'')+' 设备';
  }else if(/iPhone|iPad|iPod/i.test(ua)){
    name='iOS 设备';
  }else if(/Windows/i.test(ua)){
    name='Windows 电脑';
  }else if(/Macintosh/i.test(ua)){
    name='Mac 电脑';
  }else if(/Linux/i.test(ua)){
    name='Linux 设备';
  }
  var browser='';
  if(/Chrome/i.test(ua)&&!/Edg/i.test(ua))browser='Chrome';
  else if(/Safari/i.test(ua)&&!/Chrome/i.test(ua))browser='Safari';
  else if(/Firefox/i.test(ua))browser='Firefox';
  else if(/Edg/i.test(ua))browser='Edge';
  else if(/MicroMessenger/i.test(ua))browser='微信';
  else if(/QQ\//i.test(ua))browser='QQ';
  return name+(browser?' · '+browser:'');
}

/* ===== LOGIN ===== */
var step=1,captchaCode='';

function showStep(n){
  step=n;
  $$('.step-panel').forEach(function(p){p.classList.remove('active')});
  var target=$('#step'+n);if(target)target.classList.add('active');
  ['dot1','dot2','dot3','line1','line2'].forEach(function(id){var el=$('#'+id);if(el)el.className=el.className.replace(/\b(done|active)\b/g,'')});
  if(n>=1){var d1=$('#dot1');if(d1)d1.classList.add('active')}
  if(n>=2){var d1b=$('#dot1b');if(d1b)d1b.classList.add('done');var l1b=$('#line1b');if(l1b)l1b.classList.add('done');var d2b=$('#dot2b');if(d2b)d2b.classList.add('active')}
  if(n>=3){var d2c=$('#dot2c');if(d2c)d2c.classList.add('done');var l2c=$('#line2c');if(l2c)l2c.classList.add('done');var d3c=$('#dot3c');if(d3c)d3c.classList.add('active')}
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
    if(d.ok&&d.token){
      sessionStorage.setItem('jf_token',d.token);
      if($('#trustDevice').checked){
        api('/api/auth/trust',{method:'POST',body:JSON.stringify({deviceName:getDeviceName()})}).then(function(td){
          if(td.ok&&td.deviceToken){
            try{localStorage.setItem('jf_device_token',encryptToken(td.deviceToken))}catch(e){}
          }
          enterDashboard();
        });
      }else{
        enterDashboard();
      }
    }else msg(d.error||'验证码错误','err');
  });
};

function enterDashboard(){
  $('#loginWrap').style.display='none';
  $('#dashboard').style.display='block';
  island('安全防护运行中');
  loadOverview();loadVisitors();loadSecurity();loadAppeals();loadAnnouncements();
  loadPermBans();loadDevices();loadWhitelist();loadScore();loadSettings();
  startRealtime();
}

$('#btnLogout').onclick=function(){
  sessionStorage.removeItem('jf_token');
  localStorage.removeItem('jf_device_token');
  location.reload();
};

/* ===== TRUSTED DEVICE AUTO-LOGIN ===== */
function checkTrustedDevice(){
  var encoded=localStorage.getItem('jf_device_token');
  if(!encoded){showStep(1);return}
  var deviceToken=decryptToken(encoded);
  if(!deviceToken){localStorage.removeItem('jf_device_token');showStep(1);return}
  api('/api/auth/check-trust',{method:'POST',body:JSON.stringify({deviceToken:deviceToken})}).then(function(d){
    if(d.ok&&d.token){
      sessionStorage.setItem('jf_token',d.token);
      enterDashboard();
    }else{
      localStorage.removeItem('jf_device_token');
      showStep(1);
    }
  }).catch(function(){showStep(1)});
}

/* ===== NAV ===== */
var currentPanel='overview';
function switchPanel(name){
  currentPanel=name;
  $$('.panel').forEach(function(p){p.classList.remove('active')});
  var target=$('#panel-'+name);
  if(target){target.classList.add('active');$('#panelTitle').textContent=target.dataset.title||''}
  $$('.tab-item').forEach(function(t){t.classList.toggle('active',t.dataset.panel===name)});
  closeMore();
  if(name==='overview'){loadOverview();loadScore()}
  if(name==='visitors')loadVisitors();
  if(name==='security')loadSecurity();
  if(name==='appeals')loadAppeals();
  if(name==='announce')loadAnnouncements();
  if(name==='permanent')loadPermBans();
  if(name==='devices')loadDevices();
  if(name==='whitelist')loadWhitelist();
  if(name==='reports'){}
  if(name==='settings')loadSettings();
}
$$('.tab-item').forEach(function(item){
  item.onclick=function(){
    if(item.dataset.panel==='more'){openMore();return}
    switchPanel(item.dataset.panel);
  };
});
$$('.sheet-item').forEach(function(item){
  item.onclick=function(){switchPanel(item.dataset.panel)};
});
function openMore(){$('#moreSheet').classList.add('show');$('#moreOverlay').classList.add('show')}
function closeMore(){$('#moreSheet').classList.remove('show');$('#moreOverlay').classList.remove('show')}
$('#moreOverlay').onclick=closeMore;

/* ===== CHARTS ===== */
function setupCanvas(c){
  var dpr=window.devicePixelRatio||2;
  var w=c.offsetWidth,h=parseInt(c.getAttribute('height'))||160;
  c.width=w*dpr;c.height=h*dpr;
  var ctx=c.getContext('2d');ctx.scale(dpr,dpr);
  return{ctx:ctx,W:w,H:h};
}
function drawLine(canvasId,labels,datasets){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,pad=32;
  ctx.clearRect(0,0,W,H);
  var max=0;datasets.forEach(function(ds){ds.data.forEach(function(v){if(v>max)max=v})});max=Math.max(max,1);
  var gridColor=getComputedStyle(document.body).getPropertyValue('--text-3').trim()||'#636366';
  ctx.strokeStyle='rgba(128,128,128,0.12)';ctx.lineWidth=1;
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  ctx.fillStyle=gridColor;ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  ctx.textAlign='center';
  var st=(W-pad*2)/(labels.length-1||1);
  labels.forEach(function(l,i){if(i%Math.ceil(labels.length/8)===0)ctx.fillText(l,pad+i*st,H-10)});
  datasets.forEach(function(ds){
    ctx.strokeStyle=ds.color;ctx.lineWidth=2.5;ctx.lineJoin='round';ctx.beginPath();
    ds.data.forEach(function(v,i){var x=pad+i*st,y=pad+(H-pad*2)*(1-v/max);i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
    ctx.stroke();
    ctx.lineTo(pad+(ds.data.length-1)*st,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();
    var g=ctx.createLinearGradient(0,pad,0,H-pad);g.addColorStop(0,ds.color+'28');g.addColorStop(1,ds.color+'00');
    ctx.fillStyle=g;ctx.fill();
    ds.data.forEach(function(v,i){var x=pad+i*st,y=pad+(H-pad*2)*(1-v/max);ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fillStyle=ds.color;ctx.fill()});
  });
}
function drawBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,pad=36;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));
  var bw=(W-pad*2)/data.length*0.6,gap=(W-pad*2)/data.length*0.4;
  ctx.strokeStyle='rgba(128,128,128,0.12)';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke()}
  var gridColor=getComputedStyle(document.body).getPropertyValue('--text-3').trim()||'#636366';
  ctx.fillStyle=gridColor;ctx.font='10px sans-serif';ctx.textAlign='right';
  for(var i=0;i<=4;i++){var y=pad+(H-pad*2)*i/4;ctx.fillText(Math.round(max*(1-i/4)),pad-6,y+3)}
  data.forEach(function(v,i){
    var x=pad+i*(bw+gap)+gap/2,bh=(H-pad*2)*(v/max),y=H-pad-bh;
    var g=ctx.createLinearGradient(0,y,0,H-pad);g.addColorStop(0,color);g.addColorStop(1,color+'50');
    ctx.fillStyle=g;
    if(ctx.roundRect){ctx.beginPath();ctx.roundRect(x,y,bw,bh,5);ctx.fill()}else{ctx.fillRect(x,y,bw,bh)}
    ctx.fillStyle=gridColor;ctx.textAlign='center';ctx.font='9px sans-serif';
    ctx.fillText(labels[i].substring(0,6),x+bw/2,H-10);
  });
}
function drawDoughnut(canvasId,labels,data,colors){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,cx=W*0.32,cy=H/2,r=Math.min(cx,cy)-8,ir=r*0.58;
  ctx.clearRect(0,0,W,H);
  var total=data.reduce(function(a,b){return a+b},0)||1;var start=-Math.PI/2;
  data.forEach(function(v,i){
    var angle=v/total*Math.PI*2;
    ctx.beginPath();ctx.arc(cx,cy,r,start,start+angle);ctx.arc(cx,cy,ir,start+angle,start,true);ctx.closePath();
    ctx.fillStyle=colors[i%colors.length];ctx.fill();start+=angle;
  });
  var gridColor=getComputedStyle(document.body).getPropertyValue('--text-2').trim()||'#98989d';
  ctx.font='10px sans-serif';ctx.textAlign='left';ctx.fillStyle=gridColor;
  labels.forEach(function(l,i){
    var y=18+i*20;ctx.fillStyle=colors[i%colors.length];ctx.fillRect(W*0.58,y-7,10,10);
    ctx.fillStyle=gridColor;ctx.fillText(l.substring(0,10)+' ('+data[i]+')',W*0.58+16,y+2);
  });
}
function drawHBar(canvasId,labels,data,color){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H;
  ctx.clearRect(0,0,W,H);
  var max=Math.max.apply(null,data.concat([1]));var rowH=H/Math.max(data.length,1);
  var gridColor=getComputedStyle(document.body).getPropertyValue('--text-3').trim()||'#636366';
  data.forEach(function(v,i){
    var y=i*rowH+8,bw=(W-100)*(v/max),bh=rowH-16;
    ctx.fillStyle=gridColor;ctx.font='10px sans-serif';ctx.textAlign='right';ctx.fillText(labels[i].substring(0,8),96,y+bh/2+3);
    var g=ctx.createLinearGradient(100,0,100+bw,0);g.addColorStop(0,color+'70');g.addColorStop(1,color);
    ctx.fillStyle=g;
    if(ctx.roundRect){ctx.beginPath();ctx.roundRect(100,y,bw,bh,5);ctx.fill()}else{ctx.fillRect(100,y,bw,bh)}
    ctx.fillStyle=gridColor;ctx.textAlign='left';ctx.fillText(v,108+bw,y+bh/2+3);
  });
}

/* ===== DATA LOADING ===== */
function loadScore(){
  api('/api/security/score').then(function(d){
    if(!d.ok)return;
    var s=d.data;
    $('#secScoreNum').textContent=s.score;
    $('#secGrade').textContent=s.grade;
    var circumference=2*Math.PI*52;
    var offset=circumference-(s.score/100)*circumference;
    $('#scoreArc').style.transition='stroke-dashoffset 1s var(--spring)';
    setTimeout(function(){$('#scoreArc').style.strokeDashoffset=offset},50);
    var checksHtml='';
    s.checks.forEach(function(c){
      checksHtml+='<span class="sc-pill '+(c.status?'ok':'fail')+'">'+(c.status?'✓':'✗')+' '+esc(c.name)+'</span>';
    });
    $('#scoreChecks').innerHTML=checksHtml;
  });
}

function loadOverview(){
  api('/api/stats/overview').then(function(d){
    if(!d.ok)return;
    $('#statVisitors').textContent=d.data.visitors||0;
    $('#statAttacks').textContent=d.data.attacks||0;
    $('#statBans').textContent=d.data.bans||0;
    $('#trendVisitors').textContent=(d.data.visitorTrend>=0?'+':'')+(d.data.visitorTrend||0)+'%';
    $('#trendVisitors').className='sc-trend '+((d.data.visitorTrend||0)>=0?'up':'down');
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
    renderVisitors(d.data.recent||[]);
  });
}

function renderVisitors(list){
  var search=($('#visitorSearch')||{}).value||'';
  var filtered=list;
  if(search){
    var q=search.toLowerCase();
    filtered=list.filter(function(v){return(v.ip||'').toLowerCase().includes(q)||(v.browser||'').toLowerCase().includes(q)||(v.fid||'').toLowerCase().includes(q)});
  }
  var html='';
  filtered.forEach(function(v){
    var avatar=(v.browser?v.browser.charAt(0):'?');
    html+='<div class="visitor-item"><div class="vi-avatar">'+esc(avatar)+'</div><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(v.ip)+'</span></div><div class="vi-meta">'+esc(v.browser||'未知')+' · '+esc(v.os||'')+' · '+esc(v.page||'/')+'</div></div><div class="vi-time">'+(v.timeStr||'')+'</div><button class="vi-action ban" data-ip="'+esc(v.ip)+'" data-fid="'+esc(v.fid||'')+'">封禁</button></div>';
  });
  $('#visitorTable').innerHTML=html||'<div class="empty-state"><p>暂无数据</p></div>';
  $$('#visitorTable .vi-action.ban').forEach(function(b){b.onclick=function(){banIP(b.dataset.ip,b.dataset.fid,'管理员手动封禁')}});
}

$('#visitorSearch').oninput=function(){
  api('/api/stats/visitors').then(function(d){if(d.ok)renderVisitors(d.data.recent||[])});
};

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
    var tempBans=(d.data.bans||[]).filter(function(b){return b.type!=='permanent'});
    $('#tempBanCount').textContent=tempBans.length+' 条';
    var html='';
    tempBans.forEach(function(b){
      html+='<div class="ban-item"><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(b.ip)+'</span><span class="ban-type temporary">临时</span></div><div class="ban-reason">'+esc(b.reason)+'</div><div class="vi-meta">'+fmtTime(b.time)+(b.fid?' · '+esc(b.fid.substring(0,12)):'')+'</div></div>'+(b.active?'<button class="vi-action unban" data-id="'+esc(b.id)+'">解封</button>':'<span class="vi-meta">已解除</span>')+'</div>';
    });
    $('#banTable').innerHTML=html||'<div class="empty-state"><p>暂无临时封禁</p></div>';
    $$('#banTable .vi-action.unban').forEach(function(b){b.onclick=function(){unban(b.dataset.id)}});
  });
  api('/api/security/warnings').then(function(d){
    if(!d.ok)return;
    var html='';
    (d.data||[]).forEach(function(w){
      html+='<div class="warning-item"><div class="wi-count">'+(w.count||1)+'</div><div class="wi-info"><div class="wi-ip">'+esc(w.ip)+'</div><div class="wi-reason">'+esc((w.reasons||[]).slice(-1)[0]||'异常行为')+'</div></div><button class="vi-action ban" data-ip="'+esc(w.ip)+'" data-fid="'+esc(w.fid||'')+'">封禁</button></div>';
    });
    $('#warningList').innerHTML=html||'<div class="empty-state"><p>暂无警告</p></div>';
    $$('#warningList .vi-action.ban').forEach(function(b){b.onclick=function(){banIP(b.dataset.ip,b.dataset.fid,'警告后手动封禁')}});
  });
}

function loadPermBans(){
  api('/api/stats/security').then(function(d){
    if(!d.ok)return;
    var permBans=(d.data.bans||[]).filter(function(b){return b.type==='permanent'});
    var html='';
    permBans.forEach(function(b){
      html+='<div class="ban-item"><div class="vi-info"><div class="vi-top"><span class="vi-ip">'+esc(b.ip)+'</span><span class="ban-type permanent">永久</span></div><div class="ban-reason">'+esc(b.reason)+'</div><div class="vi-meta">'+fmtTime(b.time)+(b.fid?' · '+esc(b.fid.substring(0,12)):'')+'</div></div></div>';
    });
    var el=$('#permBanList');
    if(el)el.innerHTML=html||'<div class="empty-state"><p>暂无永久封禁</p></div>';
  });
}

function loadDevices(){
  api('/api/devices').then(function(d){
    if(!d.ok)return;
    var html='';
    (d.data||[]).forEach(function(dev){
      html+='<div class="device-item"><div class="device-current"></div><div class="vi-info"><div class="device-name">'+esc(dev.name)+'</div><div class="device-meta">'+esc(dev.ip)+' · 添加于 '+fmtTime(dev.createdAt)+' · 最近使用 '+fmtTime(dev.lastUsed)+'</div></div><button class="vi-action revoke" data-id="'+esc(dev.id)+'">移除</button></div>';
    });
    $('#deviceList').innerHTML=html||'<div class="empty-state"><p>暂无信任设备</p></div>';
    $$('#deviceList .vi-action.revoke').forEach(function(b){b.onclick=function(){revokeDevice(b.dataset.id)}});
  });
}

function revokeDevice(id){
  api('/api/devices/revoke',{method:'POST',body:JSON.stringify({id:id})}).then(function(d){
    if(d.ok){toast('设备已移除','ok');loadDevices()}else toast(d.error||'操作失败','err');
  });
}

function loadWhitelist(){
  api('/api/security/whitelist').then(function(d){
    if(!d.ok)return;
    var html='';
    (d.data||[]).forEach(function(w){
      html+='<div class="wl-item"><div class="vi-info"><div class="vi-ip">'+esc(w.ip)+'</div><div class="vi-meta">'+esc(w.note||'无备注')+' · '+fmtTime(w.time)+'</div></div><button class="vi-action del" data-ip="'+esc(w.ip)+'">移除</button></div>';
    });
    $('#wlTable').innerHTML=html||'<div class="empty-state"><p>白名单为空</p></div>';
    $$('#wlTable .vi-action.del').forEach(function(b){b.onclick=function(){removeWhitelist(b.dataset.ip)}});
  });
}

$('#btnAddWl').onclick=function(){
  var ip=$('#wlIp').value.trim(),note=$('#wlNote').value.trim();
  if(!ip)return toast('请输入IP','err');
  api('/api/security/whitelist/add',{method:'POST',body:JSON.stringify({ip:ip,note:note})}).then(function(d){
    if(d.ok){toast('已添加','ok');$('#wlIp').value='';$('#wlNote').value='';loadWhitelist()}else toast(d.error||'失败','err');
  });
};

function removeWhitelist(ip){
  api('/api/security/whitelist/remove',{method:'POST',body:JSON.stringify({ip:ip})}).then(function(d){
    if(d.ok){toast('已移除','ok');loadWhitelist()}else toast(d.error||'失败','err');
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
      html+='<div class="ann-item"><div class="ann-item-title">'+esc(a.title)+'</div><div class="ann-item-content">'+esc(a.content)+'</div><div class="ann-item-time">'+fmtTime(a.time)+' <button class="vi-action del" data-id="'+esc(a.id)+'">删除</button></div></div>';
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
    if(d.ok){toast('已封禁','ok');island('已封禁IP: '+ip,true);loadSecurity();loadVisitors()}else toast(d.error||'操作失败','err');
  });
}
function permBanIP(ip,fid,reason){
  api('/api/security/permanent',{method:'POST',body:JSON.stringify({ip:ip,fid:fid,reason:reason})}).then(function(d){
    if(d.ok){toast('已永久封禁','ok');island('永久封禁: '+ip,true);loadSecurity();loadPermBans()}else toast(d.error||'操作失败','err');
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
    if(d.ok){toast('发布成功','ok');island('公告已发布');$('#annTitleInput').value='';$('#annContentInput').value='';loadAnnouncements()}else toast(d.error||'失败','err');
  });
};

$('#btnPermBan').onclick=function(){
  var ip=$('#permIp').value.trim(),reason=$('#permReason').value.trim()||'管理员永久封禁';
  if(!ip)return toast('请输入IP','err');
  permBanIP(ip,$('#permFid').value.trim(),reason);
  $('#permIp').value='';$('#permFid').value='';$('#permReason').value='';
};

/* ===== REPORTS ===== */
function genReport(type){
  toast('正在生成报告...');
  api('/api/reports/generate',{method:'POST',body:JSON.stringify({type:type})}).then(function(d){
    if(d.ok&&d.data){$('#reportPreview').textContent=d.data.content;$('#btnCopyReport').style.display='block';toast('报告已生成','ok')}else toast(d.error||'生成失败','err');
  });
}
$('#btnReportDaily').onclick=function(){genReport('daily')};
$('#btnReportWeekly').onclick=function(){genReport('weekly')};
$('#btnReportAttack').onclick=function(){genReport('attack')};
$('#btnReportFull').onclick=function(){genReport('full')};
$('#btnCopyReport').onclick=function(){
  var text=$('#reportPreview').textContent;
  if(navigator.clipboard){navigator.clipboard.writeText(text).then(function(){toast('已复制','ok')})}
};

/* ===== DATA EXPORT ===== */
$('#btnExport').onclick=function(){
  toast('正在导出数据...');
  api('/api/data/export',{method:'POST',body:JSON.stringify({type:'all'})}).then(function(d){
    if(d.ok&&d.data){
      var blob=new Blob([JSON.stringify(d.data,null,2)],{type:'application/json'});
      var a=document.createElement('a');a.href=URL.createObjectURL(blob);
      a.download='jifeng-backup-'+new Date().toISOString().slice(0,10)+'.json';a.click();
      toast('导出成功','ok');
    }else toast(d.error||'导出失败','err');
  });
};

/* ===== SETTINGS ===== */
$$('.toggle').forEach(function(t){t.onclick=function(){t.classList.toggle('on');api('/api/settings',{method:'POST',body:JSON.stringify({key:t.dataset.setting,value:t.classList.contains('on')})})}});

/* ===== HEADER REFRESH ===== */
$('#btnRefresh').onclick=function(){
  this.classList.add('spinning');setTimeout(function(){$('#btnRefresh').classList.remove('spinning')},600);
  if(currentPanel==='overview'){loadOverview();loadScore()}
  else if(currentPanel==='visitors')loadVisitors();
  else if(currentPanel==='security')loadSecurity();
  else if(currentPanel==='appeals')loadAppeals();
  else if(currentPanel==='announce')loadAnnouncements();
  else if(currentPanel==='permanent')loadPermBans();
  else if(currentPanel==='devices')loadDevices();
  else if(currentPanel==='whitelist')loadWhitelist();
  toast('已刷新');
};

/* ===== REALTIME ===== */
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
        if(stream.children.length>40)stream.removeChild(stream.lastChild);
        if(l.type==='attack'||l.type==='ban'){island(l.message,true)}
      });
      $('#logCount').textContent=logCount+' 条';
    });
  },4000);
  setInterval(function(){loadOverview();loadScore()},30000);
}

/* ===== MANUAL BAN MODAL ===== */
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

/* ===== RIPPLE ===== */
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

/* ===== INIT ===== */
(function(){
  // Check session token first
  var token=sessionStorage.getItem('jf_token');
  if(token){
    api('/api/auth/check').then(function(d){if(d.ok)enterDashboard();else checkTrustedDevice()});
  }else{
    checkTrustedDevice();
  }
  window.addEventListener('resize',function(){
    if(currentPanel==='overview'){loadOverview()}
    if(currentPanel==='visitors')loadVisitors();
    if(currentPanel==='security')loadSecurity();
  });
})();
})();
