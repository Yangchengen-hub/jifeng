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
  var w=c.offsetWidth||c.parentElement.offsetWidth||320;
  var h=parseInt(c.getAttribute('height'))||160;
  if(w<10)w=320;
  c.width=w*dpr;c.height=h*dpr;
  c.style.width=w+'px';
  var ctx=c.getContext('2d');ctx.setTransform(1,0,0,1,0,0);ctx.scale(dpr,dpr);
  ctx.clearRect(0,0,w,h);
  return{ctx:ctx,W:w,H:h};
}
function drawLine(canvasId,labels,datasets){
  var c=$(canvasId);if(!c)return;var s=setupCanvas(c),ctx=s.ctx,W=s.W,H=s.H,pad=32;
  ctx.clearRect(0,0,W,H);
  var hasData=false;datasets.forEach(function(ds){ds.data.forEach(function(v){if(v>0)hasData=true})});
  if(!hasData){chartEmpty(canvasId,'暂无数据');return}
  chartOk(canvasId);
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
  var total=data.reduce(function(a,b){return a+b},0);
  if(!total){chartEmpty(canvasId,'暂无攻击记录');return}
  chartOk(canvasId);
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
  var total=data.reduce(function(a,b){return a+b},0);
  if(!total||total===0){chartEmpty(canvasId,'暂无数据');return}
  chartOk(canvasId);
  total=total||1;var start=-Math.PI/2;
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
  var total=data.reduce(function(a,b){return a+b},0);
  if(!total){chartEmpty(canvasId,'暂无数据');return}
  chartOk(canvasId);
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
    cacheAndDraw('chartDevice',d.data.deviceLabels||['移动端','桌面端'],[d.data.mobile||0,d.data.desktop||0],['#0a84ff','#bf5af2'],'doughnut');
    cacheAndDraw('chartPages',d.data.pageLabels||[],d.data.pageData||[],'#ff6900','hbar');
    renderVisitors(d.data.recent||[]);
  });
}

function renderDevices(list){
  var search=($('#visitorSearch')||{}).value||'';
  var filtered=list;
  if(search){
    var q=search.toLowerCase();
    filtered=list.filter(function(v){return(v.ip||'').toLowerCase().includes(q)||(v.browser||'').toLowerCase().includes(q)||(v.fid||'').toLowerCase().includes(q)||(v.brand||'').toLowerCase().includes(q)||(v.model||'').toLowerCase().includes(q)});
  }
  var html='';
  filtered.forEach(function(v,idx){
    var deviceName=v.brand?(v.brand+' '+(v.model||'')).trim():(v.os||'未知设备');
    var avatar=(v.browser?v.browser.charAt(0):'?');
    var banTag=v.banned?'<span class="vi-tag" style="background:rgba(255,69,58,0.15);color:var(--red)">⛔ 已封禁</span>':'';
    var lastSeenStr=fmtTime(v.lastSeen);
    html+='<div class="device-card" data-idx="'+idx+'">'+
      '<div class="dc-header" onclick="toggleDevice('+idx+')">'+
        '<div class="dc-avatar">'+esc(avatar)+'</div>'+
        '<div class="dc-info">'+
          '<div class="dc-name">'+esc(deviceName)+' '+banTag+'</div>'+
          '<div class="dc-meta">'+esc(v.browser||'')+(v.androidVer?' · Android '+esc(v.androidVer):'')+(v.kernel?' · 内核'+esc(v.kernel):'')+'</div>'+
          '<div class="dc-sub">'+esc(v.ip)+' · 访问'+v.visits+'次 · 最后'+lastSeenStr+'</div>'+
        '</div>'+
        '<div class="dc-arrow">›</div>'+
      '</div>'+
      '<div class="dc-body" id="dcbody_'+idx+'">'+renderDeviceProfile(v)+'</div>'+
    '</div>';
  });
  $('#visitorTable').innerHTML=html||'<div class="empty-state"><p>暂无访客</p></div>';
  window._devices=filtered;
}

function toggleDevice(idx){
  var body=$('#dcbody_'+idx);
  if(body)body.classList.toggle('open');
}

function renderDeviceProfile(v){
  var deviceName=v.brand?(v.brand+' '+(v.model||'')).trim():(v.os||'未知设备');
  var h='';
  // Stats row
  h+='<div class="dc-stats">';
  h+='<div class="dc-stat"><b>'+v.visits+'</b><span>访问</span></div>';
  h+='<div class="dc-stat"><b>'+Math.round(v.totalDuration)+'s</b><span>停留</span></div>';
  h+='<div class="dc-stat"><b>'+v.totalClicks+'</b><span>点击</span></div>';
  h+='<div class="dc-stat"><b>'+v.maxScroll+'%</b><span>滚动</span></div>';
  h+='</div>';
  // Info grid
  h+='<div class="dc-info-grid">';
  var info=[
    ['品牌',v.brand],['型号',v.model],['系统',v.os],['版本',v.androidVer||v.iosVer],
    ['内核',v.kernel],['浏览器',v.browser],['屏幕',v.screen],['GPU',v.gpu?v.gpu.substring(0,30):''],
    ['网络',v.network],['主题',v.colorScheme==='dark'?'深色':'浅色'],
    ['首次',fmtTime(v.firstSeen)],['最后',fmtTime(v.lastSeen)]
  ];
  info.forEach(function(r){if(r[1])h+='<div class="dc-info-item"><span>'+r[0]+'</span><b>'+esc(String(r[1]))+'</b></div>'});
  h+='</div>';
  // IPs
  if(v.ips&&v.ips.length){
    h+='<div class="dc-section"><span class="dc-label">IP 地址 ('+v.ips.length+')</span>';
    v.ips.forEach(function(ip){h+='<div class="dc-ip-row">'+esc(ip)+'</div>'});
    h+='</div>';
  }
  // Pages
  if(v.pages&&v.pages.length){
    h+='<div class="dc-section"><span class="dc-label">访问页面</span>';
    v.pages.forEach(function(p){h+='<span class="dc-page-tag">'+esc(p)+'</span>'});
    h+='</div>';
  }
  // Timeline
  if(v.actions&&v.actions.length){
    h+='<div class="dc-section"><span class="dc-label">行为时间线 ('+v.actions.length+')</span><div class="timeline-list">';
    v.actions.slice(-80).forEach(function(a){
      var tag=a.t==='click'?'click':a.t==='visibility'?'visit':'warning';
      var label=a.t==='click'?'点击':a.t==='visibility'?(a.d&&a.d.hidden?'离开':'回到'):'行为';
      var detail=a.d?(a.d.text||a.d.href||a.d.tag||''):'';
      h+='<div class="timeline-event"><span class="te-time">'+new Date(a.ts).toLocaleTimeString('zh-CN',{hour12:false})+'</span><div class="te-content"><span class="te-tag '+tag+'">'+label+'</span>'+esc(detail)+'</div></div>';
    });
    h+='</div></div>';
  }
  // Actions
  h+='<div class="dc-actions">';
  if(v.banned){
    h+='<button class="dc-btn unban" onclick="event.stopPropagation();unbanIP(\''+esc(v.ip)+'\',\''+esc(v.fid||'')+'\')">解封</button>';
  }else{
    h+='<button class="dc-btn ban" onclick="event.stopPropagation();banIP(\''+esc(v.ip)+'\',\''+esc(v.fid||'')+'\',\'管理员手动封禁\')">封禁</button>';
  }
  h+='</div>';
  return h;
}

function renderVisitorDetail(v){
  var deviceName=v.brand?(v.brand+' '+(v.model||'')).trim():'未知';
  var rows=[
    ['IP地址',v.ip],['设备指纹',v.fid?esc(v.fid.substring(0,24))+'...':''],
    ['品牌型号',esc(deviceName)],['系统版本',v.androidVer?'Android '+esc(v.androidVer):(v.iosVer?'iOS '+esc(v.iosVer):esc(v.os||''))],
    ['内核版本',v.kernel?esc(v.kernel):''],
    ['User-Agent',v.ua?esc(v.ua.substring(0,120)):''],
    ['浏览器/系统',v.browser],['平台',v.platform],
    ['语言',v.language+(v.languages?' ('+v.languages+')':'')],
    ['时区',v.timezone+' (UTC'+(v.tzOffset>0?'-':'+')+(v.tzOffset/60)+')'],
    ['屏幕',v.screen+' 色深:'+v.colorDepth+'bit 方向:'+v.orientation],
    ['视口',v.viewport],['DPR',v.dpr+'x'],
    ['CPU核心',v.cores],['内存',v.memory?v.memory+'GB':''],
    ['触控点',v.touchPoints],
    ['网络',v.network+' 下行:'+v.downlink+'Mbps RTT:'+v.rtt+'ms'],
    ['GPU',v.gpu],['Canvas指纹',v.canvasHash],
    ['电池',v.battery||'未知'],['主题',v.colorScheme==='dark'?'深色':'浅色'],
    ['Cookie',v.cookieEnabled?'启用':'禁用'],['DNT',v.doNotTrack||'未设置'],
    ['字体',v.fonts],['插件',v.plugins],
    ['来源页',v.referrer||v.ref||'直接访问'],
    ['停留时长',v.duration?Math.round(v.duration)+'秒':'进行中'],
    ['点击次数',v.clicks||0],['滚动深度',(v.maxScroll||0)+'%'],
    ['访问时间',new Date(v.time).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})]
  ];
  var html='<div class="vd-grid">';
  rows.forEach(function(r){
    if(r[1])html+='<div class="vd-item"><span class="vd-label">'+r[0]+'</span><span class="vd-val">'+esc(String(r[1]))+'</span></div>';
  });
  html+='</div>';
  if(v.actions&&v.actions.length){
    html+='<div class="vd-actions"><h4>行为日志 ('+v.actions.length+')</h4><div class="vd-action-list">';
    v.actions.slice(-20).forEach(function(a){
      var icon=a.t==='click'?'🖱️':a.t==='visibility'?'👁️':a.t==='copy'?'📋':a.t==='contextmenu'?'📌':'📝';
      html+='<div class="vd-action"><span>'+icon+' '+esc(a.t)+'</span><span class="vd-action-d">'+esc((a.d&&a.d.text)||(a.d&&a.d.href)||'')+'</span><span class="vd-action-t">'+new Date(a.ts).toLocaleTimeString('zh-CN',{hour12:false})+'</span></div>';
    });
    html+='</div></div>';
  }
  return html;
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
  loadSiteMode();
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
        // Security events collected for email digest, no popup
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


/* ===== DEVICE PROFILE ===== */
function openDeviceProfile(v){
  var deviceName=v.brand?(v.brand+' '+(v.model||'')).trim():(v.os||'未知设备');
  var html='<div class="profile-back" onclick="switchPanel(\'visitors\')">← 返回访客列表</div>';
  html+='<div class="profile-header"><div class="profile-avatar" style="background:rgba(255,105,0,0.15);color:var(--brand)">'+esc((v.browser||'?').charAt(0))+'</div><div class="profile-info"><h3>'+esc(v.ip)+'</h3><p>'+esc(deviceName)+' · '+esc(v.browser||'')+'</p></div></div>';
  html+='<div class="profile-stats">';
  html+='<div class="profile-stat"><div class="ps-val">'+(v.clicks||0)+'</div><div class="ps-label">点击</div></div>';
  html+='<div class="profile-stat"><div class="ps-val">'+(v.maxScroll||0)+'%</div><div class="ps-label">滚动</div></div>';
  html+='<div class="profile-stat"><div class="ps-val">'+(v.duration?Math.round(v.duration)+'s':'在线')+'</div><div class="ps-label">停留</div></div>';
  html+='</div>';
  // Device info
  html+='<div class="chart-card"><h3>设备档案</h3><div class="vd-grid">';
  var info=[
    ['品牌',v.brand],['型号',v.model],['系统',v.os],['系统版本',v.androidVer||v.iosVer],
    ['内核',v.kernel],['浏览器',v.browser],['UA',v.ua?v.ua.substring(0,100):''],
    ['屏幕',v.screen],['DPR',v.dpr],['色深',v.colorDepth],['视口',v.viewport],
    ['CPU',v.cores? v.cores+'核':''],['内存',v.memory?v.memory+'GB':''],['触控',v.touchPoints],
    ['GPU',v.gpu],['网络',v.network],['下行',v.downlink?v.downlink+'Mbps':''],['RTT',v.rtt?v.rtt+'ms':''],
    ['电池',v.battery],['语言',v.language],['时区',v.timezone],['主题',v.colorScheme],
    ['Canvas指纹',v.canvasHash],['字体',v.fonts],['插件',v.plugins],
    ['Cookie',v.cookieEnabled?'启用':'禁用'],['DNT',v.doNotTrack||'未设置'],
    ['来源',v.referrer||v.ref||'直接访问'],['首次访问',new Date(v.time).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})]
  ];
  info.forEach(function(r){if(r[1])html+='<div class="vd-item"><span class="vd-label">'+r[0]+'</span><span class="vd-val">'+esc(String(r[1]))+'</span></div>'});
  html+='</div></div>';
  // Action timeline
  html+='<div class="chart-card"><h3>行为时间线</h3><div class="timeline-list">';
  html+='<div class="timeline-event"><span class="te-time">'+(v.timeStr||'')+'</span><div class="te-content"><span class="te-tag visit">访问</span>进入 '+esc(v.page||'/')+'</div></div>';
  if(v.actions&&v.actions.length){
    v.actions.slice(-50).forEach(function(a){
      var tag=a.t==='click'?'click':a.t==='visibility'?'visit':a.t==='copy'?'click':'warning';
      var label=a.t==='click'?'点击':a.t==='visibility'?(a.d&&a.d.hidden?'离开':'回到'):'行为';
      var detail=a.d?(a.d.text||a.d.href||a.d.tag||''):'';
      html+='<div class="timeline-event"><span class="te-time">'+new Date(a.ts).toLocaleTimeString('zh-CN',{hour12:false})+'</span><div class="te-content"><span class="te-tag '+tag+'">'+label+'</span>'+esc(detail)+'</div></div>';
    });
  }
  html+='</div></div>';
  // Actions
  html+='<div style="display:flex;gap:10px;margin-top:14px">';
  html+='<button class="btn-login ripple" style="flex:1;padding:14px" onclick="banIP(\''+esc(v.ip)+'\',\''+esc(v.fid||'')+'\',\'设备档案手动封禁\')">封禁此设备</button>';
  html+='</div>';
  // Replace visitors panel content
  var panel=$('#panel-visitors');
  var original=panel.innerHTML;
  panel.dataset.original=original;
  panel.innerHTML=html;
  $('#panelTitle').textContent='设备档案';
}

/* ===== CHART EMPTY STATE ===== */
function chartEmpty(canvasId,text){
  var c=$(canvasId);if(!c)return;
  var parent=c.parentElement;
  var existing=parent.querySelector('.chart-empty');
  if(existing)existing.remove();
  var div=document.createElement('div');div.className='chart-empty';div.textContent=text||'暂无数据';
  parent.appendChild(div);
  c.style.visibility='hidden';
}
function chartOk(canvasId){
  var c=$(canvasId);if(!c)return;
  c.style.visibility='visible';
  var parent=c.parentElement;
  var existing=parent.querySelector('.chart-empty');
  if(existing)existing.remove();
}

/* ===== SITE MODE CONTROL ===== */
function loadSiteMode(){
  api('/api/settings').then(function(d){
    if(!d.ok||!d.data)return;
    var mode=d.data.siteMode||'normal';
    $$('.mode-btn').forEach(function(b){b.classList.toggle('active',b.dataset.mode===mode)});
    if(d.data.reportTime){var rt=$('#reportTimeInput');if(rt)rt.value=d.data.reportTime}
  });
}
$$('.mode-btn').forEach(function(btn){
  btn.onclick=function(){
    var mode=btn.dataset.mode;
    $$('.mode-btn').forEach(function(b){b.classList.remove('active')});
    btn.classList.add('active');
    var msgBox=$('#modeMsgBox');
    if(mode==='normal'){
      api('/api/admin/site-mode',{method:'POST',body:JSON.stringify({mode:'normal'})}).then(function(d){
        if(d.ok){toast('网站已恢复正常','ok');msgBox.style.display='none'}else toast(d.error||'失败','err');
      });
    }else{
      msgBox.style.display='block';
      $('#modeMsgInput').placeholder=mode==='maintenance'?'维护提示消息...':'关停提示消息...';
      $('#btnApplyMode').onclick=function(){
        var msg=$('#modeMsgInput').value.trim();
        api('/api/admin/site-mode',{method:'POST',body:JSON.stringify({mode:mode,msg:msg})}).then(function(d){
          if(d.ok){toast(mode==='maintenance'?'维护模式已开启':'网站已关停','ok');msgBox.style.display='none';$('#modeMsgInput').value=''}else toast(d.error||'失败','err');
        });
      };
    }
  };
});
$('#reportTimeInput').onchange=function(){
  api('/api/admin/report-time',{method:'POST',body:JSON.stringify({time:this.value})}).then(function(d){
    if(d.ok)toast('报告时间已保存','ok');
  });
};


/* ===== WEBAUTHN (Face ID / Fingerprint) ===== */
function waSupported(){
  return !!(window.PublicKeyCredential&&navigator.credentials&&navigator.credentials.create);
}
function bufToB64(buf){
  var bytes=new Uint8Array(buf);var str='';
  for(var i=0;i<bytes.byteLength;i++)str+=String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function b64ToBuf(b64){
  var s=b64.replace(/-/g,'+').replace(/_/g,'\/');
  while(s.length%4)s+='=';
  var bin=atob(s);var bytes=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
  return bytes.buffer;
}
function checkBioStatus(){
  if(!waSupported())return;
  fetch(API+'/api/auth/wa/status').then(function(r){return r.json()}).then(function(d){
    if(d.ok&&d.registered){
      var btn=document.getElementById('btnBio');var hint=document.getElementById('bioHint');
      if(btn)btn.style.display='flex';
      if(hint)hint.style.display='block';
    }
  }).catch(function(){});
}
function bioLogin(){
  var btn=document.getElementById('btnBio');
  if(btn){btn.disabled=true;btn.textContent='验证中...'}
  fetch(API+'/api/auth/wa/login-options').then(function(r){return r.json()}).then(function(d){
    if(!d.ok){toast(d.error||'未注册生物识别','err');resetBioBtn();return}
    var opts=d.options;
    opts.challenge=b64ToBuf(opts.challenge);
    if(opts.allowCredentials)opts.allowCredentials.forEach(function(c){c.id=b64ToBuf(c.id)});
    return navigator.credentials.get({publicKey:opts});
  }).then(function(assertion){
    if(!assertion)return;
    var body={
      id:assertion.id,
      rawId:bufToB64(assertion.rawId),
      response:{
        authenticatorData:bufToB64(assertion.response.authenticatorData),
        clientDataJSON:bufToB64(assertion.response.clientDataJSON),
        signature:bufToB64(assertion.response.signature),
        userHandle:assertion.response.userHandle?bufToB64(assertion.response.userHandle):null
      },
      type:assertion.type
    };
    return fetch(API+'/api/auth/wa/login-verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json()});
  }).then(function(d){
    if(d&&d.ok){
      localStorage.setItem('jf_token',d.token);
      token=d.token;
      showApp();loadDashboard();
      toast('生物识别登录成功','ok');
    }else if(d){
      toast(d.error||'验证失败','err');
    }
    resetBioBtn();
  }).catch(function(e){
    toast('生物识别不可用: '+e.message,'err');
    resetBioBtn();
  });
}
function resetBioBtn(){
  var btn=document.getElementById('btnBio');
  if(btn){btn.disabled=false;btn.innerHTML='<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"/></svg> 生物识别登录';}
}
function regBio(){
  var btn=document.getElementById('btnRegBio');
  if(btn){btn.disabled=true;btn.textContent='注册中...'}
  fetch(API+'/api/auth/wa/reg-options',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}}).then(function(r){return r.json()}).then(function(d){
    if(!d.ok){toast(d.error||'请先登录','err');resetRegBtn();return}
    var opts=d.options;
    opts.challenge=b64ToBuf(opts.challenge);
    opts.user.id=b64ToBuf(opts.user.id);
    if(opts.excludeCredentials)opts.excludeCredentials.forEach(function(c){c.id=b64ToBuf(c.id)});
    return navigator.credentials.create({publicKey:opts});
  }).then(function(cred){
    if(!cred)return;
    var body={
      id:cred.id,
      rawId:bufToB64(cred.rawId),
      response:{
        attestationObject:bufToB64(cred.response.attestationObject),
        clientDataJSON:bufToB64(cred.response.clientDataJSON),
        transports:cred.response.getTransports?cred.response.getTransports():['internal']
      },
      type:cred.type
    };
    return fetch(API+'/api/auth/wa/reg-verify',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify(body)}).then(function(r){return r.json()});
  }).then(function(d){
    if(d&&d.ok){toast('生物识别注册成功','ok');resetRegBtn('已注册')}
    else if(d){toast(d.error||'注册失败','err');resetRegBtn()}
  }).catch(function(e){
    toast('注册失败: '+e.message,'err');resetRegBtn();
  });
}
function resetRegBtn(txt){
  var btn=document.getElementById('btnRegBio');
  if(btn){btn.disabled=false;btn.textContent=txt||'注册'}
}

/* ===== CHART CACHE & REDRAW ===== */
var chartCache={};
function cacheAndDraw(id,labels,data,colors,type){
  chartCache[id]={labels:labels,data:data,colors:colors,type:type};
  drawChartCached(id);
}
function drawChartCached(id){
  var c=chartCache[id];if(!c)return;
  var el=$(id);if(!el)return;
  if(el.offsetWidth<10)return;
  if(c.type==='doughnut')drawDoughnut(id,c.labels,c.data,c.colors);
  else if(c.type==='hbar')drawHBar(id,c.labels,c.data,c.colors);
  else if(c.type==='bar')drawBar(id,c.labels,c.data,c.colors);
  else if(c.type==='line')drawLine(id,c.labels,c.data);
}
function redrawAllCharts(){
  Object.keys(chartCache).forEach(function(id){
    setTimeout(function(){drawChartCached(id)},100);
  });
}
window.addEventListener('resize',function(){redrawAllCharts()});
window.addEventListener('orientationchange',function(){setTimeout(redrawAllCharts,200)});


/* ===== PWA INSTALL PROMPT ===== */
var deferredPrompt=null;
window.addEventListener('beforeinstallprompt',function(e){
  e.preventDefault();deferredPrompt=e;
  setTimeout(function(){showInstallBanner()},3000);
});
function showInstallBanner(){
  if(localStorage.getItem('jf_pwa_dismissed'))return;
  var existing=document.getElementById('pwaBanner');if(existing)return;
  var banner=document.createElement('div');
  banner.id='pwaBanner';
  banner.style.cssText='position:fixed;bottom:90px;left:16px;right:16px;background:var(--card);backdrop-filter:var(--glass-blur);border-radius:18px;padding:16px;display:flex;align-items:center;gap:12px;z-index:999;box-shadow:var(--shadow);border:0.5px solid var(--border);animation:fadeUp .4s var(--spring)';
  banner.innerHTML='<div style="font-size:28px">📱</div><div style="flex:1"><div style="font-weight:700;font-size:14px">安装控制端APP</div><div style="font-size:11px;color:var(--text-3)">添加到桌面，支持生物识别快速登录</div></div><button id="pwaInstall" style="padding:10px 18px;border-radius:14px;border:none;background:var(--brand-gradient);color:#fff;font-weight:600;font-size:13px;cursor:pointer">安装</button><button id="pwaDismiss" style="padding:8px;border:none;background:none;color:var(--text-3);font-size:18px;cursor:pointer">×</button>';
  document.body.appendChild(banner);
  document.getElementById('pwaInstall').onclick=function(){
    if(deferredPrompt){deferredPrompt.prompt();deferredPrompt.userChoice.then(function(){deferredPrompt=null;banner.remove()})}
  };
  document.getElementById('pwaDismiss').onclick=function(){
    localStorage.setItem('jf_pwa_dismissed','1');banner.remove();
  };
}

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
