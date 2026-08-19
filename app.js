(function(){
var API=window.JF_API||'https://jifeng-studio.netlify.app';
var fid=localStorage.getItem('jf_fid')||('f_'+Date.now().toString(36)+Math.random().toString(36).slice(2,10));
localStorage.setItem('jf_fid',fid);

function api(path,data){
  var ctrl=new AbortController();var timer=setTimeout(function(){ctrl.abort()},10000);
  return fetch(API+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),signal:ctrl.signal})
    .then(function(r){clearTimeout(timer);return r.json().catch(function(){return{ok:r.ok}})})
    .catch(function(){clearTimeout(timer);return{ok:false}});
}

/* ===== COMPREHENSIVE FINGERPRINT ===== */
function getCanvasFp(){
  try{
    var c=document.createElement('canvas'),ctx=c.getContext('2d');
    c.width=240;c.height=60;
    ctx.textBaseline='top';ctx.font='16px Arial';ctx.fillStyle='#f60';ctx.fillRect(0,0,100,40);
    ctx.fillStyle='#069';ctx.fillText('JifengStudio',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('FP',4,35);
    return btoa(c.toDataURL().slice(-80));
  }catch(e){return''}
}

function getWebGLInfo(){
  try{
    var c=document.createElement('canvas'),gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(!gl)return{};
    var dbg=gl.getExtension('WEBGL_debug_renderer_info');
    return{
      vendor:dbg?String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)):String(gl.getParameter(gl.VENDOR)),
      renderer:dbg?String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)):String(gl.getParameter(gl.RENDERER))
    };
  }catch(e){return{}}
}

function getFonts(){
  var fonts=['Arial','Helvetica','Times New Roman','Courier New','Verdana','Georgia','Comic Sans MS','Trebuchet MS','Arial Black','Impact','Microsoft YaHei','SimSun','PingFang SC','Hiragino Sans GB','Noto Sans CJK SC','WenQuanYi Micro Hei','sans-serif','monospace'];
  var detected=[];
  var span=document.createElement('span');span.style.position='absolute';span.style.left='-9999px';span.style.fontSize='72px';span.innerHTML='mmmmmmmmmmlli';
  document.body.appendChild(span);
  var defaultW=span.offsetWidth,defaultH=span.offsetHeight;
  fonts.forEach(function(f){
    span.style.fontFamily=f+',monospace';
    if(span.offsetWidth!==defaultW||span.offsetHeight!==defaultH)detected.push(f);
  });
  document.body.removeChild(span);
  return detected;
}

function getNetworkInfo(){
  var conn=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
  if(!conn)return{};
  return{
    type:conn.effectiveType||conn.type||'unknown',
    downlink:conn.downlink||0,
    rtt:conn.rtt||0,
    saveData:!!conn.saveData
  };
}

function getBatteryInfo(){
  if(!navigator.getBattery)return Promise.resolve({});
  return navigator.getBattery().then(function(b){
    return{level:Math.round(b.level*100),charging:b.charging};
  }).catch(function(){return{}});
}

function getPlugins(){
  try{return Array.prototype.map.call(navigator.plugins||[],function(p){return p.name}).slice(0,20)}catch(e){return[]}
}

function collectFingerprint(){
  var scr=screen;
  return{
    fid:fid,
    ua:navigator.userAgent,
    platform:navigator.platform||'',
    language:navigator.language||'',
    languages:(navigator.languages||[]).join(','),
    timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'',
    timezoneOffset:new Date().getTimezoneOffset(),
    online:navigator.onLine,
    cookieEnabled:navigator.cookieEnabled,
    doNotTrack:navigator.doNotTrack||window.doNotTrack||'',
    screen:{width:scr.width,height:scr.height,availWidth:scr.availWidth,availHeight:scr.availHeight,colorDepth:scr.colorDepth,pixelDepth:scr.pixelDepth,orientation:scr.orientation?scr.orientation.type:'',dpr:window.devicePixelRatio||1},
    viewport:{width:window.innerWidth,height:window.innerHeight},
    cores:navigator.hardwareConcurrency||0,
    memory:navigator.deviceMemory||0,
    touchPoints:navigator.maxTouchPoints||0,
    touchSupport:'ontouchstart'in window,
    network:getNetworkInfo(),
    plugins:getPlugins(),
    webgl:getWebGLInfo(),
    fonts:getFonts().slice(0,12),
    canvasHash:getCanvasFp().slice(0,24),
    referrer:document.referrer||'',
    url:location.href,
    colorScheme:window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light',
    reducedMotion:window.matchMedia('(prefers-reduced-motion:reduce)').matches,
    timestamp:Date.now()
  };
}

/* ===== BEHAVIOR TRACKING ===== */
var behaviorLog=[];
var sessionStart=Date.now();
var maxScroll=0;
var clickCount=0;

function logBehavior(type,detail){
  behaviorLog.push({t:type,d:detail,ts:Date.now()});
  if(behaviorLog.length>200)behaviorLog.shift();
}

document.addEventListener('click',function(e){
  clickCount++;
  var target=e.target.closest('a,button,[role="button"],.card,.value-item,.tl-item,.ann-bar');
  if(target){
    var tag=target.tagName.toLowerCase();
    var text=(target.textContent||'').trim().substring(0,50);
    var href=target.getAttribute('href')||'';
    var id=target.id||'';
    logBehavior('click',{tag:tag,text:text,href:href,id:id});
  }
},{passive:true,capture:true});

window.addEventListener('scroll',function(){
  var h=document.documentElement.scrollHeight-window.innerHeight;
  if(h>0){var pct=Math.round(window.scrollY/h*100);if(pct>maxScroll)maxScroll=pct;}
},{passive:true});

document.addEventListener('visibilitychange',function(){
  logBehavior('visibility',{hidden:document.hidden});
});

window.addEventListener('beforeunload',function(){
  try{
    navigator.sendBeacon(API+'/api/visitor/session',JSON.stringify({
      fid:fid,
      session:{duration:Math.round((Date.now()-sessionStart)/1000),clicks:clickCount,maxScroll:maxScroll,actions:behaviorLog.slice(-50)}
    }));
  }catch(e){}
});

document.addEventListener('copy',function(){logBehavior('copy',{})});
document.addEventListener('contextmenu',function(){logBehavior('contextmenu',{})});

var lastFp=null;

window.JF={
  trackVisitor:function(){
    var fp=collectFingerprint();
    lastFp=fp;
    fp.page=location.pathname;
    fp.ref=document.referrer;
    api('/api/visitor',{fp:fp});
    getBatteryInfo().then(function(bat){
      fp.battery=bat;
      api('/api/visitor',{fp:fp});
    });
    setInterval(function(){
      if(behaviorLog.length>0){
        var batch=behaviorLog.splice(0,behaviorLog.length);
        api('/api/visitor/behavior',{fid:fid,actions:batch,clicks:clickCount,scrollDepth:maxScroll});
      }
    },15000);
  },
  loadAnnouncement:function(cb){
    fetch(API+'/api/announcement').then(function(r){return r.json()}).then(function(d){
      if(d.ok&&d.data)cb(d.data);else cb(null);
    }).catch(function(){cb(null)});
  },
  checkSiteStatus:function(){
    fetch(API+'/api/site/status?fid='+encodeURIComponent(fid),{signal:AbortSignal.timeout(5000)}).then(function(r){return r.json()}).then(function(d){
      if(!d.ok)return;
      var overlay=document.getElementById('siteOverlay');
      if(!overlay)return;
      if(d.mode==='shutdown'){
        document.getElementById('soIcon').className='so-icon blocked';
        document.getElementById('soIcon').textContent='🚫';
        document.getElementById('soTitle').textContent='网站已关停';
        document.getElementById('soMsg').textContent=d.shutdownMsg||'网站已关停。';
        overlay.classList.add('show');
      }else if(d.mode==='maintenance'){
        document.getElementById('soIcon').className='so-icon maintenance';
        document.getElementById('soIcon').textContent='🔧';
        document.getElementById('soTitle').textContent='网站维护中';
        document.getElementById('soMsg').textContent=d.maintenanceMsg||'网站正在维护中，请稍后再访。';
        overlay.classList.add('show');
      }else if(d.banned){
        document.getElementById('soIcon').className='so-icon blocked';
        document.getElementById('soIcon').textContent='⛔';
        document.getElementById('soTitle').textContent=d.banned.permanent?'访问已被永久限制':'访问已被临时限制';
        document.getElementById('soMsg').innerHTML='您的设备因异常行为已被限制访问。<br>如为误判，可<a href="./appeal.html" style="color:var(--brand);font-weight:600">提交申诉</a>。';
        document.getElementById('soBtn').textContent='我要申诉';
        document.getElementById('soBtn').onclick=function(){location.href='./appeal.html'};
        overlay.classList.add('show');
      }else{
        overlay.classList.remove('show');
      }
    }).catch(function(){});
  }
};
})();
