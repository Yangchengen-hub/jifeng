(function(){
  var API_BASE=window.JF_API||'';
  function $(s){return document.querySelector(s)}
  function toast(msg,dur){
    var t=document.getElementById('toast')||document.createElement('div');
    t.id='toast';t.className='toast';t.textContent=msg;document.body.appendChild(t);
    requestAnimationFrame(function(){t.classList.add('show')});
    setTimeout(function(){t.classList.remove('show')},dur||3000);
  }
  function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
  function api(path,opts){
    opts=opts||{};opts.headers=opts.headers||{};opts.headers['Content-Type']='application/json';
    return fetch(API_BASE+path,opts).then(function(r){return r.json().catch(function(){return{ok:r.ok}})}).catch(function(){return{ok:false,error:'网络错误'}});
  }

  function fp(){
    var n=navigator,s=screen,w=window;
    var canvas=document.createElement('canvas');
    var gl=canvas.getContext('webgl')||canvas.getContext('experimental-webgl');
    var glInfo={};
    try{if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');glInfo={renderer:gl.getParameter(dbg?dbg.UNMASKED_RENDERER_WEBGL:0),vendor:gl.getParameter(dbg?dbg.UNMASKED_VENDOR_WEBGL:0)}}}catch(e){}
    var tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'unknown';
    var data={
      ua:n.userAgent,
      platform:n.platform||'',
      lang:n.language||'',
      langs:(n.languages||[]).join(','),
      tz:tz,
      tzOffset:new Date().getTimezoneOffset(),
      screen:s.width+'x'+s.height+'x'+s.colorDepth,
      avail:s.availWidth+'x'+s.availHeight,
      dpr:w.devicePixelRatio||1,
      cores:n.hardwareConcurrency||0,
      mem:n.deviceMemory||0,
      touch:('ontouchstart' in w)||n.maxTouchPoints>0,
      points:n.maxTouchPoints||0,
      webdriver:n.webdriver||false,
      gl:JSON.stringify(glInfo),
      plugins:Array.prototype.map.call(n.plugins||[],function(p){return p.name}).join(','),
      fonts:(function(){
        var c=document.createElement('canvas').getContext('2d');var fs=['Arial','Courier New','Georgia','Times New Roman','Verdana','monospace','sans-serif'];
        return fs.filter(function(f){c.font='72px "'+f+'"';var w1=c.measureText('mmmmmmmmmmlli').width;c.font='72px monospace';var w2=c.measureText('mmmmmmmmmmlli').width;return w1!==w2}).join(',');
      })()
    };
    var str=JSON.stringify(data);
    var hash=0;
    for(var i=0;i<str.length;i++){hash=((hash<<5)-hash)+str.charCodeAt(i);hash|=0}
    data.fid='jf_'+Math.abs(hash).toString(36)+'_'+Date.now().toString(36);
    return data;
  }

  var visitorTracked=false;
  function trackVisitor(){
    if(visitorTracked)return;visitorTracked=true;
    var f=fp();
    api('/api/visitor',{method:'POST',body:JSON.stringify({fp:f,page:location.pathname,ref:document.referrer})});
    document.addEventListener('visibilitychange',function(){
      if(document.visibilityState==='hidden'){navigator.sendBeacon&&navigator.sendBeacon(API_BASE+'/api/visitor/leave',JSON.stringify({fid:f.fid}))}
    });
  }

  function loadAnnouncement(cb){
    api('/api/announcement').then(function(d){if(d&&d.ok&&d.data)cb(d.data);else cb(null)}).catch(function(){cb(null)});
  }

  function antiDebug(){
    var warned=false;
    setInterval(function(){
      var start=performance.now();debugger;var end=performance.now();
      if(end-start>100&&!warned){warned=true;api('/api/security/event',{method:'POST',body:JSON.stringify({type:'devtools',fp:fp()})});toast('检测到调试工具，已记录');}
    },4000);
    document.addEventListener('contextmenu',function(e){e.preventDefault();toast('右键已禁用')});
    document.addEventListener('keydown',function(e){
      if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&(e.key==='I'||e.key==='J'||e.key==='C'))||(e.ctrlKey&&e.key==='u')){e.preventDefault();toast('该操作已被禁用')}
    });
  }

  window.JF={$:$ ,toast:toast,esc:esc,api:api,fp:fp,trackVisitor:trackVisitor,loadAnnouncement:loadAnnouncement,antiDebug:antiDebug};
})();
