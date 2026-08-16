/* ============================================
   极风工作室 Jifeng Studio v7.0
   Frontend utilities — NO sensitive logic here.
   All auth, validation, data processing runs
   server-side via /api/* serverless functions.
   ============================================ */

/* ---- Time helpers ---- */
function nowCST(){return new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});}
function nowTime(){return new Date().toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});}

/* ---- HTML escape (XSS protection) ---- */
function esc(s){
  if(s===null||s===undefined)return'';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ---- Device fingerprint (non-sensitive, for logging only) ---- */
function deviceInfo(){
  var ua=navigator.userAgent||'';
  var isMobile=/Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  var os=isMobile?'mobile':'desktop';
  var browser=/Chrome/i.test(ua)?'Chrome':/Firefox/i.test(ua)?'Firefox':/Safari/i.test(ua)?'Safari':/Edg/i.test(ua)?'Edge':'Other';
  return{isMobile:isMobile,os:os,browser:browser,ua:ua,screen:screen.width+'x'+screen.height,lang:navigator.language||''};
}

/* ---- API helper (all requests go through serverless functions) ---- */
async function api(path,opts){
  opts=opts||{};
  opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{});
  try{
    var r=await fetch(path,opts);
    return await r.json();
  }catch(e){return{success:false,error:'网络错误，请稍后重试'};}
}

/* ---- Toast notification ---- */
function toast(msg,type){
  var t=document.getElementById('toast');
  if(!t){t=document.createElement('div');t.id='toast';t.className='toast';document.body.appendChild(t);}
  t.textContent=msg;t.className='toast show '+(type||'');
  clearTimeout(t._timer);t._timer=setTimeout(function(){t.className='toast';},3000);
}

/* ---- Scroll reveal ---- */
function initReveal(){
  try{
    var IO=new IntersectionObserver(function(entries){
      entries.forEach(function(e){if(e.isIntersecting){e.target.classList.add('v');IO.unobserve(e.target);}});
    },{threshold:0.1});
    document.querySelectorAll('.card,.section-title,.hero-badge').forEach(function(el){IO.observe(el);});
  }catch(e){}
}

/* ---- Mobile menu ---- */
function initMenu(){
  var btn=document.getElementById('menuBtn');
  if(btn)btn.addEventListener('click',function(){
    document.getElementById('navMenu').classList.toggle('open');
  });
}

/* ---- Log visitor (server-side records IP, geo, etc.) ---- */
function logVisitor(){
  var info=deviceInfo();
  api('/api/visitor',{method:'POST',body:JSON.stringify({page:location.pathname,device:info.os,browser:info.browser,screen:info.screen,lang:info.lang})});
}

/* ---- Init on load ---- */
document.addEventListener('DOMContentLoaded',function(){
  initReveal();
  initMenu();
  logVisitor();
});
