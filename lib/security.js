const crypto=require('crypto');
const db=require('./db');
const enc=require('./crypto');

function getClientIp(req){
  const xff=(req.headers['x-forwarded-for']||'').split(',')[0].trim();
  return xff||req.headers['x-real-ip']||(req.connection&&req.connection.remoteAddress)||'0.0.0.0';
}
function hash(s){return crypto.createHash('sha256').update(s).digest('hex')}

async function isBanned(ip,fid){
  const ipBan=await db.sismember('banned:ips',ip);
  if(ipBan){
    const bans=await db.lrange('bans:list',0,-1);
    const b=bans.find(x=>x.ip===ip&&x.active);
    if(b&&b.type==='permanent')return{ip:true,permanent:true};
    if(b&&b.expires&&Date.now()>b.expires){await unbanByIp(ip);return false}
    return{ip:true};
  }
  if(fid){
    const fidBan=await db.sismember('banned:fids',fid);
    if(fidBan)return{fid:true};
  }
  return false;
}

async function ban(ip,fid,reason,type,opts){
  opts=opts||{};
  const entry={
    id:'ban_'+Date.now().toString(36)+Math.random().toString(36).slice(2,5),
    ip,fid,reason,
    type:type||'temporary',
    time:Date.now(),
    expires:type==='permanent'?null:Date.now()+86400000,
    active:true,
    appealCount:0
  };
  await db.lpush('bans:list',entry);
  await db.sadd('banned:ips',ip);
  if(fid)await db.sadd('banned:fids',fid);
  await logSecurityEvent('ban',`[${type==='permanent'?'永久':'临时'}] 封禁 ${enc.maskIP(ip)} - ${reason}`,{ip,fid,reason,type});
  if(!opts.silent){
    try{
      const email=require('./email');
      await email.securityAlert({
        type:type==='permanent'?'永久封禁':'临时封禁',
        message:`IP: ${enc.maskIP(ip)}\n设备: ${fid?enc.hashFp(fid):'未知'}\n原因: ${reason}\n类型: ${type==='permanent'?'永久':'临时24小时'}\n时间: ${new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}`,
        meta:{ip,fid}
      });
    }catch(e){}
  }
  return entry;
}

async function unban(id){
  const bans=await db.lrange('bans:list',0,-1);
  const target=bans.find(b=>b.id===id);
  const updated=bans.map(b=>{if(b.id===id){b.active=false;b.unbannedAt=Date.now();return b}return b});
  await db.del('bans:list');
  for(let i=updated.length-1;i>=0;i--)await db.lpush('bans:list',updated[i]);
  if(target){
    await db.srem('banned:ips',target.ip);
    if(target.fid)await db.srem('banned:fids',target.fid);
    await logSecurityEvent('unban',`解封 ${enc.maskIP(target.ip)}`,{ip:target.ip});
  }
}

async function unbanByIp(ip){
  const bans=await db.lrange('bans:list',0,-1);
  const updated=bans.map(b=>{if(b.ip===ip&&b.active){b.active=false;b.unbannedAt=Date.now();return b}return b});
  await db.del('bans:list');
  for(let i=updated.length-1;i>=0;i--)await db.lpush('bans:list',updated[i]);
  await db.srem('banned:ips',ip);
  await logSecurityEvent('unban',`按申诉解封 ${enc.maskIP(ip)}`,{ip});
}

const ATTACK_PATTERNS=[
  {name:'SQL注入',regex:/(\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|or\s+1=1|and\s+1=1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|sysobjects|pg_sleep|char\s*\(\s*39)\b)/i},
  {name:'XSS攻击',regex:/(<script[\s>]|javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|<iframe|document\.cookie|window\.location\s*=|String\.fromCharCode)/i},
  {name:'路径穿越',regex:/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|etc\/passwd|etc\/shadow|proc\/self|win\.ini|\/\.\.\/)/i},
  {name:'命令注入',regex:/(;|\||`|\$\()(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|rm|chmod|chown|powershell|cmd\.exe)\s/i},
  {name:'敏感文件探测',regex:/(\.env($|[^a-z])|\.git\/|wp-admin|phpmyadmin|\.aws\/|config\.php|\.ssh\/|id_rsa|\.npmrc|\.dockerenv|composer\.json|package-lock|\.htaccess|web\.config|\.svn\/|\.hg\/|backup\.zip|\.sql$|database\.yml)/i},
  {name:'爬虫/扫描器',regex:/(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|acunetix|nessus|burp|fuzz|dirsearch|arachni|w3af|openvas|whatweb|wappalyzer|nuclei|xray|awvs)/i},
  {name:'恶意UA/脚本',regex:/(python-requests|go-http-client|libwww-perl|scrapy|httpclient|okhttp|java\/[0-9]|php\/[0-9]|node-fetch|axios\/0\.|powershell|winhttp|httrack)/i},
  {name:'XXE/LFI',regex:/(<!ENTITY|<!DOCTYPE|php:\/\/filter|data:\/\/text|file:\/\/\/|expect:\/\/)/i},
  {name:'SSRF探测',regex:/(169\.254\.169\.254|metadata\.google|100\.100\.100\.200|0\.0\.0\.0:80|127\.0\.0\.1:|localhost:)/i},
  {name:'WebShell',regex:/(eval\s*\(\s*\$_|assert\s*\(\s*\$_|\$_POST\s*\[|\$_GET\s*\[|\$_REQUEST\s*\[|base64_decode\s*\(|gzinflate\s*\(|str_rot13|preg_replace\s*\(.+\/[a-z]*e[a-z]*\/)/i},
  {name:'CSRF/会话劫持',regex:/(<form[^>]+action|crossdomain\.xml|clientaccesspolicy\.xml|\.well-known\/security)/i},
  {name:'目录枚举',regex:/(\/wp-admin|\/phpmyadmin|\/administrator\/|\/manager\/html|\/debug\/|\/test\.php|\/info\.php|\/phpinfo|\/server-status|\/actuator\/|\/solr\/|\/jenkins\/|\/struts|\/jmx-console)/i},
  {name:'CORS探测',regex:/(access-control-allow-origin|origin:\s*null|\$\.ajax|xmlhttprequest)/i}
];

function detectAttack(req){
  const ua=req.headers['user-agent']||'';
  const url=req.url||'';
  const checks=[ua,url];
  if(req.body&&typeof req.body==='object')checks.push(JSON.stringify(req.body));
  else if(typeof req.body==='string')checks.push(req.body);
  for(const p of ATTACK_PATTERNS){
    for(const c of checks){if(p.regex.test(c))return p.name}
  }
  return null;
}

function detectAnomaly(req,fp){
  const signals=[];
  const ua=req.headers['user-agent']||'';
  if(/headless|phantom|selenium|puppeteer|playwright|webdriver|chromedriver/i.test(ua))signals.push('无头浏览器');
  if(fp){
    if(fp.webdriver)signals.push('WebDriver标记');
    if(fp.touchSupport===false&&/mobile|android|iphone/i.test(ua))signals.push('移动端无触控');
    if(fp.languages===''&&!/(bot|crawler|spider)/i.test(ua))signals.push('无语言设置');
  }
  return signals;
}

async function rateLimit(key,max,window){
  const now=Date.now();
  const rlKey='rl:'+key;
  const data=await db.get(rlKey)||{count:0,reset:now+window};
  if(now>data.reset){data.count=0;data.reset=now+window}
  data.count++;
  await db.set(rlKey,data,Math.ceil(window/1000));
  return{limited:data.count>max,remaining:Math.max(0,max-data.count),reset:data.reset,count:data.count};
}

async function addWarning(ip,fid,reason){
  const key='warnings:'+ip;
  const warnings=await db.get(key)||{count:0,history:[]};
  warnings.count++;
  warnings.history.push({reason,time:Date.now()});
  if(warnings.history.length>10)warnings.history=warnings.history.slice(-10);
  await db.set(key,warnings,86400);
  await logSecurityEvent('warning',`警告 ${warnings.count}/3 - ${enc.maskIP(ip)} - ${reason}`,{ip,fid,reason,warningCount:warnings.count});
  return warnings.count;
}

async function resetWarnings(ip){
  await db.del('warnings:'+ip);
}

async function logSecurityEvent(type,message,meta){
  const entry={
    id:'evt_'+Date.now().toString(36)+Math.random().toString(36).slice(2,6),
    type,message,
    meta:meta?{
      ip:meta.ip?enc.maskIP(meta.ip):undefined,
      fid:meta.fid?enc.hashFp(meta.fid):undefined,
      reason:meta.reason,
      type:meta.type,
      attack:meta.attack
    }:{},
    time:Date.now(),
    timeStr:new Date().toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})
  };
  await db.lpush('events:list',entry);
  await db.ltrim('events:list',0,499);
  const day=new Date().toISOString().slice(0,10);
  if(type==='attack'||type==='ban'||type==='blocked'){
    await db.incr('stats:attacks:'+day);
    await db.incr('stats:attacks:total');
  }
  return entry;
}

async function logVisitor(ip,fp,page,ref){
  const day=shDate();
  const hour=shHour();
  await db.incr('stats:visitors:'+day);
  await db.incr('stats:visitors:hour:'+hour);
  await db.incr('stats:visitors:total');
  if(page)await db.incr('stats:page:'+page);
  const isMobile=/mobile|android|iphone|ipad|ipod/i.test(fp.ua||'');
  if(isMobile)await db.incr('stats:mobile:'+day);else await db.incr('stats:desktop:'+day);
  const browser=getBrowser(fp.ua);
  if(browser)await db.incr('stats:browser:'+browser);
  const dev=getDeviceDetail(fp.ua);
  const scr=fp.screen||{};
  const net=fp.network||{};
  const wgl=fp.webgl||{};
  const entry={
    id:'v_'+Date.now().toString(36),
    ip:ip,
    ipMasked:enc.maskIP(ip),
    fid:enc.hashFp(fp.fid),
    ua:fp.ua?fp.ua.substring(0,300):'',
    browser:browser+' / '+getOS(fp.ua),
    os:getOS(fp.ua),
    brand:dev.brand,
    model:dev.model,
    kernel:dev.kernel,
    androidVer:dev.androidVer,
    iosVer:dev.iosVer,
    platform:fp.platform||'',
    language:fp.language||'',
    languages:fp.languages||'',
    timezone:fp.timezone||'',
    tzOffset:fp.timezoneOffset||0,
    online:fp.online!==false,
    screen:scr.width?scr.width+'x'+scr.height+'@'+(scr.dpr||1)+'x':'',
    screenW:scr.width||0,screenH:scr.height||0,dpr:scr.dpr||1,
    colorDepth:scr.colorDepth||0,
    orientation:scr.orientation||'',
    viewport:fp.viewport?fp.viewport.width+'x'+fp.viewport.height:'',
    cores:fp.cores||0,
    memory:fp.memory||0,
    touchPoints:fp.touchPoints||0,
    network:net.type||'',
    downlink:net.downlink||0,
    rtt:net.rtt||0,
    gpu:wgl.renderer?String(wgl.renderer).substring(0,80):'',
    canvasHash:fp.canvasHash||'',
    colorScheme:fp.colorScheme||'',
    battery:fp.battery?fp.battery.level+'%'+(fp.battery.charging?'(充电中)':''):'',
    cookieEnabled:fp.cookieEnabled!==false,
    doNotTrack:fp.doNotTrack||'',
    fonts:(fp.fonts||[]).slice(0,8).join(','),
    plugins:(fp.plugins||[]).slice(0,8).join(','),
    page:page||'/',
    ref:ref||'',
    referrer:fp.referrer||'',
    clicks:0,
    maxScroll:0,
    duration:0,
    actions:[],
    time:Date.now(),
    timeStr:new Date().toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false})
  };
  await db.lpush('visitors:recent',entry);
  await db.ltrim('visitors:recent',0,199);
  return entry;
}

function getBrowser(ua){
  if(!ua)return'未知';
  var v='';
  var vm;
  var isWebView=/;\s*wv\)/i.test(ua)||/MQQBrowser/i.test(ua);
  if(/V1_AND_SQ_[\d.]+/.test(ua))return'QQ内置浏览器';
  if(/doubao/i.test(ua))return'豆包WebView';
  if(/EdgA?\/([\d.]+)/i.test(ua)){vm=ua.match(/EdgA?\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Edge'+(v?' '+v:'')}
  if(/QQBrowser\/([\d.]+)/i.test(ua)){vm=ua.match(/QQBrowser\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'QQ浏览器'+(v?' '+v:'')}
  if(/MicroMessenger\/([\d.]+)/i.test(ua)){vm=ua.match(/MicroMessenger\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'微信内置'+(v?' '+v:'')}
  if(/MiuiBrowser\/([\d.]+)/i.test(ua)){vm=ua.match(/MiuiBrowser\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'小米浏览器'+(v?' '+v:'')}
  if(/HuaweiBrowser\/([\d.]+)/i.test(ua)){vm=ua.match(/HuaweiBrowser\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'华为浏览器'+(v?' '+v:'')}
  if(/SamsungBrowser\/([\d.]+)/i.test(ua)){vm=ua.match(/SamsungBrowser\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'三星浏览器'+(v?' '+v:'')}
  if(/VivoBrowser/i.test(ua))return'vivo浏览器';
  if(/OppoBrowser/i.test(ua))return'OPPO浏览器';
  if(/HeyTapBrowser/i.test(ua))return'HeyTap浏览器';
  if(/UCBrowser\/([\d.]+)/i.test(ua)){vm=ua.match(/UCBrowser\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'UC浏览器'+(v?' '+v:'')}
  if(/baidubrowser/i.test(ua))return'百度浏览器';
  if(/360se|360ee/i.test(ua))return'360浏览器';
  if(/liebao/i.test(ua))return'猎豹浏览器';
  if(/sogou/i.test(ua))return'搜狗浏览器';
  if(/maxthon/i.test(ua))return'遨游浏览器';
  if(/OPR\/([\d.]+)|Opera\/([\d.]+)/i.test(ua)){vm=ua.match(/(?:OPR|Opera)\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Opera'+(v?' '+v:'')}
  if(/Firefox\/([\d.]+)|FxiOS\/([\d.]+)/i.test(ua)){vm=ua.match(/(?:Firefox|FxiOS)\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Firefox'+(v?' '+v:'')}
  if(/CriOS\/([\d.]+)/i.test(ua)){vm=ua.match(/CriOS\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Chrome'+(v?' '+v:'')}
  if(/Chrome\/([\d.]+)/i.test(ua)){vm=ua.match(/Chrome\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Chrome'+(v?' '+v:'')+(isWebView?' (WebView)':'')}
  if(/Version\/([\d.]+).*Safari/i.test(ua)){vm=ua.match(/Version\/([\d.]+)/i);v=vm?vm[1].split('.')[0]:'';return'Safari'+(v?' '+v:'')+(isWebView?' (WebView)':'')}
  return'其他'+(isWebView?' (WebView)':'');
}
function getOS(ua){
  if(!ua)return'未知';
  if(/Android 15/i.test(ua))return'Android 15';
  if(/Android 14/i.test(ua))return'Android 14';
  if(/Android 13/i.test(ua))return'Android 13';
  if(/Android 12/i.test(ua))return'Android 12';
  if(/Android 11/i.test(ua))return'Android 11';
  if(/Android 10/i.test(ua))return'Android 10';
  if(/Android ([\d.]+)/i.test(ua)){var m=ua.match(/Android ([\d.]+)/i);return'Android '+(m?m[1]:'')}
  if(/iPhone OS 18/i.test(ua))return'iOS 18';
  if(/iPhone OS 17/i.test(ua))return'iOS 17';
  if(/iPhone OS 16/i.test(ua))return'iOS 16';
  if(/iPhone OS ([\d_]+)/i.test(ua)){var m=ua.match(/iPhone OS ([\d_]+)/i);var ver=m?m[1].replace(/_/g,'.'):'';if(ver.endsWith('.0'))ver=ver.slice(0,-2);return'iOS '+ver}
  if(/iPad.*OS ([\d_]+)/i.test(ua)){var m=ua.match(/OS ([\d_]+)/i);return'iPadOS '+(m?m[1].replace(/_/g,'.'):'')}
  if(/Windows NT 10.0/i.test(ua)){
    if(/Chrome\/(?:1[2-9]\d|[2-9]\d{2})/i.test(ua))return'Windows 11';
    return'Windows 10/11';
  }
  if(/Windows NT 6.3/i.test(ua))return'Windows 8.1';
  if(/Windows NT 6.2/i.test(ua))return'Windows 8';
  if(/Windows NT 6.1/i.test(ua))return'Windows 7';
  if(/Windows/i.test(ua))return'Windows';
  if(/Mac OS X ([\d_]+)/i.test(ua)){var m=ua.match(/Mac OS X ([\d_]+)/m);return'macOS '+(m?m[1].replace(/_/g,'.'):'')}
  if(/Macintosh/i.test(ua))return'macOS';
  if(/Linux/i.test(ua))return'Linux';
  if(/HarmonyOS|OpenHarmony/i.test(ua))return'HarmonyOS';
  return'未知';
}
function getDeviceDetail(ua){
  if(!ua)return{brand:'',model:'',kernel:'',androidVer:'',iosVer:''};
  var brand='',model='',kernel='',androidVer='',iosVer='';
  // Android version
  var am=ua.match(/Android\s([\d.]+)/);if(am)androidVer=am[1];
  // iOS version
  var im=ua.match(/OS\s([\d_]+)/);if(im)iosVer=im[1].replace(/_/g,'.');
  // Kernel version
  var km=ua.match(/Linux[;\s][^)]*?(\d+\.\d+\.\d+[-\w.]*)/i);if(km)kernel=km[1];
  // Phone brand/model from UA
  var bm=ua.match(/Android[\s\d.]+;\s*([^;)]+?)(?:\s+Build|\)|;)/i);
  if(bm){
    var raw=bm[1].trim();
    // Known brands
    var brands={
      'Redmi':'Redmi','XiaoMi':'Xiaomi','MI ':'Xiaomi','Mi ':'Xiaomi','Xiaomi':'Xiaomi','POCO':'POCO',
      'HUAWEI':'Huawei','Huawei':'Huawei','HONOR':'HONOR','Honor':'HONOR','HBLD':'Huawei',
      'OPPO':'OPPO','OnePlus':'OnePlus','vivo':'vivo','VIVO':'vivo','iQOO':'iQOO','iQOO ':'iQOO',
      'samsung':'Samsung','SAMSUNG':'Samsung','SM-':'Samsung','GT-':'Samsung','SGH':'Samsung',
      'Sony':'Sony','Xperia':'Sony','SO-':'Sony','LG':'LG','LM-':'LG','Nokia':'Nokia',
      'Pixel':'Google Pixel','Pixel ':'Google Pixel',
      'realme':'realme','Realme':'realme','RMX':'realme',
      'MEIZU':'Meizu','Meizu':'Meizu','MZ-':'Meizu','m3 note':'Meizu','m1 note':'Meizu',
      'ZTE':'ZTE','nubia':'nubia','Nubia':'nubia','NX':'nubia',
      'Lenovo':'Lenovo','LNV':'Lenovo','Legion':'Lenovo','拯救者':'Lenovo',
      'Motorola':'Motorola','moto':'Motorola','XT':'Motorola',
      'Infinix':'Infinix','TECNO':'TECNO','Itel':'itel',
      'ASUS':'ASUS','Asus':'ASUS','ZenFone':'ASUS','ROG':'ASUS',
      'HTC':'HTC','Sharp':'Sharp','Aquos':'Sharp',
      'Hisense':'Hisense','TCL':'TCL','Alcatel':'Alcatel',
      'OnePlus':'OnePlus','GM19':'OnePlus','IN2':'OnePlus','KB2':'OnePlus','LE2':'OnePlus','CPH':'OnePlus'
    };
    for(var b in brands){
      if(raw.toLowerCase().indexOf(b.toLowerCase())===0||raw.indexOf(b)===0){
        brand=brands[b];
        model=raw.replace(new RegExp(b,'i'),'').trim();
        break;
      }
    }
    // Model number database lookup (even if brand found)
    var modelDbMatched=false;
    var xiaomiModels={
      '23077RABDC':'Redmi 12 5G','23076RA4BR':'Redmi 12','23053RN02Y':'Redmi Note 12R',
      '2201116SG':'Redmi Note 11','2201117TG':'Redmi Note 11S','22101316G':'Redmi Note 12',
      '23021RAAEG':'Redmi Note 12','22101316UCP':'Redmi Note 12 Pro','22101316G':'Redmi Note 12',
      '23090RA98C':'Redmi Note 13','23117RA68G':'Redmi Note 13 Pro','24040RN64C':'Redmi Note 13R',
      '23129RAA4G':'Redmi K70','23117RK66C':'Redmi K70 Pro','24013RK75C':'Redmi K70E',
      '22081212C':'Xiaomi 12T Pro','2211133G':'Xiaomi 13','2304FPN6DC':'Xiaomi 13 Pro',
      '2304FPN6DG':'Xiaomi 13 Ultra','23127PN0CC':'Xiaomi 14','24031PN0DC':'Xiaomi 14 Pro',
      '24030PN60G':'Xiaomi 14 Ultra','23116PN5BC':'Xiaomi Pad 6','24018RPACC':'Redmi Turbo 3',
      '24053PY09C':'Xiaomi Civi 4 Pro','2407FRK8EC':'Redmi K70 Ultra'
    };
    var huaweiModels={
      'ALN-AL00':'Mate 60 Pro','ALN-AL10':'Mate 60','BRA-AL00':'Mate 60 RS',
      'BNE-AL00':'Mate 50','CET-AL00':'Mate 50 Pro','DCO-AL00':'Mate 50 RS',
      'ADT-AL00':'P60 Art','LNA-AL00':'P60 Pro','MNA-AL00':'P60',
      'HBN-AL00':'Pocket 2','LEM-AL00':'P50 Pocket','ABR-AL00':'P50 Pro',
      'JAD-AL50':'P50 Pro','NAM-AL00':'nova 12','ADA-AL00':'nova 12 Pro',
      'BLK-AL00':'nova 12 Ultra','FIN-AL60':'nova 11','GOA-AL80':'nova 11 Pro',
      'RKY-AL00':'MatePad Pro 11','TGR-AL00':'MatePad Pro 13.2'
    };
    var honorModels={
      'PGT-AN00':'Magic5 Pro','PGT-AN10':'Magic5','PGT-AN20':'Magic5 Ultimate',
      'BVL-AN16':'Magic6 Pro','BVL-AN00':'Magic6','AN00':'Magic V2',
      'FCP-AN10':'90 GT','MAA-AN10':'90 Pro','REA-AN00':'100 Pro',
      'ELI-AN00':'200 Pro','NTH-AN00':'50','RMO-AN00':'70 Pro'
    };
    var oppoModels={
      'PHZ110':'Find X7','PHZ120':'Find X7 Ultra','PJE110':'Find X6 Pro',
      'PGFM10':'Find X6','PJH110':'Reno11 Pro','PJJ110':'Reno11',
      'PKB110':'Reno12 Pro','PJW110':'Reno12','PKX110':'K12'
    };
    var vivoModels={
      'V2309A':'X100 Pro','V2324A':'X100','V2359A':'X100 Ultra',
      'V2318A':'S18 Pro','V2323A':'S18','V2334A':'iQOO 12 Pro',
      'V2307A':'iQOO 12','V2329A':'iQOO Neo9','V2348A':'iQOO Z9 Turbo'
    };
    var samsungModels={
      'SM-S928':'Galaxy S24 Ultra','SM-S926':'Galaxy S24+','SM-S921':'Galaxy S24',
      'SM-S918':'Galaxy S23 Ultra','SM-S916':'Galaxy S23+','SM-S911':'Galaxy S23',
      'SM-A546':'Galaxy A54','SM-A536':'Galaxy A53','SM-A346':'Galaxy A34',
      'SM-F946':'Galaxy Z Fold5','SM-F731':'Galaxy Z Flip5','SM-F956':'Galaxy Z Fold6'
    };
    var modelNum=raw.toUpperCase().trim();
    if(xiaomiModels[modelNum]){brand='Xiaomi';model=xiaomiModels[modelNum];modelDbMatched=true}
    else if(huaweiModels[modelNum]){brand='Huawei';model=huaweiModels[modelNum];modelDbMatched=true}
    else if(honorModels[modelNum]){brand='HONOR';model=honorModels[modelNum];modelDbMatched=true}
    else if(oppoModels[modelNum]){brand='OPPO';model=oppoModels[modelNum];modelDbMatched=true}
    else if(vivoModels[modelNum]){brand='vivo';model=vivoModels[modelNum];modelDbMatched=true}
    else if(samsungModels[modelNum.substring(0,7)]){brand='Samsung';model=samsungModels[modelNum.substring(0,7)];modelDbMatched=true}

    // Xiaomi/Redmi model number patterns
    if(!modelDbMatched && !brand){
      // Fallback: numeric model numbers
      var modelNum=raw.toUpperCase().trim();
      if(/^2\d{4}[A-Z]/.test(modelNum)||/^\d{4}[A-Z]/.test(modelNum)){
        if(/M[QN]|REDMI|HM/i.test(ua)){brand='Redmi';model=modelNum}
        else if(/MI/i.test(ua)){brand='Xiaomi';model=modelNum}
        else{model=modelNum}
      }
    }
    if(!brand){
      // Try Build pattern
      var bm2=ua.match(/;\s*([^;)]+?)\s+Build\//);
      if(bm2){
        raw=bm2[1].trim();
        var parts=raw.split(/\s+/);
        if(parts.length>=2){brand=parts[0];model=parts.slice(1).join(' ')}
        else{model=raw}
      }else{model=raw.substring(0,40)}
    }
  }
  // iPhone model detection
  if(/iPhone/.test(ua)){
    brand='Apple';
    var pm=ua.match(/iPhone(\d+,\d+)/);
    var iphoneModels={
      '14,2':'iPhone 13 Pro','14,3':'iPhone 13 Pro Max','14,4':'iPhone 13 mini','14,5':'iPhone 13',
      '15,2':'iPhone 14','15,3':'iPhone 14 Plus','15,4':'iPhone 14 Pro','15,5':'iPhone 14 Pro Max',
      '16,1':'iPhone 15 Pro','16,2':'iPhone 15 Pro Max','17,1':'iPhone 15','17,2':'iPhone 15 Plus',
      '17,3':'iPhone 16','17,4':'iPhone 16 Plus','18,1':'iPhone 16 Pro','18,2':'iPhone 16 Pro Max'
    };
    model=pm?(iphoneModels[pm[1]]||'iPhone'):'iPhone';
  }
  if(/iPad/.test(ua)){brand='Apple';model='iPad'}
  if(/Macintosh/.test(ua)){brand='Apple';model='Mac'}
  if(/Windows/.test(ua)){brand='PC';model='Windows PC'}
  return{brand:brand,model:model,kernel:kernel,androidVer:androidVer,iosVer:iosVer};
}

module.exports={getClientIp,hash,isBanned,ban,unban,unbanByIp,detectAttack,detectAnomaly,rateLimit,addWarning,resetWarnings,logSecurityEvent,logVisitor,getBrowser,getOS,getDeviceDetail};
