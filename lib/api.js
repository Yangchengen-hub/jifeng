const sec=require('../lib/security');
const db=require('../lib/db');

function setSecurityHeaders(res){
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('X-XSS-Protection','1;mode=block');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','geolocation=(),microphone=(),camera=()');
}

function cors(res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization,X-Captcha,X-Fp');
  res.setHeader('Access-Control-Max-Age','86400');
}

function json(res,data,status){
  cors(res);setSecurityHeaders(res);
  res.statusCode=status||200;res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify(data));
}

async function parseBody(req){
  return new Promise(function(resolve){
    let body='';req.on('data',c=>body+=c);req.on('end',function(){
      try{resolve(JSON.parse(body||'{}'))}catch(e){resolve({})}
    });req.on('error',()=>resolve({}));
  });
}

async function handler(req,res,fn,opts){
  opts=opts||{};
  cors(res);setSecurityHeaders(res);
  if(req.method==='OPTIONS')return json(res,{ok:true});
  req.body=await parseBody(req);
  const ip=sec.getClientIp(req);
  req.clientIp=ip;
  const fid=(req.body.fp&&req.body.fp.fid)||req.body.fid||req.headers['x-fp']||'';

  const banned=await sec.isBanned(ip,fid);
  if(banned&&!opts.skipBan){
    await sec.logSecurityEvent('blocked','已封禁IP/设备尝试访问 '+req.url,{ip,fid});
    return json(res,{
      ok:false,banned:true,permanent:!!banned.permanent,
      error:banned.permanent?'您的访问已被永久限制':'您的访问已被限制，如有异议请提交申诉',
      appealUrl:'./appeal.html'
    },403);
  }

  if(!opts.skipRateLimit){
    const rl=await sec.rateLimit(ip+':'+(opts.rateKey||req.url),opts.rateMax||60,opts.rateWindow||60000);
    if(rl.limited){
      const wc=await sec.addWarning(ip,fid,'频率限制触发');
      if(wc>=3){
        await sec.ban(ip,fid,'触发频率限制3次警告','temporary');
        return json(res,{ok:false,banned:true,error:'因多次异常行为已被临时封禁'},403);
      }
      return json(res,{ok:false,warning:true,warningCount:wc,error:'请求过于频繁（警告'+wc+'/3）'},429);
    }
  }

  if(!opts.skipAttackCheck){
    const attack=sec.detectAttack(req);
    if(attack){
      const anomalies=sec.detectAnomaly(req,req.body.fp);
      const reason=attack+(anomalies.length?' ('+anomalies.join(',')+')':'');
      const wc=await sec.addWarning(ip,fid,reason);
      if(wc>=3){
        const isRepeat=await db.get('repeat:'+ip);
        await sec.ban(ip,fid,attack+' (3次警告后封禁)',isRepeat?'permanent':'temporary');
        if(isRepeat){
          try{const email=require('./email');await email.securityAlert({type:'二次违规永久封禁',message:'IP: '+ip+' 解封后再次攻击，已永久封禁',meta:{ip,fid}})}catch(e){}
        }
        return json(res,{ok:false,banned:true,permanent:!!isRepeat,error:'因多次攻击行为已被'+(isRepeat?'永久':'临时')+'封禁'},403);
      }
      return json(res,{ok:false,warning:true,warningCount:wc,warningMax:3,error:'检测到异常请求（警告'+wc+'/3），继续将被封禁'},403);
    }
    const anomalies=sec.detectAnomaly(req,req.body.fp);
    if(anomalies.length>=2){
      return json(res,{ok:false,captcha:true,error:'请完成人机验证'});
    }
  }

  try{await fn(req,res)}catch(e){console.error(e);json(res,{ok:false,error:'服务器内部错误'},500)}
}

module.exports={json,handler,setSecurityHeaders};
