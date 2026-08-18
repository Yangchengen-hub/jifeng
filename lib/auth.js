const crypto=require('crypto');
const SECRET=process.env.AUTH_SECRET||crypto.randomBytes(32).toString('hex');

function sign(payload){
  const body=Buffer.from(JSON.stringify({...payload,iat:Date.now()})).toString('base64url');
  const sig=crypto.createHmac('sha256',SECRET).update(body).digest('base64url');
  return body+'.'+sig;
}

function verify(token){
  try{
    const[body,sig]=token.split('.');
    const expected=crypto.createHmac('sha256',SECRET).update(body).digest('base64url');
    if(sig!==expected)return null;
    const payload=JSON.parse(Buffer.from(body,'base64url').toString());
    if(payload.exp&&Date.now()>payload.exp)return null;
    return payload;
  }catch(e){return null}
}

function checkAdmin(req){
  const auth=req.headers.authorization||'';
  const token=auth.replace('Bearer ','');
  return verify(token);
}

module.exports={sign,verify,checkAdmin};
