const crypto=require('crypto');
const ALGO='aes-256-gcm';
function getKey(){
  const k=process.env.DATA_ENC_KEY||process.env.AUTH_SECRET||'jifeng-default-key-change-me-32bytes!';
  return crypto.createHash('sha256').update(k).digest();
}
function encrypt(text){
  if(text===null||text===undefined)return text;
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv(ALGO,getKey(),iv);
  let enc=cipher.update(String(text),'utf8','hex');
  enc+=cipher.final('hex');
  const tag=cipher.getAuthTag().toString('hex');
  return iv.toString('hex')+':'+tag+':'+enc;
}
function decrypt(encStr){
  if(!encStr||typeof encStr!=='string'||!encStr.includes(':'))return encStr;
  try{
    const[ivHex,tagHex,enc]=encStr.split(':');
    const decipher=crypto.createDecipheriv(ALGO,getKey(),Buffer.from(ivHex,'hex'));
    decipher.setAuthTag(Buffer.from(tagHex,'hex'));
    let dec=decipher.update(enc,'hex','utf8');
    dec+=decipher.final('utf8');
    return dec;
  }catch(e){return encStr}
}
function maskIP(ip){
  if(!ip)return ip;
  const parts=ip.split('.');
  if(parts.length===4)return parts[0]+'.'+parts[1]+'.x.x';
  return ip.substring(0,8)+'***';
}
function hashFp(fp){
  return crypto.createHash('sha256').update(fp||'').digest('hex').substring(0,16);
}
module.exports={encrypt,decrypt,maskIP,hashFp};
