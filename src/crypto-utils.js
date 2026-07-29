/**
 * 极风工作室 - 隐私信息加密模块
 * 对作者邮箱、手机号等敏感信息进行AES-256加密存储
 * 前端展示时自动脱敏处理
 */

const crypto = require('crypto');

// 加密密钥（必须从环境变量获取，禁止硬编码）
const ENCRYPTION_KEY = process.env.CRYPTO_KEY ? Buffer.from(process.env.CRYPTO_KEY, 'hex') : null;
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
  throw new Error('[Crypto] CRYPTO_KEY 环境变量未设置或长度不正确（需要64位hex字符串对应32字节）');
}
const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

/**
 * 加密数据
 * @param {string} text - 明文
 * @returns {string} 格式: iv:authTag:encryptedData (均hex编码)
 */
function encrypt(text) {
  if (!text) return null;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch (e) {
    console.error('[Crypto] 加密失败:', e.message);
    return null;
  }
}

/**
 * 解密数据
 * @param {string} encryptedText - 加密文本
 * @returns {string|null} 明文
 */
function decrypt(encryptedText) {
  if (!encryptedText) return null;
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) return null;
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('[Crypto] 解密失败:', e.message);
    return null;
  }
}

/**
 * 脱敏邮箱地址
 * user@example.com -> u****le@example.com
 */
function maskEmail(email) {
  if (!email) return '';
  const [name, domain] = email.split('@');
  if (!domain) return email;
  if (name.length <= 2) return name[0] + '*@' + domain;
  return name[0] + '*'.repeat(Math.max(3, name.length - 2)) + name.slice(-2) + '@' + domain;
}

/**
 * 脱敏手机号
 * 13812345678 -> 138****5678
 */
function maskPhone(phone) {
  if (!phone || phone.length < 7) return phone;
  return phone.slice(0, 3) + '*'.repeat(4) + phone.slice(-4);
}

/**
 * 脱敏IP地址
 * 192.168.1.100 -> 192.168.*.***
 */
function maskIP(ip) {
  if (!ip) return '';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return parts[0] + '.' + parts[1] + '.*.***';
  }
  return ip;
}

/**
 * 生成哈希（不可逆，用于比对）
 */
function hash(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * 生成UUID v4
 */
function uuid() {
  return crypto.randomUUID();
}

module.exports = {
  encrypt,
  decrypt,
  maskEmail,
  maskPhone,
  maskIP,
  hash,
  uuid
};
