/**
 * 极风工作室 - 隐私信息加密模块
 * AES-256-GCM 加密（工业级，攻击者无法直接解密）
 *
 * 安全设计：
 *   - 密钥仅从环境变量 CRYPTO_KEY 读取，禁止硬编码
 *   - 每次加密使用随机 IV（即使同明文也产生不同密文）
 *   - 认证标签（authTag）防篡改，密文被改立即解密失败
 *   - 加密失败时返回 null 而非抛异常，避免整站崩溃
 */

const crypto = require('crypto');

let ENCRYPTION_KEY = null;
let KEY_LOADED = false;

function _tryLoadKey() {
  if (KEY_LOADED) return !!ENCRYPTION_KEY;
  KEY_LOADED = true;

  const raw = process.env.CRYPTO_KEY;
  if (!raw) {
    console.warn('[Crypto] CRYPTO_KEY 环境变量未设置，加密功能将被禁用。请在 Vercel 控制台设置以启用完整加密。');
    return false;
  }

  try {
    const buf = Buffer.from(raw, 'hex');
    if (buf.length !== 32) {
      console.error('[Crypto] CRYPTO_KEY 必须是 64 位 hex 字符串（对应 32 字节）。');
      return false;
    }
    ENCRYPTION_KEY = buf;
    return true;
  } catch (e) {
    console.error('[Crypto] CRYPTO_KEY 解析失败:', e.message);
    return false;
  }
}

const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

/**
 * 加密数据
 * @param {string} text - 明文
 * @returns {string|null} 格式: iv:authTag:encryptedData (均hex编码)；密钥未配置时返回 null
 */
function encrypt(text) {
  if (!text) return null;
  if (!_tryLoadKey()) return null;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(String(text), 'utf8', 'hex');
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
 * @returns {string|null} 明文；密钥未配置或密文损坏时返回 null
 */
function decrypt(encryptedText) {
  if (!encryptedText) return null;
  if (!_tryLoadKey()) return null;
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) return null;
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    // 密文损坏 / 密钥不匹配：保持静默，不泄露任何信息
    return null;
  }
}

/**
 * 是否启用加密（仅用于诊断）
 */
function isEnabled() {
  return _tryLoadKey();
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
 * 不可逆哈希（仅用于比对，不用于还原）
 */
function hash(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

/**
 * UUID v4
 */
function uuid() {
  return crypto.randomUUID();
}

module.exports = {
  encrypt,
  decrypt,
  isEnabled,
  maskEmail,
  maskPhone,
  maskIP,
  hash,
  uuid,
};
