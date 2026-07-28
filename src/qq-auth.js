/**
 * 极风工作室 - QQ 授权二级登录模块
 * QQ OAuth2.0 授权登录 + OpenID 绑定验证
 * 仅允许已绑定的 QQ 号通过二级验证
 */

const crypto = require('crypto');
const https = require('https');
const db = require('./db');
const { encrypt, decrypt, uuid } = require('./crypto-utils');

const QQ_APP_ID = process.env.QQ_APP_ID || '';
const QQ_APP_KEY = process.env.QQ_APP_KEY || '';
const QQ_REDIRECT_URI = process.env.QQ_REDIRECT_URI || '';

// QQ 白名单 - 只有这些QQ号才能参与二级登录
const QQ_WHITELIST = [
  '3565583431'
];

const oauthStates = new Map();

function isQQWhitelisted(qqNumber) {
  if (!qqNumber) return false;
  return QQ_WHITELIST.some(n => n === String(qqNumber));
}

function getQQWhitelist() {
  return [...QQ_WHITELIST];
}

function validateQQNumber(qqNumber) {
  if (!isQQWhitelisted(qqNumber)) {
    return {
      valid: false,
      reason: '该QQ号不在授权白名单中',
      whitelist: getQQWhitelist()
    };
  }
  return { valid: true };
}

function isQQConfigured() {
  return !!(QQ_APP_ID && QQ_APP_KEY && QQ_REDIRECT_URI);
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch (e) {
          resolve(data);
        }
      });
    }).on('error', reject);
  });
}

function generateOAuthState(ip) {
  const state = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, { ip, createdAt: Date.now() });
  setTimeout(() => oauthStates.delete(state), 10 * 60 * 1000);
  return state;
}

function validateOAuthState(state, ip) {
  const record = oauthStates.get(state);
  if (!record) return false;
  if (record.ip !== ip) return false;
  if (Date.now() - record.createdAt > 10 * 60 * 1000) {
    oauthStates.delete(state);
    return false;
  }
  oauthStates.delete(state);
  return true;
}

function getQQAuthURL(ip, purpose = 'login') {
  if (!isQQConfigured()) return null;
  const state = generateOAuthState(ip);
  const scope = 'get_user_info';
  return `https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=${QQ_APP_ID}&redirect_uri=${encodeURIComponent(QQ_REDIRECT_URI)}&state=${state}&scope=${scope}`;
}

async function exchangeCodeForToken(code) {
  const tokenUrl = `https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id=${QQ_APP_ID}&client_secret=${QQ_APP_KEY}&code=${code}&redirect_uri=${encodeURIComponent(QQ_REDIRECT_URI)}`;
  try {
    const result = await httpsGet(tokenUrl);
    if (typeof result === 'string') {
      const params = new URLSearchParams(result);
      const accessToken = params.get('access_token');
      if (accessToken) return { access_token: accessToken };
      return { error: '无法解析 token 响应' };
    }
    if (result.error) return { error: result.error_description || result.error };
    return result;
  } catch (e) {
    return { error: e.message };
  }
}

async function getOpenID(accessToken) {
  try {
    const result = await httpsGet(`https://graph.qq.com/oauth2.0/me?access_token=${accessToken}`);
    if (typeof result === 'string') {
      const callbackMatch = result.match(/callback\((.*)\)/);
      if (callbackMatch) {
        const json = JSON.parse(callbackMatch[1]);
        if (json.error) return { error: json.error_description || json.error };
        return { openid: json.openid, client_id: json.client_id };
      }
    }
    if (result.error) return { error: result.error_description || result.error };
    return result;
  } catch (e) {
    return { error: e.message };
  }
}

async function getUserInfo(accessToken, openid) {
  try {
    const result = await httpsGet(`https://graph.qq.com/user/get_user_info?access_token=${accessToken}&oauth_consumer_key=${QQ_APP_ID}&openid=${openid}`);
    if (result.ret !== undefined && result.ret !== 0) {
      return { error: result.msg || '获取用户信息失败' };
    }
    return result;
  } catch (e) {
    return { error: e.message };
  }
}

function isQQBound(openid) {
  const row = db.prepare('SELECT * FROM admin_qq_bindings WHERE openid = ? AND status = ?').get(openid, 'active');
  return !!row;
}

function getAdminByQQOpenID(openid) {
  const row = db.prepare(`
    SELECT a.* FROM admins a
    INNER JOIN admin_qq_bindings q ON a.id = q.admin_id
    WHERE q.openid = ? AND q.status = 'active'
  `).get(openid);
  return row || null;
}

function bindQQToAdmin(adminId, openid, nickname, avatar, qqNumber) {
  try {
    if (qqNumber && !isQQWhitelisted(qqNumber)) {
      return { success: false, error: '该QQ号不在授权白名单中' };
    }

    const existing = db.prepare('SELECT * FROM admin_qq_bindings WHERE admin_id = ?').get(adminId);
    if (existing) {
      db.prepare(`
        UPDATE admin_qq_bindings 
        SET openid = ?, nickname = ?, avatar = ?, qq_number = ?, updated_at = datetime('now')
        WHERE admin_id = ?
      `).run(openid, nickname || '', avatar || '', qqNumber || '', adminId);
    } else {
      db.prepare(`
        INSERT INTO admin_qq_bindings (admin_id, openid, nickname, avatar, qq_number, status)
        VALUES (?, ?, ?, ?, ?, 'active')
      `).run(adminId, openid, nickname || '', avatar || '', qqNumber || '');
    }
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function unbindQQ(adminId) {
  try {
    db.prepare('DELETE FROM admin_qq_bindings WHERE admin_id = ?').run(adminId);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function getQQBinding(adminId) {
  const row = db.prepare('SELECT * FROM admin_qq_bindings WHERE admin_id = ?').get(adminId);
  if (!row) return null;
  return {
    id: row.id,
    nickname: row.nickname,
    avatar: row.avatar,
    openid_masked: row.openid ? row.openid.slice(0, 4) + '****' + row.openid.slice(-4) : '',
    status: row.status,
    bound_at: row.created_at,
    last_used: row.last_used_at
  };
}

function updateQQLastUsed(openid) {
  try {
    db.prepare(`
      UPDATE admin_qq_bindings SET last_used_at = datetime('now') WHERE openid = ?
    `).run(openid);
  } catch (e) {}
}

function create2FASession(adminId, ip, userAgent) {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  try {
    db.prepare(`
      INSERT INTO two_fa_sessions (session_token, admin_id, ip, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(sessionToken, adminId, ip, userAgent || '', expiresAt);
    return { success: true, sessionToken, expiresAt };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function verify2FASession(sessionToken, ip) {
  const row = db.prepare(`
    SELECT * FROM two_fa_sessions s
    INNER JOIN admins a ON s.admin_id = a.id
    WHERE s.session_token = ? AND s.verified = 1 AND s.expires_at > datetime('now')
  `).get(sessionToken);
  if (!row) return { valid: false };
  if (row.ip !== ip) return { valid: false, reason: 'IP 不匹配' };
  return { valid: true, admin: { id: row.id, username: row.username, role: row.role } };
}

function mark2FAVerified(sessionToken, openid) {
  try {
    const result = db.prepare(`
      UPDATE two_fa_sessions SET verified = 1, qq_openid = ?, verified_at = datetime('now')
      WHERE session_token = ?
    `).run(openid, sessionToken);
    return result.changes > 0;
  } catch (e) {
    return false;
  }
}

function cleanupExpired2FASessions() {
  try {
    db.prepare("DELETE FROM two_fa_sessions WHERE expires_at < datetime('now')").run();
  } catch (e) {}
}

setInterval(cleanupExpired2FASessions, 30 * 60 * 1000);

module.exports = {
  isQQConfigured,
  getQQAuthURL,
  validateOAuthState,
  exchangeCodeForToken,
  getOpenID,
  getUserInfo,
  isQQBound,
  getAdminByQQOpenID,
  bindQQToAdmin,
  unbindQQ,
  getQQBinding,
  updateQQLastUsed,
  create2FASession,
  verify2FASession,
  mark2FAVerified,
  isQQWhitelisted,
  getQQWhitelist,
  validateQQNumber,
  QQ_APP_ID,
  QQ_REDIRECT_URI
};
