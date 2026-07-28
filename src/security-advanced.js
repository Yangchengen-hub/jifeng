/**
 * 极风工作室 - 高级安全模块
 * 功能：动态路径、IP白名单、防爆破、二次验证、邮件通知
 *       设备级封禁、申诉解封系统、隐私信息加密
 */

const crypto = require('crypto');
const db = require('./db');
const { encrypt, decrypt, maskEmail, maskPhone, uuid } = require('./crypto-utils');

// ============ 安全配置 ============
const SECURITY_CONFIG = {
  // 管理员邮箱（仅从环境变量读取，绝不硬编码）
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || '',
  
  // IP 白名单（默认为空，可在管理后台配置）
  IP_WHITELIST: [],
  
  // 允许访问的时间段（24小时制）
  ALLOWED_HOURS: { start: 0, end: 24 },
  
  // 登录失败次数限制
  MAX_LOGIN_ATTEMPTS: 5,
  
  // 登录锁定时间（毫秒）
  LOCKOUT_TIME: 30 * 60 * 1000, // 30分钟
  
  // 动态路径有效期（毫秒）
  DYNAMIC_PATH_TTL: 60 * 60 * 1000, // 1小时
  
  // 二次验证码长度
  TWO_FA_CODE_LENGTH: 6,
  
  // 二次验证码有效期（毫秒）
  TWO_FA_TTL: 5 * 60 * 1000, // 5分钟
};

// ============ 内存存储 ============
const loginAttempts = new Map(); // IP -> { count, firstAttempt, lockUntil }
const dynamicPaths = new Map(); // path -> { expiresAt, ip, used }
const twoFACodes = new Map(); // sessionId -> { code, expiresAt, ip }
const adminSessions = new Map(); // sessionId -> { ip, createdAt, lastActivity }

// ============ 数据库表扩展 ============
function initSecurityTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_whitelist (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL UNIQUE,
      description TEXT,
      added_by TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS login_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      username TEXT,
      success INTEGER DEFAULT 0,
      failure_reason TEXT,
      user_agent TEXT,
      device_fingerprint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT UNIQUE NOT NULL,
      admin_id INTEGER,
      ip TEXT NOT NULL,
      user_agent TEXT,
      device_fingerprint TEXT,
      two_fa_verified INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    );

    CREATE TABLE IF NOT EXISTS dynamic_admin_paths (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      path TEXT UNIQUE NOT NULL,
      ip TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      used INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      ip TEXT,
      message TEXT,
      details TEXT,
      email_sent INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS device_fingerprints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      fingerprint_hash TEXT NOT NULL,
      canvas_hash TEXT,
      webgl_hash TEXT,
      audio_hash TEXT,
      fonts_hash TEXT,
      screen_info TEXT,
      timezone TEXT,
      language TEXT,
      plugins TEXT,
      hardware_info TEXT,
      first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 设备级封禁表（基于指纹哈希）
    CREATE TABLE IF NOT EXISTS banned_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint_hash TEXT UNIQUE NOT NULL,
      ip TEXT NOT NULL,
      device_info TEXT,
      canvas_hash TEXT,
      webgl_hash TEXT,
      reason TEXT NOT NULL,
      severity TEXT DEFAULT 'high',
      banned_by TEXT DEFAULT 'system',
      appeal_token TEXT,
      appeal_status TEXT DEFAULT 'none',
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 申诉表
    CREATE TABLE IF NOT EXISTS appeals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      appeal_token TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL,
      ip TEXT,
      fingerprint_hash TEXT,
      reason TEXT NOT NULL,
      contact_email TEXT,
      appeal_message TEXT,
      status TEXT DEFAULT 'pending',
      admin_reply TEXT,
      processed_by TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      processed_at DATETIME
    );

    -- 作者隐私信息加密存储表
    CREATE TABLE IF NOT EXISTS private_config (
      key TEXT PRIMARY KEY,
      encrypted_value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 详细访问记录表（含设备完整信息）
    CREATE TABLE IF NOT EXISTS visitor_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_token TEXT UNIQUE NOT NULL,
      ip TEXT NOT NULL,
      fingerprint_hash TEXT,
      user_agent TEXT,
      device_brand TEXT,
      device_model TEXT,
      os TEXT,
      os_version TEXT,
      browser TEXT,
      browser_version TEXT,
      screen_resolution TEXT,
      timezone TEXT,
      language TEXT,
      country TEXT,
      region TEXT,
      city TEXT,
      isp TEXT,
      connection_type TEXT,
      is_mobile INTEGER DEFAULT 0,
      is_bot INTEGER DEFAULT 0,
      risk_score INTEGER DEFAULT 0,
      risk_factors TEXT,
      pages_visited TEXT,
      duration INTEGER DEFAULT 0,
      first_visit DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history(ip);
    CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history(created_at);
    CREATE INDEX IF NOT EXISTS idx_admin_sessions_session ON admin_sessions(session_id);
    CREATE INDEX IF NOT EXISTS idx_security_alerts_created ON security_alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_banned_devices_fp ON banned_devices(fingerprint_hash);
    CREATE INDEX IF NOT EXISTS idx_banned_devices_ip ON banned_devices(ip);
    CREATE INDEX IF NOT EXISTS idx_appeals_status ON appeals(status);
    CREATE INDEX IF NOT EXISTS idx_visitor_sessions_fp ON visitor_sessions(fingerprint_hash);
    CREATE INDEX IF NOT EXISTS idx_visitor_sessions_ip ON visitor_sessions(ip);
    CREATE INDEX IF NOT EXISTS idx_visitor_sessions_last ON visitor_sessions(last_activity);
  `);

  // 初始化加密存储的作者隐私信息
  const existingEmail = db.prepare('SELECT key FROM private_config WHERE key = ?').get('author_email_encrypted');
  if (!existingEmail) {
    const emailEncrypted = encrypt(SECURITY_CONFIG.ADMIN_EMAIL);
    db.prepare('INSERT OR IGNORE INTO private_config (key, encrypted_value) VALUES (?, ?)').run('author_email_encrypted', emailEncrypted);
  }
}

// 初始化
initSecurityTables();

// ============ 动态路径生成 ============
function generateDynamicPath() {
  // 生成随机路径，格式: /secure_{random}/admin
  const randomPart = crypto.randomBytes(16).toString('hex');
  return `/secure_${randomPart}/admin`;
}

function createDynamicPathForIP(ip) {
  const path = generateDynamicPath();
  const expiresAt = Date.now() + SECURITY_CONFIG.DYNAMIC_PATH_TTL;
  
  // 清理旧路径
  for (const [p, data] of dynamicPaths) {
    if (data.ip === ip || data.expiresAt < Date.now()) {
      dynamicPaths.delete(p);
    }
  }
  
  dynamicPaths.set(path, {
    ip,
    expiresAt,
    used: false
  });
  
  // 存入数据库
  try {
    db.prepare(`
      INSERT INTO dynamic_admin_paths (path, ip, expires_at)
      VALUES (?, ?, datetime('now', '+1 hour'))
    `).run(path, ip);
  } catch (e) {
    console.error('[Security] 保存动态路径失败:', e.message);
  }
  
  return path;
}

function validateDynamicPath(path, ip) {
  const data = dynamicPaths.get(path);
  
  if (!data) {
    // 检查数据库
    const dbPath = db.prepare(`
      SELECT * FROM dynamic_admin_paths 
      WHERE path = ? AND ip = ? AND expires_at > datetime('now') AND used = 0
    `).get(path, ip);
    
    if (!dbPath) return { valid: false, reason: 'path_not_found' };
    
    // 标记为已使用
    db.prepare('UPDATE dynamic_admin_paths SET used = 1 WHERE id = ?').run(dbPath.id);
    return { valid: true };
  }
  
  if (data.expiresAt < Date.now()) {
    dynamicPaths.delete(path);
    return { valid: false, reason: 'expired' };
  }
  
  if (data.ip !== ip) {
    return { valid: false, reason: 'ip_mismatch' };
  }
  
  if (data.used) {
    return { valid: false, reason: 'already_used' };
  }
  
  // 单次使用
  data.used = true;
  return { valid: true };
}

// ============ IP 白名单验证 ============
function isIPWhitelisted(ip) {
  // 从数据库检查
  const whitelisted = db.prepare('SELECT * FROM admin_whitelist WHERE ip = ?').get(ip);
  return !!whitelisted;
}

function addToWhitelist(ip, description, addedBy) {
  try {
    db.prepare(`
      INSERT OR IGNORE INTO admin_whitelist (ip, description, added_by)
      VALUES (?, ?, ?)
    `).run(ip, description, addedBy);
    return true;
  } catch (e) {
    console.error('[Security] 添加白名单失败:', e.message);
    return false;
  }
}

function removeFromWhitelist(ip) {
  db.prepare('DELETE FROM admin_whitelist WHERE ip = ?').run(ip);
}

function getWhitelist() {
  return db.prepare('SELECT * FROM admin_whitelist ORDER BY created_at DESC').all();
}

// ============ 登录防护（防爆破）============
function checkLoginAttempt(ip) {
  const attempts = loginAttempts.get(ip);
  const now = Date.now();
  
  if (!attempts) {
    return { allowed: true, remaining: SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS };
  }
  
  // 检查是否在锁定中
  if (attempts.lockUntil && attempts.lockUntil > now) {
    const remainingTime = Math.ceil((attempts.lockUntil - now) / 60000);
    return { 
      allowed: false, 
      locked: true, 
      remainingTime,
      reason: 'account_locked'
    };
  }
  
  // 锁定期已过，重置
  if (attempts.lockUntil && attempts.lockUntil <= now) {
    loginAttempts.delete(ip);
    return { allowed: true, remaining: SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS };
  }
  
  const remaining = SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS - attempts.count;
  return { allowed: remaining > 0, remaining: Math.max(0, remaining) };
}

function recordLoginAttempt(ip, success, username = null, userAgent = null, deviceFingerprint = null) {
  const now = Date.now();
  
  if (success) {
    // 登录成功，清除失败记录
    loginAttempts.delete(ip);
  } else {
    // 登录失败
    let attempts = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
    attempts.count++;
    
    if (attempts.count >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
      attempts.lockUntil = now + SECURITY_CONFIG.LOCKOUT_TIME;
      
      // 记录安全事件
      createSecurityAlert('login_brute_force', 'high', ip, 
        `IP ${ip} 登录失败 ${attempts.count} 次，已锁定30分钟`,
        { attempts: attempts.count, username });
    }
    
    loginAttempts.set(ip, attempts);
  }
  
  // 记录到数据库
  try {
    db.prepare(`
      INSERT INTO login_history (ip, username, success, failure_reason, user_agent, device_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(ip, username, success ? 1 : 0, success ? null : 'invalid_credentials', userAgent, deviceFingerprint);
  } catch (e) {
    console.error('[Security] 记录登录历史失败:', e.message);
  }
}

// ============ 二次验证（2FA）============
function generate2FACode(sessionId, ip) {
  const code = crypto.randomInt(100000, 999999).toString();
  const expiresAt = Date.now() + SECURITY_CONFIG.TWO_FA_TTL;
  
  twoFACodes.set(sessionId, {
    code,
    expiresAt,
    ip,
    attempts: 0
  });
  
  return code;
}

function verify2FACode(sessionId, code, ip) {
  const data = twoFACodes.get(sessionId);
  
  if (!data) {
    return { valid: false, reason: 'code_not_found' };
  }
  
  if (data.expiresAt < Date.now()) {
    twoFACodes.delete(sessionId);
    return { valid: false, reason: 'code_expired' };
  }
  
  if (data.ip !== ip) {
    return { valid: false, reason: 'ip_mismatch' };
  }
  
  if (data.attempts >= 3) {
    twoFACodes.delete(sessionId);
    return { valid: false, reason: 'too_many_attempts' };
  }
  
  data.attempts++;
  
  if (data.code !== code) {
    return { valid: false, reason: 'invalid_code', remaining: 3 - data.attempts };
  }
  
  twoFACodes.delete(sessionId);
  return { valid: true };
}

// ============ 会话管理 ============
function createAdminSession(adminId, ip, userAgent, deviceFingerprint) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24小时
  
  adminSessions.set(sessionId, {
    adminId,
    ip,
    userAgent,
    deviceFingerprint,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    expiresAt
  });
  
  try {
    db.prepare(`
      INSERT INTO admin_sessions (session_id, admin_id, ip, user_agent, device_fingerprint, expires_at)
      VALUES (?, ?, ?, ?, ?, datetime('now', '+24 hours'))
    `).run(sessionId, adminId, ip, userAgent, deviceFingerprint);
  } catch (e) {
    console.error('[Security] 创建会话记录失败:', e.message);
  }
  
  return sessionId;
}

function validateAdminSession(sessionId, ip) {
  const session = adminSessions.get(sessionId);
  
  if (!session) {
    // 检查数据库
    const dbSession = db.prepare(`
      SELECT * FROM admin_sessions 
      WHERE session_id = ? AND expires_at > datetime('now')
    `).get(sessionId);
    
    if (!dbSession) return { valid: false, reason: 'session_not_found' };
    if (dbSession.ip !== ip) return { valid: false, reason: 'ip_mismatch' };
    
    return { valid: true, session: dbSession };
  }
  
  if (session.expiresAt < Date.now()) {
    adminSessions.delete(sessionId);
    return { valid: false, reason: 'session_expired' };
  }
  
  if (session.ip !== ip) {
    // IP 变化检测
    createSecurityAlert('ip_change_detected', 'medium', ip,
      `管理员会话 IP 变化: ${session.ip} -> ${ip}`,
      { oldIp: session.ip, newIp: ip });
    return { valid: false, reason: 'ip_changed' };
  }
  
  // 更新最后活动时间
  session.lastActivity = Date.now();
  
  return { valid: true, session };
}

function terminateSession(sessionId) {
  adminSessions.delete(sessionId);
  db.prepare('DELETE FROM admin_sessions WHERE session_id = ?').run(sessionId);
}

function terminateAllSessions(adminId) {
  for (const [sid, session] of adminSessions) {
    if (session.adminId === adminId) {
      adminSessions.delete(sid);
    }
  }
  db.prepare('DELETE FROM admin_sessions WHERE admin_id = ?').run(adminId);
}

// ============ 时间限制验证 ============
function isWithinAllowedTime() {
  const hour = new Date().getHours();
  return hour >= SECURITY_CONFIG.ALLOWED_HOURS.start && 
         hour <= SECURITY_CONFIG.ALLOWED_HOURS.end;
}

// ============ 安全警报系统 ============
function createSecurityAlert(type, severity, ip, message, details = null) {
  try {
    const result = db.prepare(`
      INSERT INTO security_alerts (type, severity, ip, message, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(type, severity, ip, message, details ? JSON.stringify(details) : null);
    
    const alertId = result.lastInsertRowid;
    
    // 高危和中危需要发送邮件通知
    if (severity === 'critical' || severity === 'high') {
      // 这里会触发邮件发送（在邮件模块中实现）
      return { alertId, shouldNotifyEmail: true };
    }
    
    return { alertId, shouldNotifyEmail: false };
  } catch (e) {
    console.error('[Security] 创建警报失败:', e.message);
    return { alertId: null, shouldNotifyEmail: false };
  }
}

function getRecentAlerts(limit = 50) {
  return db.prepare(`
    SELECT * FROM security_alerts 
    ORDER BY created_at DESC 
    LIMIT ?
  `).all(limit);
}

function getUnsentAlerts() {
  return db.prepare(`
    SELECT * FROM security_alerts 
    WHERE email_sent = 0 AND severity IN ('critical', 'high')
    ORDER BY created_at DESC
  `).all();
}

function markAlertAsSent(alertId) {
  db.prepare('UPDATE security_alerts SET email_sent = 1 WHERE id = ?').run(alertId);
}

// ============ 设备指纹存储 ============
function saveDeviceFingerprint(ip, fingerprint) {
  try {
    const existing = db.prepare(`
      SELECT * FROM device_fingerprints WHERE ip = ? AND fingerprint_hash = ?
    `).get(ip, fingerprint.hash);
    
    if (existing) {
      db.prepare(`
        UPDATE device_fingerprints SET last_seen = datetime('now')
        WHERE id = ?
      `).run(existing.id);
      return existing.id;
    }
    
    const result = db.prepare(`
      INSERT INTO device_fingerprints (
        ip, fingerprint_hash, canvas_hash, webgl_hash, audio_hash,
        fonts_hash, screen_info, timezone, language, plugins, hardware_info
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      ip,
      fingerprint.hash,
      fingerprint.canvasHash,
      fingerprint.webglHash,
      fingerprint.audioHash,
      fingerprint.fontsHash,
      JSON.stringify(fingerprint.screenInfo),
      fingerprint.timezone,
      fingerprint.language,
      JSON.stringify(fingerprint.plugins),
      JSON.stringify(fingerprint.hardwareInfo)
    );
    
    return result.lastInsertRowid;
  } catch (e) {
    console.error('[Security] 保存设备指纹失败:', e.message);
    return null;
  }
}

function getDeviceFingerprints(ip) {
  return db.prepare(`
    SELECT * FROM device_fingerprints WHERE ip = ?
    ORDER BY last_seen DESC
  `).all(ip);
}

// ============ 设备级封禁系统 ============

// 检查设备是否被封禁（基于指纹哈希）
function isDeviceBanned(fingerprintHash) {
  if (!fingerprintHash) return false;
  const ban = db.prepare(`
    SELECT * FROM banned_devices
    WHERE fingerprint_hash = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(fingerprintHash);
  return !!ban;
}

// 封禁设备
function banDevice(fingerprintHash, ip, deviceInfo, reason, severity = 'high', bannedBy = 'system') {
  try {
    const appealToken = uuid();
    db.prepare(`
      INSERT OR REPLACE INTO banned_devices
      (fingerprint_hash, ip, device_info, canvas_hash, webgl_hash, reason, severity, banned_by, appeal_token, appeal_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'none')
    `).run(
      fingerprintHash,
      ip,
      JSON.stringify(deviceInfo || {}),
      deviceInfo?.canvasHash || null,
      deviceInfo?.webglHash || null,
      reason,
      severity,
      bannedBy,
      appealToken
    );
    console.log(`[Security] 设备已封禁: ${fingerprintHash} - ${reason}`);
    return { success: true, appealToken };
  } catch (e) {
    console.error('[Security] 封禁设备失败:', e.message);
    return { success: false, error: e.message };
  }
}

// 解封设备
function unbanDevice(fingerprintHash) {
  db.prepare('DELETE FROM banned_devices WHERE fingerprint_hash = ?').run(fingerprintHash);
  console.log(`[Security] 设备已解封: ${fingerprintHash}`);
}

// 获取封禁设备列表
function getBannedDevices(limit = 100, offset = 0) {
  return db.prepare(`
    SELECT * FROM banned_devices
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
}

// 检查IP和设备是否都被封禁
function isIPAndDeviceBanned(ip, fingerprintHash) {
  const ipBanned = db.prepare(`
    SELECT * FROM banned_ips
    WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(ip);

  const deviceBanned = fingerprintHash ? isDeviceBanned(fingerprintHash) : false;

  return {
    banned: !!ipBanned || deviceBanned,
    ipBanned: !!ipBanned,
    deviceBanned,
    ipBanInfo: ipBanned || null
  };
}

// ============ 申诉解封系统 ============

// 创建申诉
function createAppeal(type, ip, fingerprintHash, reason, contactEmail, appealMessage) {
  try {
    const appealToken = uuid();

    db.prepare(`
      INSERT INTO appeals (appeal_token, type, ip, fingerprint_hash, reason, contact_email, appeal_message)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(appealToken, type, ip, fingerprintHash, reason, contactEmail || null, appealMessage);

    // 如果是设备封禁，更新封禁记录的申诉状态
    if (type === 'device' && fingerprintHash) {
      db.prepare(`
        UPDATE banned_devices SET appeal_status = 'pending', appeal_token = ?
        WHERE fingerprint_hash = ?
      `).run(appealToken, fingerprintHash);
    } else if (type === 'ip' && ip) {
      db.prepare(`
        UPDATE banned_ips SET reason = reason || ' [申诉中: ' || ? || ']'
        WHERE ip = ?
      `).run(appealToken, ip);
    }

    return { success: true, appealToken };
  } catch (e) {
    console.error('[Security] 创建申诉失败:', e.message);
    return { success: false, error: e.message };
  }
}

// 获取申诉列表
function getAppeals(status = null, limit = 100, offset = 0) {
  let query = 'SELECT * FROM appeals';
  const params = [];
  if (status && status !== 'all') {
    query += ' WHERE status = ?';
    params.push(status);
  }
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  return db.prepare(query).all(...params);
}

// 处理申诉
function processAppeal(appealId, status, adminReply, processedBy) {
  try {
    const appeal = db.prepare('SELECT * FROM appeals WHERE id = ?').get(appealId);
    if (!appeal) return { success: false, error: '申诉不存在' };

    db.prepare(`
      UPDATE appeals SET status = ?, admin_reply = ?, processed_by = ?, processed_at = datetime('now')
      WHERE id = ?
    `).run(status, adminReply, processedBy, appealId);

    // 如果申诉通过，解封IP或设备
    if (status === 'approved') {
      if (appeal.type === 'device' && appeal.fingerprint_hash) {
        unbanDevice(appeal.fingerprint_hash);
      } else if (appeal.type === 'ip' && appeal.ip) {
        db.prepare('DELETE FROM banned_ips WHERE ip = ?').run(appeal.ip);
      }
    }

    return { success: true, appeal };
  } catch (e) {
    console.error('[Security] 处理申诉失败:', e.message);
    return { success: false, error: e.message };
  }
}

// ============ 访客会话记录系统 ============

// 记录访客会话
function recordVisitorSession(sessionData) {
  try {
    const token = uuid();
    db.prepare(`
      INSERT INTO visitor_sessions (
        session_token, ip, fingerprint_hash, user_agent, device_brand, device_model,
        os, os_version, browser, browser_version, screen_resolution, timezone, language,
        country, region, city, isp, connection_type, is_mobile, is_bot, risk_score, risk_factors
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      token, sessionData.ip, sessionData.fingerprintHash, sessionData.userAgent,
      sessionData.deviceBrand, sessionData.deviceModel, sessionData.os, sessionData.osVersion,
      sessionData.browser, sessionData.browserVersion, sessionData.screenResolution,
      sessionData.timezone, sessionData.language, sessionData.country, sessionData.region,
      sessionData.city, sessionData.isp, sessionData.connectionType,
      sessionData.isMobile ? 1 : 0, sessionData.isBot ? 1 : 0,
      sessionData.riskScore || 0, JSON.stringify(sessionData.riskFactors || [])
    );
    return token;
  } catch (e) {
    console.error('[Security] 记录访客会话失败:', e.message);
    return null;
  }
}

// 更新访客活动
function updateVisitorActivity(sessionToken, page) {
  try {
    const session = db.prepare('SELECT pages_visited FROM visitor_sessions WHERE session_token = ?').get(sessionToken);
    let pages = [];
    if (session && session.pages_visited) {
      pages = JSON.parse(session.pages_visited);
    }
    pages.push({ page, time: new Date().toISOString() });

    db.prepare(`
      UPDATE visitor_sessions SET last_activity = datetime('now'), pages_visited = ?
      WHERE session_token = ?
    `).run(JSON.stringify(pages), sessionToken);
  } catch (e) {
    console.error('[Security] 更新访客活动失败:', e.message);
  }
}

// 获取访客会话列表（管理端用）
function getVisitorSessions(limit = 50, offset = 0) {
  return db.prepare(`
    SELECT * FROM visitor_sessions
    ORDER BY last_activity DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
}

// 获取单个访客详情
function getVisitorDetail(sessionToken) {
  const session = db.prepare('SELECT * FROM visitor_sessions WHERE session_token = ?').get(sessionToken);
  if (session && session.pages_visited) {
    session.pages_visited = JSON.parse(session.pages_visited);
  }
  if (session && session.risk_factors) {
    session.risk_factors = JSON.parse(session.risk_factors);
  }
  return session;
}

// ============ 隐私信息管理 ============

// 获取作者邮箱（解密）
function getAuthorEmail() {
  const row = db.prepare('SELECT encrypted_value FROM private_config WHERE key = ?').get('author_email_encrypted');
  if (row) {
    return decrypt(row.encrypted_value);
  }
  return SECURITY_CONFIG.ADMIN_EMAIL;
}

// 获取脱敏后的邮箱（前端显示用）
function getMaskedAuthorEmail() {
  const email = getAuthorEmail();
  return maskEmail(email);
}

// 更新作者邮箱（加密存储）
function setAuthorEmail(newEmail) {
  const encrypted = encrypt(newEmail);
  db.prepare(`
    INSERT OR REPLACE INTO private_config (key, encrypted_value, updated_at)
    VALUES (?, ?, datetime('now'))
  `).run('author_email_encrypted', encrypted);
}

// ============ 综合安全检查中间件 ============
function advancedSecurityCheck(req, res, next) {
  const ip = req.ip;
  const path = req.path;
  
  // 1. 时间限制检查
  if (!isWithinAllowedTime()) {
    return res.status(403).json({ 
      error: 'outside_allowed_hours',
      message: '当前时间不允许访问管理后台'
    });
  }
  
  // 2. IP 白名单检查（如果已配置）
  const whitelistEnabled = db.prepare(`
    SELECT value FROM system_config WHERE key = 'admin_ip_whitelist_enabled'
  `).get();
  
  if (whitelistEnabled?.value === 'true' && !isIPWhitelisted(ip)) {
    createSecurityAlert('unauthorized_ip_access', 'high', ip,
      `非白名单 IP 尝试访问管理后台: ${ip}`,
      { path });
    return res.status(403).json({ 
      error: 'ip_not_whitelisted',
      message: 'IP 未授权'
    });
  }
  
  // 3. 登录锁定检查
  const loginCheck = checkLoginAttempt(ip);
  if (!loginCheck.allowed && loginCheck.locked) {
    return res.status(429).json({ 
      error: 'account_locked',
      message: `账户已锁定，请 ${loginCheck.remainingTime} 分钟后重试`,
      remainingTime: loginCheck.remainingTime
    });
  }
  
  next();
}

// ============ 导出 ============
module.exports = {
  // 配置
  SECURITY_CONFIG,

  // 动态路径
  generateDynamicPath,
  createDynamicPathForIP,
  validateDynamicPath,

  // IP 白名单
  isIPWhitelisted,
  addToWhitelist,
  removeFromWhitelist,
  getWhitelist,

  // 登录防护
  checkLoginAttempt,
  recordLoginAttempt,

  // 二次验证
  generate2FACode,
  verify2FACode,

  // 会话管理
  createAdminSession,
  validateAdminSession,
  terminateSession,
  terminateAllSessions,

  // 时间限制
  isWithinAllowedTime,

  // 安全警报
  createSecurityAlert,
  getRecentAlerts,
  getUnsentAlerts,
  markAlertAsSent,

  // 设备指纹
  saveDeviceFingerprint,
  getDeviceFingerprints,

  // 设备级封禁
  isDeviceBanned,
  banDevice,
  unbanDevice,
  getBannedDevices,
  isIPAndDeviceBanned,

  // 申诉系统
  createAppeal,
  getAppeals,
  processAppeal,

  // 访客会话
  recordVisitorSession,
  updateVisitorActivity,
  getVisitorSessions,
  getVisitorDetail,

  // 隐私信息
  getAuthorEmail,
  getMaskedAuthorEmail,
  setAuthorEmail,

  // 中间件
  advancedSecurityCheck
};