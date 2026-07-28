const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const dbPath = process.env.VERCEL ? '/tmp/jifeng.db' : path.join(__dirname, '..', 'data', 'jifeng.db');
if (process.env.VERCEL) {
  const fs = require('fs');
  if (!fs.existsSync('/tmp')) fs.mkdirSync('/tmp', { recursive: true });
}
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    last_login_at DATETIME,
    last_login_ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    user_agent TEXT,
    referer TEXT,
    accept_language TEXT,
    browser TEXT,
    browser_version TEXT,
    os TEXT,
    os_version TEXT,
    device TEXT,
    device_type TEXT,
    is_mobile INTEGER DEFAULT 0,
    is_bot INTEGER DEFAULT 0,
    bot_name TEXT,
    country TEXT,
    region TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    response_time INTEGER,
    request_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT,
    path TEXT,
    description TEXT,
    details TEXT,
    request_id TEXT,
    blocked INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS captcha_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    answer TEXT NOT NULL,
    purpose TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    file_name TEXT NOT NULL,
    user_agent TEXT,
    captcha_verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS rate_limit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    hits INTEGER DEFAULT 1,
    window_start DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip, endpoint, window_start)
  );

  CREATE TABLE IF NOT EXISTS banned_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    severity TEXT DEFAULT 'high',
    banned_by TEXT DEFAULT 'system',
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS security_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    threats_found TEXT,
    action_taken TEXT,
    ai_risk_score INTEGER DEFAULT 0,
    ai_risk_level TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'safe',
    features TEXT,
    risk_factors TEXT,
    recommendations TEXT,
    confidence REAL DEFAULT 0.85,
    request_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip TEXT NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    user_agent TEXT,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip);
  CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at);
  CREATE INDEX IF NOT EXISTS idx_access_logs_bot ON access_logs(is_bot);
  CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip);
  CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
  CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
  CREATE INDEX IF NOT EXISTS idx_banned_ips_ip ON banned_ips(ip);
  CREATE INDEX IF NOT EXISTS idx_security_scans_ip ON security_scans(ip);
  CREATE INDEX IF NOT EXISTS idx_ai_analysis_ip ON ai_analysis(ip);
  CREATE INDEX IF NOT EXISTS idx_ai_analysis_created_at ON ai_analysis(created_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
`);

// 初始化默认系统配置
const defaultConfigs = {
  'site_enabled': 'true',
  'waf_enabled': 'true',
  'bot_protection_enabled': 'true',
  'rate_limit_enabled': 'true',
  'download_captcha_enabled': 'true',
  'login_captcha_enabled': 'true',
  'auto_ban_enabled': 'true',
  'auto_ban_threshold': '3',
  'admin_secret_path': crypto.randomBytes(8).toString('hex'),
  'admin_access_token': crypto.randomBytes(32).toString('hex')
};

const insertConfig = db.prepare('INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)');
for (const [key, value] of Object.entries(defaultConfigs)) {
  insertConfig.run(key, value);
}

// 创建或更新管理员账号 - 密码从环境变量读取（绝不硬编码）
// 部署时在 Render 控制台设置 ADMIN_USERNAME 和 ADMIN_PASSWORD 环境变量
const adminUsername = process.env.ADMIN_USERNAME || 'JIFENG';
const adminPassword = process.env.ADMIN_PASSWORD;

if (adminPassword) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  const existingAdmin = db.prepare('SELECT id FROM admins WHERE username = ?').get(adminUsername);
  if (existingAdmin) {
    db.prepare('UPDATE admins SET password_hash = ?, role = ? WHERE id = ?')
      .run(hash, 'superadmin', existingAdmin.id);
    console.log('[DB] 管理员密码已从环境变量同步');
  } else {
    // 删除旧的默认 admin 账号
    db.prepare('DELETE FROM admins WHERE username = ?').run('admin');
    db.prepare('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)')
      .run(adminUsername, hash, 'superadmin');
    console.log(`[DB] 管理员已创建: ${adminUsername}`);
  }
} else {
  // 仅在已存在管理员时跳过，否则警告
  const anyAdmin = db.prepare('SELECT COUNT(*) as count FROM admins').get().count;
  if (anyAdmin === 0) {
    console.warn('[DB] ⚠️  未设置 ADMIN_PASSWORD 环境变量，未创建管理员');
    console.warn('[DB] ⚠️  请在 Render 控制台配置后再启动');
  } else {
    console.log('[DB] 沿用现有管理员账号');
  }
}

// 获取配置的辅助函数
function getConfig(key) {
  const row = db.prepare('SELECT value FROM system_config WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setConfig(key, value) {
  db.prepare('INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, datetime(\'now\'))')
    .run(key, value);
}

// 检查 IP 是否被封禁
function isIPBanned(ip) {
  const ban = db.prepare(`
    SELECT * FROM banned_ips 
    WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(ip);
  return !!ban;
}

// 封禁 IP
function banIP(ip, reason, severity = 'high', bannedBy = 'system', expiresAt = null) {
  try {
    db.prepare(`
      INSERT OR REPLACE INTO banned_ips (ip, reason, severity, banned_by, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(ip, reason, severity, bannedBy, expiresAt);
    console.log(`[Security] IP 已封禁: ${ip} - ${reason}`);
  } catch (e) {
    console.error('[Security] 封禁 IP 失败:', e.message);
  }
}

// 解封 IP
function unbanIP(ip) {
  db.prepare('DELETE FROM banned_ips WHERE ip = ?').run(ip);
}

module.exports = db;
module.exports.getConfig = getConfig;
module.exports.setConfig = setConfig;
module.exports.isIPBanned = isIPBanned;
module.exports.banIP = banIP;
module.exports.unbanIP = unbanIP;
