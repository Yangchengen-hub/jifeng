const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

let db;
let dbReady = false;

try {
  const Database = require('better-sqlite3');
  const dbPath = process.env.VERCEL ? '/tmp/jifeng.db' : path.join(__dirname, '..', 'data', 'jifeng.db');
  if (process.env.VERCEL) {
    const fs = require('fs');
    if (!fs.existsSync('/tmp')) fs.mkdirSync('/tmp', { recursive: true });
  }
  db = new Database(dbPath);

  // Vercel Serverless 环境禁用 WAL（部分只读文件系统不兼容）
  if (!process.env.VERCEL) {
    db.pragma('journal_mode = WAL');
  }
  db.pragma('foreign_keys = ON');
  dbReady = true;
} catch (err) {
  console.error('[DB] better-sqlite3 初始化失败:', err.message);
  console.error('[DB] 将使用内存 fallback（数据重启后丢失）');
  // 内存 fallback：提供兼容 API 的极简内存数据库
  const memTables = {};
  const memSeq = {};
  db = {
    exec: (sql) => {
      const tm = sql.match(/CREATE TABLE IF NOT EXISTS\s+(\w+)/gi);
      if (tm) tm.forEach(m => {
        const t = m.replace(/CREATE TABLE IF NOT EXISTS\s+/i, '');
        if (!memTables[t]) { memTables[t] = []; memSeq[t] = 1; }
      });
    },
    pragma: () => {},
    prepare: (sql) => ({
      get: (...p) => {
        if (sql.includes('COUNT(*)')) return { count: 0 };
        const tm = sql.match(/FROM\s+(\w+)/i);
        const t = tm ? memTables[tm[1]] : [];
        const wm = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
        if (wm && t) {
          const c = wm[1], v = p[0];
          return t.find(r => String(r[c]) === String(v));
        }
        return t ? t[0] : undefined;
      },
      all: (...p) => {
        const tm = sql.match(/FROM\s+(\w+)/i);
        if (!tm) return [];
        let r = [...(memTables[tm[1]] || [])];
        const wm = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
        if (wm) { const c = wm[1], v = p.shift(); r = r.filter(x => String(x[c]) === String(v)); }
        const om = sql.match(/ORDER BY\s+(\w+)\s*(DESC|ASC)?/i);
        if (om) {
          const c = om[1], d = om[2]?.toUpperCase() === 'DESC';
          r.sort((a, b) => { if (a[c] < b[c]) return d ? 1 : -1; if (a[c] > b[c]) return d ? -1 : 1; return 0; });
        }
        const lm = sql.match(/LIMIT\s+(\?|\d+)/i);
        const om2 = sql.match(/OFFSET\s+(\?|\d+)/i);
        let lim = r.length, off = 0;
        if (lm) lim = parseInt(lm[1]) || p.shift() || r.length;
        if (om2) off = parseInt(om2[1]) || p.shift() || 0;
        return r.slice(off, off + lim);
      },
      run: (...p) => {
        const im = sql.match(/INSERT INTO\s+(\w+)/i);
        const um = sql.match(/UPDATE\s+(\w+)/i);
        const dm = sql.match(/DELETE FROM\s+(\w+)/i);
        if (im) {
          const t = im[1];
          if (!memTables[t]) { memTables[t] = []; memSeq[t] = 1; }
          const cm = sql.match(/\(([^)]+)\)\s*VALUES/i);
          const cols = cm ? cm[1].split(',').map(c => c.trim()) : [];
          const row = { id: memSeq[t]++ };
          cols.forEach((c, i) => { row[c] = p[i]; });
          memTables[t].push(row);
          return { changes: 1, lastInsertRowid: row.id };
        }
        if (um || dm) {
          const t = (um || dm)[1];
          const before = memTables[t]?.length || 0;
          if (dm) memTables[t] = [];
          return { changes: before, lastInsertRowid: 0 };
        }
        return { changes: 0, lastInsertRowid: 0 };
      }
    })
  };
}

// 建表（SQLite 或内存模式通用）
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

  CREATE TABLE IF NOT EXISTS download_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    file_name TEXT NOT NULL,
    description TEXT,
    version TEXT,
    file_size TEXT,
    icon TEXT DEFAULT '📦',
    download_url TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, file_name, download_url)
  );

  CREATE TABLE IF NOT EXISTS site_content (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    section TEXT UNIQUE NOT NULL,
    title TEXT,
    content TEXT,
    is_active INTEGER DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS repository_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'default',
    icon TEXT DEFAULT '📁',
    repo_url TEXT,
    download_url TEXT,
    version TEXT,
    stars INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, repo_url)
  );

  CREATE INDEX IF NOT EXISTS idx_download_links_active ON download_links(is_active);
  CREATE INDEX IF NOT EXISTS idx_repo_items_active ON repository_items(is_active);
  CREATE INDEX IF NOT EXISTS idx_repo_items_category ON repository_items(category);
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

// 初始化默认官网内容
const defaultContents = [
  ['hero_title', '极风工作室', '专注于极致体验的创作团队', 'JIFENG STUDIO', 1],
  ['hero_subtitle', '安全·高效·创新', '极致的安全防护与用户体验', 'SECURE · EFFICIENT', 1],
  ['announcement', '欢迎访问极风工作室', '本站采用多重安全防护机制，为您提供安全的下载与浏览体验', 'Welcome', 1],
  ['about', '关于极风', '我们是一支专注于数字产品开发的团队，致力于为用户提供高品质的软件与服务。', 'About', 1],
  ['footer', '© 2026 极风工作室', '保留所有权利', 'Footer', 1]
];
const insertContent = db.prepare('INSERT OR IGNORE INTO site_content (section, title, content, is_active, updated_at) VALUES (?, ?, ?, ?, datetime(\'now\'))');
for (const [section, title, content, , is_active] of defaultContents) {
  insertContent.run(section, title, content, is_active);
}

// 初始化默认下载链接
const defaultDownloads = [
  ['极风工具箱', 'jifeng-toolbox-v1.2.0.zip', '多功能系统工具集合', '1.2.0', '45MB', '🛠️', '/download/serve/jifeng-toolbox-v1.2.0.zip', 1, 0],
  ['极风安全助手', 'jifeng-security-v2.0.0.zip', '全方位安全防护解决方案', '2.0.0', '38MB', '🛡️', '/download/serve/jifeng-security-v2.0.0.zip', 1, 1],
  ['极风开发套件', 'jifeng-dev-kit-v0.9.5.zip', '开发者辅助工具包', '0.9.5', '22MB', '💻', '/download/serve/jifeng-dev-kit-v0.9.5.zip', 1, 2]
];
const insertDownload = db.prepare('INSERT OR IGNORE INTO download_links (name, file_name, description, version, file_size, icon, download_url, is_active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
for (const d of defaultDownloads) {
  insertDownload.run(...d);
}

// 初始化默认仓库项
const defaultRepos = [
  ['极风工具箱', '系统优化与清理工具', 'tool', '🛠️', 'https://github.com/jifeng/toolbox', '/download/serve/jifeng-toolbox.zip', '1.2.0', 128, 1, 0],
  ['极风安全中心', '多维度安全防护工具', 'security', '🛡️', 'https://github.com/jifeng/security', '/download/serve/jifeng-security.zip', '2.0.0', 256, 1, 1],
  ['极风UI组件库', '现代化前端UI组件', 'library', '🎨', 'https://github.com/jifeng/ui', '', '3.1.0', 512, 1, 2]
];
const insertRepo = db.prepare('INSERT OR IGNORE INTO repository_items (name, description, category, icon, repo_url, download_url, version, stars, is_active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
for (const r of defaultRepos) {
  insertRepo.run(...r);
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
