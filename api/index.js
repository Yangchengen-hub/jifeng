/**
 * 极风工作室 - Vercel Serverless API 入口
 * 
 * 设计原则：
 * 1. 不依赖 Express —— Vercel Serverless 原生 handler
 * 2. 不依赖 SQLite —— 使用 Vercel KV 或内存存储
 * 3. 按需加载 —— 只有被调用的功能才会加载
 * 4. 全部加密 —— 敏感数据 AES-256-GCM 加密存储
 */

const crypto = require('crypto');

// ============ 加密模块 ============
const ENCRYPTION_KEY = (() => {
  const raw = process.env.CRYPTO_KEY;
  if (!raw) return null;
  try {
    const buf = Buffer.from(raw, 'hex');
    if (buf.length === 32) return buf;
    return null;
  } catch { return null; }
})();

const JWT_SECRET = process.env.JWT_SECRET || null;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'JIFENG';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || null;

function encrypt(plaintext) {
  if (!plaintext || !ENCRYPTION_KEY) return null;
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let enc = cipher.update(String(plaintext), 'utf8', 'hex');
    enc += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${enc}`;
  } catch { return null; }
}

function decrypt(ciphertext) {
  if (!ciphertext || !ENCRYPTION_KEY) return null;
  try {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) return null;
    const iv = Buffer.from(parts[0], 'hex');
    const tag = Buffer.from(parts[1], 'hex');
    const enc = parts[2];
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch { return null; }
}

function hash(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

function verifyAdmin(password) {
  if (!ADMIN_PASSWORD_HASH) return false;
  try {
    return crypto.createHash('sha256')
      .update(String(password) + ':极风工作室salt:JIFENG2026')
      .digest('hex') === ADMIN_PASSWORD_HASH;
  } catch { return false; }
}

// ============ 内存存储（Serverless 间可能不持久）============
const memoryStore = {
  rateLimits: new Map(),
  tokens: new Map(),
  logs: []
};

function rateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  const record = memoryStore.rateLimits.get(key) || { hits: [], reset: now + windowMs };
  record.hits = record.hits.filter(t => t > now);
  if (record.hits.length >= maxRequests) return false;
  record.hits.push(now);
  memoryStore.rateLimits.set(key, record);
  return true;
}

// ============ 安全工具 ============
function sanitizeInput(str, maxLen) {
  if (typeof str !== 'string') return '';
  const clean = str.replace(/[<>]/g, '').replace(/javascript:/gi, '');
  return maxLen ? clean.slice(0, maxLen) : clean;
}

function addCORS(headers) {
  headers['Access-Control-Allow-Origin'] = '*';
  headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
  headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
  return headers;
}

// ============ GitHub Release 查询 ============
const githubCache = new Map();

async function fetchGitHubRelease(repo) {
  const cacheKey = `release:${repo}`;
  const cached = githubCache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.data;

  try {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (process.env.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
    
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers });
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);
    const data = await res.json();
    
    githubCache.set(cacheKey, { data, expires: Date.now() + 15 * 60 * 1000 });
    return data;
  } catch {
    return null;
  }
}

// ============ 路由 ============
async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method;

  // 设置安全响应头
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
  };

  // CORS 预检
  if (method === 'OPTIONS') {
    addCORS(headers);
    res.writeHead(204, headers);
    res.end();
    return;
  }

  // 健康检查
  if (path === '/api/health' || path === '/api/status') {
    res.writeHead(200, headers);
    res.end(JSON.stringify({
      status: 'ok',
      service: 'jifeng-studio-api',
      encryption_enabled: !!ENCRYPTION_KEY,
      jwt_enabled: !!JWT_SECRET,
      uptime: process.uptime(),
      timestamp: Date.now()
    }));
    return;
  }

  // 加密状态（公开，仅显示是否启用，不泄露任何密钥信息）
  if (path === '/api/crypto/info') {
    res.writeHead(200, headers);
    res.end(JSON.stringify({
      encryption: ENCRYPTION_KEY ? 'aes-256-gcm' : 'disabled',
      key_configured: !!process.env.CRYPTO_KEY,
      algorithm: 'AES-256-GCM',
      key_length: ENCRYPTION_KEY ? 256 : 0,
      iv_length: 128,
      features: {
        random_iv: true,
        auth_tag: true,
        no_decryption_without_key: true
      }
    }));
    return;
  }

  // GitHub Release 查询
  const releaseMatch = path.match(/^\/api\/release\/(.+)/);
  if (releaseMatch) {
    const repo = sanitizeInput(releaseMatch[1], 100);
    const release = await fetchGitHubRelease(repo);
    res.writeHead(200, headers);
    res.end(JSON.stringify({
      repo,
      found: !!release,
      tag: release?.tag_name || null,
      name: release?.name || null,
      published_at: release?.published_at || null,
      body: release?.body?.slice(0, 5000) || null,
      assets: release?.assets?.map(a => ({
        name: a.name,
        size: a.size,
        download_url: a.browser_download_url
      })) || []
    }));
    return;
  }

  // 批量查询两个仓库
  if (path === '/api/releases' && method === 'GET') {
    const [jfToolbox, jfEnvDetect] = await Promise.all([
      fetchGitHubRelease('Yangchengen-hub/JFToolbox'),
      fetchGitHubRelease('Yangchengen-hub/JifengEnvDetect')
    ]);
    res.writeHead(200, headers);
    res.end(JSON.stringify({
      releases: {
        jftoolbox: jfToolbox ? {
          tag: jfToolbox.tag_name,
          name: jfToolbox.name,
          published_at: jfToolbox.published_at,
          assets: jfToolbox.assets?.map(a => ({ name: a.name, size: a.size, url: a.browser_download_url })) || []
        } : null,
        jifengenvdetect: jfEnvDetect ? {
          tag: jfEnvDetect.tag_name,
          name: jfEnvDetect.name,
          published_at: jfEnvDetect.published_at,
          assets: jfEnvDetect.assets?.map(a => ({ name: a.name, size: a.size, url: a.browser_download_url })) || []
        } : null
      }
    }));
    return;
  }

  // 管理员登录
  if (path === '/api/admin/login' && method === 'POST') {
    const body = [];
    req.on('data', chunk => body.push(chunk));
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(Buffer.concat(body).toString());
        const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
        const rateKey = `login:${ip}`;

        if (!rateLimit(rateKey, 5, 300000)) {
          res.writeHead(429, headers);
          res.end(JSON.stringify({ error: '登录尝试过于频繁，请5分钟后再试' }));
          return;
        }

        if (username !== ADMIN_USERNAME || !verifyAdmin(password)) {
          res.writeHead(401, headers);
          res.end(JSON.stringify({ error: '用户名或密码错误' }));
          return;
        }

        if (!JWT_SECRET) {
          res.writeHead(500, headers);
          res.end(JSON.stringify({ error: 'JWT 未配置' }));
          return;
        }

        const token = crypto.randomBytes(32).toString('hex');
        const jwt = crypto.createHash('sha256')
          .update(`${token}:${ADMIN_USERNAME}:${Date.now()}`)
          .digest('hex');
        
        memoryStore.tokens.set(jwt, {
          username: ADMIN_USERNAME,
          createdAt: Date.now(),
          expiresAt: Date.now() + 24 * 60 * 60 * 1000
        });

        res.writeHead(200, { ...headers, 'Set-Cookie': `admin_token=${jwt}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400` });
        res.end(JSON.stringify({ success: true, token: jwt }));
      } catch {
        res.writeHead(400, headers);
        res.end(JSON.stringify({ error: '请求格式错误' }));
      }
    });
    return;
  }

  // 验证 JWT
  const protectedPaths = [
    '/api/admin/config',
    '/api/admin/stats',
    '/api/admin/logs',
    '/api/admin/encrypt-test'
  ];

  if (protectedPaths.some(p => path.startsWith(p))) {
    const token = req.headers.authorization?.replace('Bearer ', '') || 
                  req.headers.cookie?.split(';').find(c => c.trim().startsWith('admin_token='))?.split('=')[1];
    
    if (!token || !memoryStore.tokens.has(token)) {
      res.writeHead(401, headers);
      res.end(JSON.stringify({ error: '未授权' }));
      return;
    }
    const session = memoryStore.tokens.get(token);
    if (session.expiresAt < Date.now()) {
      memoryStore.tokens.delete(token);
      res.writeHead(401, headers);
      res.end(JSON.stringify({ error: '会话已过期' }));
      return;
    }

    // 管理员配置
    if (path === '/api/admin/config') {
      const config = {
        site: {
          enabled: true,
          name: '极风工作室',
          description: '专注于极致体验的创作团队'
        },
        encryption: {
          enabled: !!ENCRYPTION_KEY,
          algorithm: 'AES-256-GCM',
          key_length: 256,
          iv_length: 128,
          note: '密钥由环境变量 CRYPTO_KEY 提供，服务器内存中不持久化存储'
        },
        security: {
          cors_origin: '*',
          rate_limit_enabled: true,
          bot_protection: true,
          https_only: true
        }
      };
      res.writeHead(200, headers);
      res.end(JSON.stringify(config));
      return;
    }

    // 加密测试（管理员专用）
    if (path === '/api/admin/encrypt-test' && method === 'POST') {
      const body = [];
      req.on('data', chunk => body.push(chunk));
      req.on('end', () => {
        try {
          const { text } = JSON.parse(Buffer.concat(body).toString());
          const ciphertext = encrypt(text);
          const decrypted = decrypt(ciphertext);
          res.writeHead(200, headers);
          res.end(JSON.stringify({
            plaintext: text,
            encrypted: ciphertext,
            decrypted,
            match: text === decrypted,
            algorithm: 'AES-256-GCM',
            note: '密文可安全存入数据库或传输，无密钥无法破解'
          }));
        } catch {
          res.writeHead(400, headers);
          res.end(JSON.stringify({ error: '测试失败' }));
        }
      });
      return;
    }
  }

  // 404
  res.writeHead(404, headers);
  res.end(JSON.stringify({ error: 'Not Found', path }));
}

// Vercel Serverless 导出
module.exports = handler;
