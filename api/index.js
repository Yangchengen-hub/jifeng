/**
 * 极风工作室 - Vercel Serverless (Catch-All Handler)
 * 
 * 功能：
 * 1. 处理所有 /api/* 路由（登录、CRUD、Release 查询、健康检查）
 * 2. 处理所有非 API 路由，返回静态文件 (index.html / admin.html / 图片 / CSS / JS)
 * 3. 密码哈希盐值与 Cloudflare Worker 版本保持一致
 * 4. 响应格式与前端完全兼容 (data/links/contents/repos 多 key 返回)
 * 
 * 安全：
 * - 所有密钥来自环境变量，代码零硬编码
 * - 密码使用 SHA-256 + 专用盐值
 * - Token 使用 HMAC-SHA256 签名
 * - 完整安全响应头
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============ 配置 ============

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PUBLIC_FOLDERS = [PROJECT_ROOT, path.join(PROJECT_ROOT, 'public')];

const CRYPTO_KEY_BUF = (() => {
  try {
    const raw = process.env.CRYPTO_KEY;
    if (!raw) return null;
    const buf = Buffer.from(raw, 'hex');
    return buf.length === 32 ? buf : null;
  } catch { return null; }
})();

const JWT_SECRET = process.env.JWT_SECRET || null;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'JIFENG';
// 管理员专用盐值（与 Cloudflare Worker 版本保持完全一致）
const PASSWORD_SALT = ':JIFENG-salt-2026';
// 密码哈希：优先使用 ADMIN_PASSWORD_HASH（生产），否则由 ADMIN_PASSWORD 实时计算（开发/便捷部署）
function sha256(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}
const ADMIN_PASSWORD_HASH = (() => {
  if (process.env.ADMIN_PASSWORD_HASH) return String(process.env.ADMIN_PASSWORD_HASH);
  if (process.env.ADMIN_PASSWORD) return sha256(String(process.env.ADMIN_PASSWORD) + PASSWORD_SALT);
  return null;
})();
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || null;

function hmacSha256(keyStr, message) {
  return crypto.createHmac('sha256', String(keyStr)).update(String(message)).digest('hex');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function verifyAdminPassword(password) {
  if (!ADMIN_PASSWORD_HASH) return false;
  return sha256(String(password) + PASSWORD_SALT) === String(ADMIN_PASSWORD_HASH);
}

function createAdminToken() {
  if (!JWT_SECRET) return null;
  const token = randomToken(32);
  const timestamp = Date.now();
  const signature = hmacSha256(JWT_SECRET, token + ':' + timestamp);
  return token + '.' + timestamp + '.' + signature;
}

function verifyAdminToken(token) {
  if (!token || !JWT_SECRET) return false;
  const parts = String(token).split('.');
  if (parts.length !== 3) return false;
  const [t, tsStr, sig] = parts;
  if (hmacSha256(JWT_SECRET, t + ':' + tsStr) !== sig) return false;
  const ts = parseInt(tsStr, 10);
  if (isNaN(ts)) return false;
  if (Date.now() - ts > 24 * 60 * 60 * 1000) return false;
  return true;
}

function encrypt(plaintext) {
  if (!plaintext || !CRYPTO_KEY_BUF) return null;
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', CRYPTO_KEY_BUF, iv);
    let enc = cipher.update(String(plaintext), 'utf8', 'hex');
    enc += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc;
  } catch { return null; }
}

function decrypt(ciphertext) {
  if (!ciphertext || !CRYPTO_KEY_BUF) return null;
  try {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) return null;
    const iv = Buffer.from(parts[0], 'hex');
    const tag = Buffer.from(parts[1], 'hex');
    const enc = parts[2];
    const decipher = crypto.createDecipheriv('aes-256-gcm', CRYPTO_KEY_BUF, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch { return null; }
}

// ============ 存储（内存 + 文件持久化后备） ============

const MEM_STORE = {
  rateLimit: new Map(),
  tokens: new Map(),
  kv: new Map(),
  ghReleaseCache: new Map()
};

const PERSIST_DIR = process.env.KV_PERSIST_DIR || path.join(PROJECT_ROOT, '.vercel-kv');
try { fs.mkdirSync(PERSIST_DIR, { recursive: true }); } catch (_) {}

function persistPath(k) { return path.join(PERSIST_DIR, encodeURIComponent(k) + '.json'); }

function kvGet(k) {
  // 内存优先
  if (MEM_STORE.kv.has(k)) return MEM_STORE.kv.get(k);
  // 文件后备
  try {
    const p = persistPath(k);
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, 'utf8');
      const v = JSON.parse(raw);
      MEM_STORE.kv.set(k, v);
      return v;
    }
  } catch (_) {}
  return null;
}

function kvSet(k, v) {
  MEM_STORE.kv.set(k, v);
  try { fs.writeFileSync(persistPath(k), JSON.stringify(v), 'utf8'); } catch (_) {}
  return true;
}

function checkRateLimit(key, max, windowMs) {
  const now = Date.now();
  const rec = MEM_STORE.rateLimit.get(key) || { hits: [] };
  rec.hits = rec.hits.filter(t => t > now - windowMs);
  if (rec.hits.length >= max) return false;
  rec.hits.push(now);
  MEM_STORE.rateLimit.set(key, rec);
  return true;
}

// ============ GitHub Release 查询 ============

async function fetchGitHubRelease(repo) {
  const cacheKey = 'release:' + repo;
  const cached = MEM_STORE.ghReleaseCache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.data;
  try {
    const headers = { 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'jifeng-studio-vercel' };
    if (GITHUB_TOKEN) headers['Authorization'] = 'Bearer ' + GITHUB_TOKEN;
    const u = 'https://api.github.com/repos/' + repo + '/releases/latest';
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(u, { headers, signal: controller.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    const data = await res.json();
    MEM_STORE.ghReleaseCache.set(cacheKey, { data, expires: Date.now() + 15 * 60 * 1000 });
    return data;
  } catch {
    return null;
  }
}

// ============ HTTP 工具 ============

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip'
};

function getMimeType(p) {
  const i = p.lastIndexOf('.');
  if (i < 0) return 'application/octet-stream';
  return MIME_TYPES[p.substring(i).toLowerCase()] || 'application/octet-stream';
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
  };
}

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
  };
}

function jsonResponse(res, data, status = 200, extra = {}) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    ...corsHeaders(),
    ...securityHeaders(),
    ...extra
  };
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function htmlEscape(str) {
  return String(str).replace(/[<>"'&]/g, c => ({
    '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'
  }[c]));
}

function errPageHTML(msg, code) {
  const safe = htmlEscape(msg);
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${code} - 极风官网</title>
<style>
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:linear-gradient(135deg,#0a0a0f,#1a1a2e);color:#e8e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.box{text-align:center;padding:40px;max-width:600px}
h1{font-size:96px;margin:0;background:linear-gradient(135deg,#00f5ff,#7b2ff7);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:900}
p{opacity:.8;margin:16px 0;line-height:1.6;font-size:16px}
.err-msg{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:20px;margin:20px 0;font-family:monospace;font-size:13px;white-space:pre-wrap;text-align:left;word-break:break-all}
a{color:#00f5ff;text-decoration:none;border:1px solid #00f5ff;padding:8px 20px;border-radius:8px;display:inline-block;margin-top:16px;transition:all .2s}
a:hover{background:#00f5ff;color:#0a0a0f}
.brand{font-size:13px;letter-spacing:6px;opacity:.3;margin-top:40px}
</style></head><body><div class="box">
<h1>${code}</h1><p>抱歉，出现了一个问题</p>
<div class="err-msg">${safe}</div>
<a href="/">← 返回极风官网</a>
<p class="brand">极风官网 · JIFENG STUDIO</p>
</div></body></html>`;
}

function sendErrorPage(res, msg, code) {
  res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders(), ...securityHeaders() });
  res.end(errPageHTML(msg, code));
}

// ============ 静态文件服务 ============

const ADMIN_REDIRECTS = new Set(['/dashboard.html', '/jftoolbox.html', '/jifengenvdetect.html']);

// 绝对禁止对外服务的扩展名（源码/密钥/部署脚本泄露防护）
const BLOCKED_EXTENSIONS = new Set([
  '.py', '.sh', '.env', '.json5', '.toml', '.yaml', '.yml',
  '.ini', '.cfg', '.conf', '.log', '.sql', '.db', '.sqlite',
  '.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.ejs',
  '.ps1', '.bat', '.cmd', '.reg', '.tar', '.gz', '.tgz',
  '.rar', '.7z'
]);
// 绝对禁止对外服务的文件名（即使扩展名是安全的）
const BLOCKED_FILENAMES = new Set([
  '_worker_meta.json', 'package.json', 'package-lock.json',
  'vercel.json', 'render.yaml', '.gitignore', 'DEPLOY_GUIDE.md',
  'README.md', 'kv-data.json',
  // Worker 脚本
  'worker-secure.js', 'worker.js', 'worker-bundle.js',
  '_worker_full.js', 'deployed_worker.js', 'deployed_worker_fixed.js',
  // 部署脚本
  'deploy_worker.py', 'deploy_worker_v2.py', 'deploy_v2.py', 'deploy_v3.py',
  'deploy_final.py', 'deploy_final2.py', 'deploy_final3.py', 'deploy_final4.py',
  'upload_kv.py', 'upload_kv2.py', 'build-worker.js', 'bulk-upload-gen.js',
  'direct-kv-upload.js', 'gen-batched-upload.js', 'gen-code.py', 'gen-codes.js',
  'gen-fast-upload.js', 'gen-final-uploads.js', 'gen-individual.js',
  'gen-upload-data.js', 'prepare-batches.js', 'upload-to-kv.js',
  'gen-code.py',
  // 批量数据
  'batch-1.js', 'batch-1.json', 'batch-2.js', 'batch-2.json',
  'batch-3.js', 'batch-3.json', 'batch-4.js', 'batch-4.json',
  'generated-codes.json', 'summary.json',
  // 其他
  'admin-api.js', 'anti-debug.js',
  'blocked.ejs'
]);
// 禁止访问的路径前缀
const BLOCKED_PREFIXES = [
  '/api/', '/src/', '/views/', '/tmp-batches/', '/.vercel-kv/',
  '/.git/', '/js/', '/public/', '/gitee-pages/'
];

function findStaticFile(relPath) {
  let p = relPath === '/' || relPath === '' ? '/index.html' : relPath;
  // 安全：防路径穿越
  if (p.includes('..') || p.includes('\0')) return null;
  // 安全：泄露防护 - 禁止访问的前缀
  for (const prefix of BLOCKED_PREFIXES) {
    if (p.startsWith(prefix)) return null;
  }
  const lowerP = p.toLowerCase();
  // 安全：泄露防护 - 禁止扩展名
  const dotIdx = lowerP.lastIndexOf('.');
  if (dotIdx >= 0 && BLOCKED_EXTENSIONS.has(lowerP.substring(dotIdx))) {
    return null;
  }
  // 安全：泄露防护 - 禁止特定文件名
  const baseName = p.substring(p.lastIndexOf('/') + 1);
  if (BLOCKED_FILENAMES.has(baseName)) return null;
  for (const folder of PUBLIC_FOLDERS) {
    const full = path.normalize(path.join(folder, '.' + p));
    if (!full.startsWith(folder)) continue;
    try {
      if (fs.existsSync(full) && fs.statSync(full).isFile()) return full;
    } catch (_) {}
  }
  return null;
}

function serveStatic(res, reqPath) {
  // 管理入口重定向
  if (ADMIN_REDIRECTS.has(reqPath)) {
    res.writeHead(302, { Location: '/admin.html', ...securityHeaders() });
    res.end();
    return true;
  }
  const filePath = findStaticFile(reqPath);
  if (!filePath) return false;
  try {
    const data = fs.readFileSync(filePath);
    const contentType = getMimeType(filePath);
    const isHTML = contentType.includes('text/html');
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': String(data.length),
      'Cache-Control': isHTML ? 'no-cache, must-revalidate' : 'public, max-age=1800',
      ...corsHeaders(),
      ...securityHeaders()
    });
    res.end(data);
    return true;
  } catch (e) {
    return false;
  }
}

// ============ API 路由处理 ============

function getTokenFromRequest(req) {
  const authH = req.headers['authorization'] || '';
  const cookieH = req.headers['cookie'] || '';
  const fromAuth = authH.startsWith('Bearer ') ? authH.slice(7) : '';
  if (fromAuth) return fromAuth;
  const m = String(cookieH).match(/admin_token=([^;]+)/);
  return m ? m[1] : '';
}

async function readJSONBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    const MAX_BYTES = 512 * 1024; // 512KB 上限
    req.on('data', c => {
      chunks.push(c);
      totalBytes += c.length;
      if (totalBytes > MAX_BYTES) reject(new Error('body too large'));
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) { reject(e); }
    });
    req.on('error', reject);
    setTimeout(() => reject(new Error('timeout')), 10000);
  });
}

function makeCRUDResponse(list) {
  return {
    data: list, links: list, contents: list, repos: list,
    items: list, list: list, total: list.length
  };
}

async function handleCRUD(kvKey, idPart, method, req) {
  let list = kvGet(kvKey);
  if (!Array.isArray(list)) list = [];

  if (method === 'GET' && !idPart) {
    return { status: 200, data: makeCRUDResponse(list) };
  }
  if (method === 'POST' && !idPart) {
    try {
      const body = await readJSONBody(req);
      const item = { id: randomToken(8), ...body, created_at: new Date().toISOString() };
      list.push(item);
      kvSet(kvKey, list);
      return { status: 200, data: { success: true, data: item, item } };
    } catch {
      return { status: 400, data: { error: '请求格式错误' } };
    }
  }
  if (idPart) {
    const idx = list.findIndex(x => x && x.id === idPart);
    if (method === 'GET' && idx >= 0) {
      return { status: 200, data: { data: list[idx], item: list[idx] } };
    }
    if (method === 'PUT' && idx >= 0) {
      try {
        const body = await readJSONBody(req);
        list[idx] = { ...list[idx], ...body, updated_at: new Date().toISOString() };
        kvSet(kvKey, list);
        return { status: 200, data: { success: true, data: list[idx], item: list[idx] } };
      } catch {
        return { status: 400, data: { error: '请求格式错误' } };
      }
    }
    if (method === 'DELETE' && idx >= 0) {
      list.splice(idx, 1);
      kvSet(kvKey, list);
      return { status: 200, data: { success: true } };
    }
  }
  return { status: 404, data: { error: 'Not Found', id: idPart || null } };
}

async function handleApi(req, res, url) {
  const path = url.pathname;
  const method = req.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    res.end();
    return true;
  }

  // 健康检查
  if (path === '/api/health' || path === '/api/status') {
    jsonResponse(res, {
      status: 'ok', service: 'jifeng-studio-vercel', runtime: 'vercel-node',
      kv_mode: 'memory+file', timestamp: Date.now()
    });
    return true;
  }

  // 加密信息
  if (path === '/api/crypto/info') {
    jsonResponse(res, {
      encryption: CRYPTO_KEY_BUF ? 'aes-256-gcm' : 'disabled',
      algorithm: 'SHA-256(password) + HMAC-SHA256(token)',
      key_configured: !!CRYPTO_KEY_BUF,
      features: {
        password_hashing: true, token_signing: true,
        no_hardcoded_secrets: true, environment_variables_only: true
      }
    });
    return true;
  }

  // GitHub Release 单仓库
  const relMatch = path.match(/^\/api\/release\/(.+)$/);
  if (relMatch && method === 'GET') {
    const repo = String(relMatch[1]).replace(/[^a-zA-Z0-9._/\-]/g, '').slice(0, 120);
    if (!repo) { jsonResponse(res, { error: '无效仓库' }, 400); return true; }
    const r = await fetchGitHubRelease(repo);
    jsonResponse(res, {
      repo, found: !!r, tag: r ? r.tag_name : null, name: r ? r.name : null,
      published_at: r ? r.published_at : null,
      body: r ? (r.body || '').slice(0, 5000) : null,
      assets: r ? (r.assets || []).map(a => ({
        name: a.name, size: a.size, download_url: a.browser_download_url
      })) : []
    });
    return true;
  }

  // 批量 Release 查询
  if (path === '/api/releases' && method === 'GET') {
    const [jf, env] = await Promise.all([
      fetchGitHubRelease('Yangchengen-hub/JFToolbox'),
      fetchGitHubRelease('Yangchengen-hub/JifengEnvDetect')
    ]);
    jsonResponse(res, {
      releases: {
        jftoolbox: jf ? {
          tag: jf.tag_name, name: jf.name, published_at: jf.published_at,
          assets: (jf.assets || []).map(a => ({ name: a.name, size: a.size, url: a.browser_download_url }))
        } : null,
        jifengenvdetect: env ? {
          tag: env.tag_name, name: env.name, published_at: env.published_at,
          assets: (env.assets || []).map(a => ({ name: a.name, size: a.size, url: a.browser_download_url }))
        } : null
      }
    });
    return true;
  }

  // 公开：下载链接列表（下载页/首页使用）
  if (path === '/api/download-links' && method === 'GET') {
    const list = Array.isArray(kvGet('download_links')) ? kvGet('download_links') : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    const out = active.map(x => ({
      id: x.id, name: x.name, file_name: x.file_name,
      download_url: x.download_url, icon: x.icon || '📦',
      version: x.version || '', file_size: x.file_size || '',
      description: x.description || '', sort_order: Number(x.sort_order) || 0,
      created_at: x.created_at
    }));
    jsonResponse(res, makeCRUDResponse(out));
    return true;
  }

  // 公开：站点内容（首页/其他页面引用）
  if (path === '/api/site-content' && method === 'GET') {
    const list = Array.isArray(kvGet('site_content')) ? kvGet('site_content') : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    jsonResponse(res, makeCRUDResponse(active));
    return true;
  }

  // 公开：仓库列表（展示页用）
  if (path === '/api/repository' && method === 'GET') {
    const list = Array.isArray(kvGet('repositories')) ? kvGet('repositories') : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    jsonResponse(res, makeCRUDResponse(active));
    return true;
  }

  // 管理员登录
  if (path === '/api/admin/login' && method === 'POST') {
    const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim()
            || (req.socket && req.socket.remoteAddress) || 'unknown';
    if (!checkRateLimit('login:' + ip, 5, 5 * 60 * 1000)) {
      jsonResponse(res, { error: '登录尝试过于频繁，请5分钟后再试' }, 429);
      return true;
    }
    try {
      const body = await readJSONBody(req);
      const u = String(body.username || '');
      const p = String(body.password || '');
      if (u !== ADMIN_USERNAME || !verifyAdminPassword(p)) {
        jsonResponse(res, { error: '用户名或密码错误' }, 401);
        return true;
      }
      const token = createAdminToken();
      if (!token) { jsonResponse(res, { error: 'JWT 未配置' }, 500); return true; }
      jsonResponse(res, { success: true, token }, 200, {
        'Set-Cookie': 'admin_token=' + token + '; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/'
      });
      return true;
    } catch {
      jsonResponse(res, { error: '请求格式错误' }, 400);
      return true;
    }
  }

  // 认证守卫
  const token = getTokenFromRequest(req);
  const isAdmin = verifyAdminToken(token);
  if (path.startsWith('/api/admin/') && path !== '/api/admin/login' && !isAdmin) {
    jsonResponse(res, { error: '未授权，请先登录' }, 401);
    return true;
  }

  // 管理员配置
  if (path === '/api/admin/config' && method === 'GET') {
    jsonResponse(res, {
      site: { enabled: true, name: '极风工作室', description: '专注于极致体验的创作团队' },
      encryption: { enabled: !!CRYPTO_KEY_BUF, algorithm: 'SHA-256 + HMAC-SHA256', note: '密钥来自 Vercel 环境变量' },
      security: { cors_origin: '*', rate_limit_enabled: true, https_only: true }
    });
    return true;
  }

  // CRUD: 下载链接
  if (path === '/api/admin/download-links' || path.startsWith('/api/admin/download-links/')) {
    const id = path.startsWith('/api/admin/download-links/') ? path.slice('/api/admin/download-links/'.length) : '';
    const r = await handleCRUD('download_links', id, method, req);
    jsonResponse(res, r.data, r.status);
    return true;
  }
  // CRUD: 站点内容
  if (path === '/api/admin/site-content' || path.startsWith('/api/admin/site-content/')) {
    const id = path.startsWith('/api/admin/site-content/') ? path.slice('/api/admin/site-content/'.length) : '';
    const r = await handleCRUD('site_content', id, method, req);
    jsonResponse(res, r.data, r.status);
    return true;
  }
  // CRUD: 仓库
  if (path === '/api/admin/repository' || path.startsWith('/api/admin/repository/')) {
    const id = path.startsWith('/api/admin/repository/') ? path.slice('/api/admin/repository/'.length) : '';
    const r = await handleCRUD('repositories', id, method, req);
    jsonResponse(res, r.data, r.status);
    return true;
  }

  // 统计
  if (path === '/api/admin/stats' && method === 'GET') {
    const links = Array.isArray(kvGet('download_links')) ? kvGet('download_links') : [];
    const content = Array.isArray(kvGet('site_content')) ? kvGet('site_content') : [];
    const repos = Array.isArray(kvGet('repositories')) ? kvGet('repositories') : [];
    jsonResponse(res, {
      download_links: links.length,
      site_content: content.length,
      repositories: repos.length,
      active_links: links.filter(l => l && l.is_active).length
    });
    return true;
  }

  // 加密测试
  if (path === '/api/admin/encrypt-test' && method === 'POST') {
    try {
      const body = await readJSONBody(req);
      const text = String(body.text || '');
      jsonResponse(res, {
        plaintext: text, sha256: sha256(text),
        aes_256_gcm: encrypt(text),
        note: CRYPTO_KEY_BUF ? '使用 AES-256-GCM，密钥由环境变量提供' : '警告：CRYPTO_KEY 未配置，AES 加密未启用'
      });
      return true;
    } catch {
      jsonResponse(res, { error: '测试失败' }, 400);
      return true;
    }
  }

  // 日志
  if (path === '/api/admin/logs' && method === 'GET') {
    jsonResponse(res, { data: [], total: 0, note: 'Vercel 请前往 Dashboard 查看 Runtime Logs' });
    return true;
  }

  // Not Found
  jsonResponse(res, { error: 'Not Found', path }, 404);
  return true;
}

// ============ 主入口 ============

async function handler(req, res) {
  try {
    const url = new URL(req.url, 'https://' + (req.headers.host || 'localhost'));
    const path = url.pathname;

    // CORS 预检 (全局)
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...corsHeaders(), ...securityHeaders() });
      res.end();
      return;
    }

    // API 路由
    if (path.startsWith('/api/')) {
      try {
        await handleApi(req, res, url);
        return;
      } catch (apiErr) {
        jsonResponse(res, {
          error: '服务器内部错误',
          detail: String(apiErr && apiErr.message ? apiErr.message : apiErr)
        }, 500);
        return;
      }
    }

    // 静态文件路由
    const ok = serveStatic(res, path);
    if (ok) return;

    // 404
    sendErrorPage(res, '页面未找到: ' + htmlEscape(path), 404);
  } catch (fatal) {
    sendErrorPage(res, '致命错误: ' + String(fatal && fatal.message ? fatal.message : fatal), 500);
  }
}

module.exports = handler;
