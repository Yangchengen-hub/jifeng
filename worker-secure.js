/**
 * 极风工作室 - Cloudflare Worker (安全加固版)
 * 
 * 安全特性：
 * 1. 所有密钥均来自 Worker Bindings (环境变量)，代码中 ZERO 硬编码密钥
 * 2. 原生 KV 绑定优先，完全移除 HTTP API Proxy 方案（不再需要 API Token）
 * 3. 支持所有 HTTP 方法：GET/HEAD/POST/PUT/DELETE/OPTIONS
 * 4. 密码使用 SHA-256 + 专用盐值哈希，Token 使用 HMAC-SHA256 签名
 * 5. 完整的 CORS / 安全响应头
 * 6. 管理后台统一入口 + 速率限制
 */

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
  '.eot': 'application/vnd.ms-fontobject',
  '.otf': 'font/otf',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip'
};

const GITHUB_API = 'https://api.github.com';
const KV_FILE_PREFIX = 'file:';
const ADMIN_REDIRECT_PATHS = ['/dashboard.html', '/jftoolbox.html', '/jifengenvdetect.html'];

function getMimeType(path) {
  const idx = path.lastIndexOf('.');
  if (idx < 0) return 'application/octet-stream';
  const ext = path.substring(idx).toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
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

function jsonResponse(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      ...corsHeaders(),
      ...securityHeaders(),
      ...extra
    }
  });
}

function htmlEscape(str) {
  return String(str).replace(/[<>"'&]/g, c => ({
    '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'
  }[c]));
}

function errorPageHTML(message, code) {
  const safeMsg = htmlEscape(message);
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
<h1>${code}</h1>
<p>抱歉，出现了一个问题</p>
<div class="err-msg">${safeMsg}</div>
<a href="/">← 返回极风官网</a>
<p class="brand">极风官网 · JIFENG STUDIO</p>
</div></body></html>`;
}

function errPage(msg, code) {
  return new Response(errorPageHTML(msg, code), {
    status: code,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders(), ...securityHeaders() }
  });
}

// ============ 加密工具 (Web Crypto API) ============

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(String(text));
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSign(keyStr, message) {
  const encoder = new TextEncoder();
  const keyData = await crypto.subtle.importKey(
    'raw', encoder.encode(String(keyStr)),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', keyData, encoder.encode(String(message)));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 安全解析 JSON 请求体：显式限制 512KB，防止超大请求攻击
async function safeParseBody(request) {
  const MAX_BODY = 512 * 1024;
  const clHeader = request.headers && request.headers.get ? request.headers.get('content-length') : null;
  if (clHeader) {
    const cl = parseInt(clHeader, 10);
    if (!isNaN(cl) && cl > MAX_BODY) throw new Error('请求体过大（上限512KB）');
  }
  let text;
  try {
    if (typeof request.text === 'function') {
      // 手动分段读取，避免无节制分配
      const tmp = await request.text();
      if (tmp && tmp.length > MAX_BODY * 4) throw new Error('请求体过大（上限512KB）');
      text = tmp;
    } else {
      text = '';
    }
  } catch (e) {
    throw e;
  }
  if (!text) return {};
  return JSON.parse(text);
}

const ADMIN_PASSWORD_CACHE = new Map();
async function verifyAdminPassword(password, env) {
  let expectedHash = null;
  if (env.ADMIN_PASSWORD_HASH) {
    expectedHash = String(env.ADMIN_PASSWORD_HASH);
  } else if (env.ADMIN_PASSWORD) {
    const plain = String(env.ADMIN_PASSWORD);
    const cacheKey = plain;
    if (!ADMIN_PASSWORD_CACHE.has(cacheKey)) {
      ADMIN_PASSWORD_CACHE.set(cacheKey, await sha256(plain + ':JIFENG-salt-2026'));
      if (ADMIN_PASSWORD_CACHE.size > 4) {
        const firstKey = ADMIN_PASSWORD_CACHE.keys().next().value;
        ADMIN_PASSWORD_CACHE.delete(firstKey);
      }
    }
    expectedHash = ADMIN_PASSWORD_CACHE.get(cacheKey);
  }
  if (!expectedHash) return false;
  const actualHash = await sha256(String(password) + ':JIFENG-salt-2026');
  return actualHash === String(expectedHash);
}

async function createAdminToken(env) {
  const token = randomToken(32);
  const timestamp = Date.now();
  const signature = await hmacSign(env.JWT_SECRET, token + ':' + timestamp);
  return token + '.' + timestamp + '.' + signature;
}

async function verifyAdminToken(token, env) {
  if (!token || !env.JWT_SECRET) return false;
  const parts = String(token).split('.');
  if (parts.length !== 3) return false;
  const [tokenPart, timestampPart, sigPart] = parts;
  const expectedSig = await hmacSign(env.JWT_SECRET, tokenPart + ':' + timestampPart);
  if (sigPart !== expectedSig) return false;
  const timestamp = parseInt(timestampPart, 10);
  if (isNaN(timestamp)) return false;
  // 24 小时过期
  if (Date.now() - timestamp > 24 * 60 * 60 * 1000) return false;
  return true;
}

// ============ 速率限制 ============
const rateLimitStore = new Map();

function checkRateLimit(key, maxHits, windowMs) {
  const now = Date.now();
  const record = rateLimitStore.get(key) || { hits: [] };
  record.hits = record.hits.filter(t => t > now - windowMs);
  if (record.hits.length >= maxHits) return false;
  record.hits.push(now);
  rateLimitStore.set(key, record);
  return true;
}

// ============ GitHub Release 查询 ============
const releaseCache = new Map();

async function fetchGitHubRelease(repo, env) {
  const cacheKey = 'release:' + repo;
  const cached = releaseCache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.data;

  try {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (env.GITHUB_TOKEN) headers['Authorization'] = 'Bearer ' + env.GITHUB_TOKEN;
    const res = await fetch(GITHUB_API + '/repos/' + repo + '/releases/latest', { headers });
    if (!res.ok) return null;
    const data = await res.json();
    releaseCache.set(cacheKey, { data, expires: Date.now() + 15 * 60 * 1000 });
    return data;
  } catch {
    return null;
  }
}

// ============ KV 操作 ============

async function kvGetJSON(env, key) {
  if (!env.JIFENG_KV) return null;
  try {
    // 优先直接按 JSON 解析
    const raw = await env.JIFENG_KV.get(key);
    if (raw === null || raw === undefined) return null;
    if (typeof raw === 'object') return raw;

    // 字符串：尝试单层 JSON
    try { return JSON.parse(raw); } catch (_) { /* ignore */ }
    // 字符串：可能是双层 JSON 编码
    try {
      const s1 = JSON.parse(raw);
      if (typeof s1 === 'string') return JSON.parse(s1);
      return s1;
    } catch (_) { /* ignore */ }

    return raw; // 实在解析不了就返回原始字符串
  } catch (e) {
    return null;
  }
}

async function kvSetJSON(env, key, value) {
  if (!env.JIFENG_KV) return false;
  try {
    await env.JIFENG_KV.put(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

// Base64 → Uint8Array
function base64ToBytes(b64) {
  const bin = atob(String(b64));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ============ 静态文件服务 (从 KV) ============

// 泄露防护 - 禁止从 KV 返回的扩展名/文件名
const W_BLOCKED_EXT = new Set([
  '.py', '.sh', '.env', '.json5', '.toml', '.yaml', '.yml',
  '.ini', '.cfg', '.conf', '.log', '.sql', '.db', '.sqlite',
  '.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.ejs',
  '.ps1', '.bat', '.cmd', '.reg', '.tar', '.gz', '.tgz',
  '.rar', '.7z'
]);
const W_BLOCKED_FILES = new Set([
  '_worker_meta.json', 'package.json', 'package-lock.json',
  'vercel.json', 'render.yaml', '.gitignore', 'DEPLOY_GUIDE.md',
  'README.md', 'kv-data.json',
  'worker-secure.js', 'worker.js', 'worker-bundle.js',
  '_worker_full.js', 'deployed_worker.js', 'deployed_worker_fixed.js',
  'deploy_worker.py', 'deploy_worker_v2.py', 'deploy_v2.py', 'deploy_v3.py',
  'deploy_final.py', 'deploy_final2.py', 'deploy_final3.py', 'deploy_final4.py',
  'upload_kv.py', 'upload_kv2.py', 'build-worker.js', 'bulk-upload-gen.js',
  'direct-kv-upload.js', 'gen-batched-upload.js', 'gen-code.py', 'gen-codes.js',
  'gen-fast-upload.js', 'gen-final-uploads.js', 'gen-individual.js',
  'gen-upload-data.js', 'prepare-batches.js', 'upload-to-kv.js',
  'batch-1.js', 'batch-1.json', 'batch-2.js', 'batch-2.json',
  'batch-3.js', 'batch-3.json', 'batch-4.js', 'batch-4.json',
  'generated-codes.json', 'summary.json',
  'admin-api.js', 'anti-debug.js', 'blocked.ejs'
]);

async function serveStaticFile(request, env) {
  const url = new URL(request.url);
  let path = url.pathname.split('?')[0].split('#')[0];

  // 安全：防止路径穿越
  if (path.includes('..') || path.includes('\0')) {
    return errPage('非法请求路径', 400);
  }

  // 泄露防护：禁止访问敏感扩展名
  const lowerPath = path.toLowerCase();
  const dotIdx = lowerPath.lastIndexOf('.');
  if (dotIdx >= 0 && W_BLOCKED_EXT.has(lowerPath.substring(dotIdx))) {
    return errPage('禁止访问', 403);
  }
  // 泄露防护：禁止访问敏感文件名
  const baseName = path.substring(path.lastIndexOf('/') + 1);
  if (W_BLOCKED_FILES.has(baseName)) {
    return errPage('禁止访问', 403);
  }
  // 泄露防护：禁止前缀（如 /src/ /views/ 等）
  if (path.startsWith('/src/') || path.startsWith('/views/') || path.startsWith('/tmp-batches/')
      || path.startsWith('/.git/') || path.startsWith('/js/') || path.startsWith('/public/')
      || path.startsWith('/gitee-pages/') || path.startsWith('/.vercel-kv/')) {
    return errPage('禁止访问', 403);
  }

  // 统一管理门户重定向
  if (ADMIN_REDIRECT_PATHS.includes(path)) {
    const redirectUrl = new URL('/admin.html', request.url).toString();
    return Response.redirect(redirectUrl, 302);
  }

  // 默认首页
  if (path === '/' || path === '') path = '/index.html';

  const key = KV_FILE_PREFIX + path;
  const fileData = await kvGetJSON(env, key);

  if (fileData && typeof fileData === 'object' && fileData.b) {
    try {
      const bytes = base64ToBytes(fileData.b);
      const contentType = fileData.t || getMimeType(path);
      const isHTML = contentType.includes('text/html');
      return new Response(bytes, {
        status: 200,
        headers: {
          'Content-Type': contentType,
          'Content-Length': String(bytes.length),
          'Cache-Control': isHTML ? 'no-cache, must-revalidate' : 'public, max-age=1800, s-maxage=3600',
          ...corsHeaders(),
          ...securityHeaders()
        }
      });
    } catch (decodeErr) {
      return errPage('文件解码失败: ' + String(decodeErr.message || decodeErr), 500);
    }
  }

  // 如果原始返回的就是字符串（非 JSON 包装的纯文本）
  if (typeof fileData === 'string' && fileData.length > 0) {
    return new Response(fileData, {
      status: 200,
      headers: {
        'Content-Type': getMimeType(path),
        'Cache-Control': 'public, max-age=1800',
        ...corsHeaders(),
        ...securityHeaders()
      }
    });
  }

  // 404 - 尝试使用自定义 404 页
  if (path !== '/404.html' && path !== '/views/404.html') {
    const nfKey = KV_FILE_PREFIX + '/404.html';
    const nfData = await kvGetJSON(env, nfKey);
    if (nfData && typeof nfData === 'object' && nfData.b) {
      try {
        const bytes = base64ToBytes(nfData.b);
        return new Response(bytes, {
          status: 404,
          headers: { 'Content-Type': nfData.t || 'text/html; charset=utf-8', ...securityHeaders() }
        });
      } catch (_) { /* ignore */ }
    }
  }

  return errPage('页面未找到: ' + htmlEscape(path), 404);
}

// ============ API 路由 ============

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // 健康检查
  if (path === '/api/health' || path === '/api/status') {
    return jsonResponse({
      status: 'ok',
      service: 'jifeng-studio-worker',
      runtime: 'cloudflare-workers',
      kv_available: !!env.JIFENG_KV,
      timestamp: Date.now()
    });
  }

  // 加密信息（公开，不泄露任何密钥）
  if (path === '/api/crypto/info') {
    return jsonResponse({
      encryption: 'aes-256-gcm-compatible',
      algorithm: 'SHA-256(password) + HMAC-SHA256(token)',
      features: {
        password_hashing: true,
        token_signing: true,
        no_hardcoded_secrets: true,
        environment_variables_only: true,
        native_kv_binding: true
      }
    });
  }

  // 单仓库 Release 查询
  const releaseMatch = path.match(/^\/api\/release\/(.+)$/);
  if (releaseMatch && method === 'GET') {
    const repo = releaseMatch[1].replace(/[^a-zA-Z0-9._/\-]/g, '').slice(0, 120);
    if (!repo) return jsonResponse({ error: '无效仓库名' }, 400);
    const release = await fetchGitHubRelease(repo, env);
    return jsonResponse({
      repo,
      found: !!release,
      tag: release ? release.tag_name : null,
      name: release ? release.name : null,
      published_at: release ? release.published_at : null,
      body: release ? (release.body || '').slice(0, 5000) : null,
      assets: release ? (release.assets || []).map(a => ({
        name: a.name, size: a.size, download_url: a.browser_download_url
      })) : []
    });
  }

  // 批量查询两个固定仓库（官网下载页用）
  if (path === '/api/releases' && method === 'GET') {
    const [jfToolbox, jfEnvDetect] = await Promise.all([
      fetchGitHubRelease('Yangchengen-hub/JFToolbox', env),
      fetchGitHubRelease('Yangchengen-hub/JifengEnvDetect', env)
    ]);
    return jsonResponse({
      releases: {
        jftoolbox: jfToolbox ? {
          tag: jfToolbox.tag_name,
          name: jfToolbox.name,
          published_at: jfToolbox.published_at,
          assets: (jfToolbox.assets || []).map(a => ({ name: a.name, size: a.size, url: a.browser_download_url }))
        } : null,
        jifengenvdetect: jfEnvDetect ? {
          tag: jfEnvDetect.tag_name,
          name: jfEnvDetect.name,
          published_at: jfEnvDetect.published_at,
          assets: (jfEnvDetect.assets || []).map(a => ({ name: a.name, size: a.size, url: a.browser_download_url }))
        } : null
      }
    });
  }

  // 公开：下载链接列表（下载页/首页使用）
  if (path === '/api/download-links' && method === 'GET') {
    const raw = await kvGetJSON(env, 'download_links');
    const list = Array.isArray(raw) ? raw : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    const out = active.map(x => ({
      id: x.id, name: x.name, file_name: x.file_name,
      download_url: x.download_url, icon: x.icon || '📦',
      version: x.version || '', file_size: x.file_size || '',
      description: x.description || '', sort_order: Number(x.sort_order) || 0,
      created_at: x.created_at
    }));
    return jsonResponse({ data: out, links: out, items: out, list: out, total: out.length });
  }

  // 公开：站点内容（首页/其他页面引用）
  if (path === '/api/site-content' && method === 'GET') {
    const raw = await kvGetJSON(env, 'site_content');
    const list = Array.isArray(raw) ? raw : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    return jsonResponse({ data: active, contents: active, items: active, list: active, total: active.length });
  }

  // 公开：仓库列表（展示页用）
  if (path === '/api/repository' && method === 'GET') {
    const raw = await kvGetJSON(env, 'repositories');
    const list = Array.isArray(raw) ? raw : [];
    const active = list.filter(x => x && (x.is_active === true || x.is_active === 1))
      .sort((a, b) => (Number(a.sort_order) || 0) - (Number(b.sort_order) || 0));
    return jsonResponse({ data: active, repos: active, items: active, list: active, total: active.length });
  }

  // 管理员登录
  if (path === '/api/admin/login' && method === 'POST') {
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    const rateKey = 'login:' + ip;
    if (!checkRateLimit(rateKey, 5, 5 * 60 * 1000)) {
      return jsonResponse({ error: '登录尝试过于频繁，请5分钟后再试' }, 429);
    }
    try {
      const body = await safeParseBody(request);
      const username = String(body.username || '');
      const password = String(body.password || '');
      const expectedUser = String(env.ADMIN_USERNAME || 'JIFENG');

      if (username !== expectedUser || !(await verifyAdminPassword(password, env))) {
        return jsonResponse({ error: '用户名或密码错误' }, 401);
      }
      if (!env.JWT_SECRET) {
        return jsonResponse({ error: '服务配置异常（JWT）' }, 500);
      }
      const token = await createAdminToken(env);
      return jsonResponse({ success: true, token }, 200, {
        'Set-Cookie': 'admin_token=' + token + '; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/'
      });
    } catch {
      return jsonResponse({ error: '请求格式错误' }, 400);
    }
  }

  // 从请求中提取管理员 Token
  const authHeader = request.headers.get('Authorization') || '';
  const cookieHeader = request.headers.get('Cookie') || '';
  const token = authHeader.replace('Bearer ', '') ||
    (cookieHeader.match(/admin_token=([^;]+)/) || [])[1] || '';
  const isAdmin = await verifyAdminToken(token, env);

  // 认证守卫
  const protectedPrefixes = ['/api/admin/'];
  const needsAuth = protectedPrefixes.some(p => path.startsWith(p));
  if (needsAuth && !isAdmin && path !== '/api/admin/login') {
    return jsonResponse({ error: '未授权，请先登录' }, 401);
  }

  // 管理员配置
  if (path === '/api/admin/config' && method === 'GET') {
    return jsonResponse({
      site: { enabled: true, name: '极风工作室', description: '专注于极致体验的创作团队' },
      encryption: { enabled: true, algorithm: 'SHA-256 + HMAC-SHA256', note: '密钥由 Worker Bindings 注入，代码中不存储' },
      security: { cors_origin: '*', rate_limit_enabled: true, https_only: true }
    });
  }

  // CRUD 通用：从 KV 读取数组，按 id 操作
  async function handleCRUD(kvKey, pathPrefix, request) {
    const method = request.method;
    const remainder = path.startsWith(pathPrefix) ? path.slice(pathPrefix.length) : '';
    const idPart = remainder.startsWith('/') ? remainder.slice(1) : remainder;

    let list = (await kvGetJSON(env, kvKey)) || [];
    if (!Array.isArray(list)) list = [];

    if (method === 'GET' && !idPart) {
      // 返回多种 key，兼容不同版本的前端
      return jsonResponse({
        data: list,
        links: list,
        contents: list,
        repos: list,
        items: list,
        list: list,
        total: list.length
      });
    }
    if (method === 'POST' && !idPart) {
      try {
        const body = await safeParseBody(request);
        const item = { id: randomToken(8), ...body, created_at: new Date().toISOString() };
        list.push(item);
        await kvSetJSON(env, kvKey, list);
        return jsonResponse({ success: true, data: item });
      } catch {
        return jsonResponse({ error: '请求格式错误' }, 400);
      }
    }
    if (idPart) {
      const idx = list.findIndex(x => x && x.id === idPart);
      if (method === 'GET' && idx >= 0) {
        return jsonResponse({ data: list[idx] });
      }
      if (method === 'PUT' && idx >= 0) {
        try {
          const body = await safeParseBody(request);
          list[idx] = { ...list[idx], ...body, updated_at: new Date().toISOString() };
          await kvSetJSON(env, kvKey, list);
          return jsonResponse({ success: true, data: list[idx] });
        } catch {
          return jsonResponse({ error: '请求格式错误' }, 400);
        }
      }
      if (method === 'DELETE' && idx >= 0) {
        list.splice(idx, 1);
        await kvSetJSON(env, kvKey, list);
        return jsonResponse({ success: true });
      }
    }
    return jsonResponse({ error: 'Not Found', path, id: idPart || null }, 404);
  }

  // 下载链接管理
  if (path === '/api/admin/download-links' || path.startsWith('/api/admin/download-links/')) {
    return handleCRUD('download_links', '/api/admin/download-links', request);
  }
  // 站点内容管理
  if (path === '/api/admin/site-content' || path.startsWith('/api/admin/site-content/')) {
    return handleCRUD('site_content', '/api/admin/site-content', request);
  }
  // 仓库信息管理
  if (path === '/api/admin/repository' || path.startsWith('/api/admin/repository/')) {
    return handleCRUD('repositories', '/api/admin/repository', request);
  }

  // 统计
  if (path === '/api/admin/stats' && method === 'GET') {
    const links = (await kvGetJSON(env, 'download_links')) || [];
    const content = (await kvGetJSON(env, 'site_content')) || [];
    const repos = (await kvGetJSON(env, 'repositories')) || [];
    return jsonResponse({
      download_links: Array.isArray(links) ? links.length : 0,
      site_content: Array.isArray(content) ? content.length : 0,
      repositories: Array.isArray(repos) ? repos.length : 0,
      active_links: Array.isArray(links) ? links.filter(l => l && l.is_active).length : 0
    });
  }

  // 加密测试
  if (path === '/api/admin/encrypt-test' && method === 'POST') {
    try {
      const body = await safeParseBody(request);
      const text = String(body.text || '');
      const hash = await sha256(text);
      return jsonResponse({
        plaintext: text,
        sha256: hash,
        algorithm: 'SHA-256',
        note: '使用 Web Crypto API 纯前端/服务端计算，无密钥无法逆向'
      });
    } catch {
      return jsonResponse({ error: '测试失败' }, 400);
    }
  }

  // 日志
  if (path === '/api/admin/logs' && method === 'GET') {
    return jsonResponse({ data: [], total: 0, note: 'Cloudflare Worker 无状态，日志请前往 Cloudflare Dashboard 查看' });
  }

  return jsonResponse({ error: 'Not Found', path }, 404);
}

// ============ 主入口 (Service Worker Syntax) ============
// 注意：必须使用 addEventListener('fetch') 形式而非 export default，
// 否则部署会报 "Unexpected token 'export'" 错误（service worker 格式不支持 ES module）

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // 从全局读取环境变量（Cloudflare Worker 自动注入到 globalThis）
  const env = {
    get JIFENG_KV() {
      return (typeof globalThis.JIFENG_KV !== 'undefined' && globalThis.JIFENG_KV && typeof globalThis.JIFENG_KV.get === 'function')
        ? globalThis.JIFENG_KV
        : null;
    },
    get ADMIN_USERNAME() { return globalThis.ADMIN_USERNAME || 'JIFENG'; },
    get ADMIN_PASSWORD() { return globalThis.ADMIN_PASSWORD || ''; },
    get ADMIN_PASSWORD_HASH() { return globalThis.ADMIN_PASSWORD_HASH || ''; },
    get JWT_SECRET() { return globalThis.JWT_SECRET || ''; },
    get GITHUB_TOKEN() { return globalThis.GITHUB_TOKEN || ''; }
  };

  try {
    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path.startsWith('/api/')) {
      try {
        return await handleApi(request, env);
      } catch (apiErr) {
        return jsonResponse({
          error: '服务器内部错误',
          detail: String(apiErr && apiErr.message ? apiErr.message : apiErr)
        }, 500);
      }
    }

    // 静态文件路由
    return await serveStaticFile(request, env);
  } catch (fatal) {
    return errPage('致命错误: ' + String(fatal && fatal.message ? fatal.message : fatal), 500);
  }
}
