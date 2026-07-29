/**
 * 极风工作室 - Cloudflare Worker
 * 独立部署，不依赖 Vercel
 * 静态文件走 jsDelivr CDN，API 直接实现
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
  '.wasm': 'application/wasm'
};

const JSDELIVR_BASE = 'https://cdn.jsdelivr.net/gh/Yangchengen-hub/jifeng@main';
const GITHUB_API = 'https://api.github.com';

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
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    ...corsHeaders(),
    ...securityHeaders(),
    ...extra
  };
  return new Response(JSON.stringify(data), { status, headers });
}

// SHA-256 哈希
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// HMAC-SHA256 签名
async function hmacSign(key, message) {
  const encoder = new TextEncoder();
  const keyData = await crypto.subtle.importKey(
    'raw', encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', keyData, encoder.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成随机 token
function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 验证管理员密码
async function verifyAdmin(password, env) {
  const expectedHash = env.ADMIN_PASSWORD_HASH;
  if (!expectedHash) return false;
  const actualHash = await sha256(String(password) + ':极风工作室salt:JIFENG2026');
  return actualHash === expectedHash;
}

// 生成管理员会话 token
async function createAdminToken(env) {
  const token = randomToken(32);
  const timestamp = Date.now();
  const signature = await hmacSign(env.JWT_SECRET, token + ':' + timestamp);
  return token + '.' + timestamp + '.' + signature;
}

// 验证管理员 token
async function verifyAdminToken(token, env) {
  if (!token || !env.JWT_SECRET) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [tokenPart, timestampPart, sigPart] = parts;
  const expectedSig = await hmacSign(env.JWT_SECRET, tokenPart + ':' + timestampPart);
  if (sigPart !== expectedSig) return false;
  const timestamp = parseInt(timestampPart);
  if (isNaN(timestamp)) return false;
  // 24小时过期
  if (Date.now() - timestamp > 24 * 60 * 60 * 1000) return false;
  return true;
}

// 速率限制（内存存储）
const rateLimits = new Map();

function checkRateLimit(key, max, windowMs) {
  const now = Date.now();
  const record = rateLimits.get(key) || { hits: [] };
  record.hits = record.hits.filter(t => t > now - windowMs);
  if (record.hits.length >= max) return false;
  record.hits.push(now);
  rateLimits.set(key, record);
  return true;
}

// GitHub Release 查询
const releaseCache = new Map();

async function fetchGitHubRelease(repo, env) {
  const cacheKey = 'release:' + repo;
  const cached = releaseCache.get(cacheKey);
  if (cached && cached.expires > Date.now()) return cached.data;

  try {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    if (env.GITHUB_TOKEN) headers['Authorization'] = 'Bearer ' + env.GITHUB_TOKEN;

    const res = await fetch(GITHUB_API + '/repos/' + repo + '/releases/latest', { headers });
    if (!res.ok) throw new Error('GitHub API ' + res.status);
    const data = await res.json();

    releaseCache.set(cacheKey, { data, expires: Date.now() + 15 * 60 * 1000 });
    return data;
  } catch {
    return null;
  }
}

// 静态文件服务
async function serveStatic(path, env) {
  // 默认首页
  if (path === '/' || path === '') path = '/index.html';

  // 清理路径
  path = path.split('?')[0].split('#')[0];

  const jsdelivrUrl = JSDELIVR_BASE + path;

  try {
    const response = await fetch(jsdelivrUrl, {
      headers: { 'User-Agent': 'CloudflareWorker/1.0' },
      cf: { cacheTtl: 3600, cacheEverything: true }
    });

    if (!response.ok) {
      // 尝试 404 页面
      if (path !== '/404.html' && path !== '/views/404.html') {
        const notFoundRes = await fetch(JSDELIVR_BASE + '/views/404.html', {
          headers: { 'User-Agent': 'CloudflareWorker/1.0' }
        }).catch(() => null);
        if (notFoundRes && notFoundRes.ok) {
          return new Response(notFoundRes.body, {
            status: 404,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'public, max-age=3600',
              ...securityHeaders()
            }
          });
        }
      }
      return new Response('404 Not Found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', ...securityHeaders() }
      });
    }

    const headers = new Headers(response.headers);
    headers.set('Content-Type', getMimeType(path));
    headers.set('Cache-Control', 'public, max-age=3600');
    headers.set('Access-Control-Allow-Origin', '*');
    Object.entries(securityHeaders()).forEach(([k, v]) => headers.set(k, v));

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: headers
    });
  } catch (err) {
    return new Response('Internal Server Error: ' + err.message, {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', ...securityHeaders() }
    });
  }
}

// KV 存储操作
async function kvGet(env, key) {
  if (!env.JIFENG_KV) return null;
  try {
    return await env.JIFENG_KV.get(key, 'json');
  } catch {
    return null;
  }
}

async function kvSet(env, key, value) {
  if (!env.JIFENG_KV) return false;
  try {
    await env.JIFENG_KV.put(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

// API 路由处理
async function handleApi(request, env, url) {
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
      timestamp: Date.now()
    });
  }

  // 加密信息（公开，不泄露密钥）
  if (path === '/api/crypto/info') {
    return jsonResponse({
      encryption: 'aes-256-gcm-compatible',
      algorithm: 'SHA-256 + HMAC-SHA256',
      features: {
        password_hashing: true,
        token_signing: true,
        no_hardcoded_secrets: true,
        environment_variables: true
      }
    });
  }

  // GitHub Release 查询
  const releaseMatch = path.match(/^\/api\/release\/(.+)$/);
  if (releaseMatch && method === 'GET') {
    const repo = releaseMatch[1].replace(/[^a-zA-Z0-9._-]/g, '');
    const release = await fetchGitHubRelease(repo, env);
    return jsonResponse({
      repo,
      found: !!release,
      tag: release ? release.tag_name : null,
      name: release ? release.name : null,
      published_at: release ? release.published_at : null,
      body: release ? (release.body || '').slice(0, 5000) : null,
      assets: release ? (release.assets || []).map(a => ({
        name: a.name,
        size: a.size,
        download_url: a.browser_download_url
      })) : []
    });
  }

  // 批量查询两个仓库
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

  // 管理员登录
  if (path === '/api/admin/login' && method === 'POST') {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!checkRateLimit('login:' + ip, 5, 300000)) {
      return jsonResponse({ error: '登录尝试过于频繁，请5分钟后再试' }, 429);
    }

    try {
      const body = await request.json();
      const username = body.username || '';
      const password = body.password || '';

      if (username !== (env.ADMIN_USERNAME || 'JIFENG')) {
        return jsonResponse({ error: '用户名或密码错误' }, 401);
      }

      if (!await verifyAdmin(password, env)) {
        return jsonResponse({ error: '用户名或密码错误' }, 401);
      }

      if (!env.JWT_SECRET) {
        return jsonResponse({ error: 'JWT 未配置' }, 500);
      }

      const token = await createAdminToken(env);
      return jsonResponse({
        success: true,
        token: token
      }, 200, {
        'Set-Cookie': 'admin_token=' + token + '; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/'
      });
    } catch {
      return jsonResponse({ error: '请求格式错误' }, 400);
    }
  }

  // 以下为需要认证的接口
  const authHeader = request.headers.get('Authorization') || '';
  const cookieHeader = request.headers.get('Cookie') || '';
  const token = authHeader.replace('Bearer ', '') ||
    (cookieHeader.match(/admin_token=([^;]+)/) || [])[1] || '';

  const isAdmin = await verifyAdminToken(token, env);

  // 管理员配置
  if (path === '/api/admin/config' && method === 'GET') {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);
    return jsonResponse({
      site: {
        enabled: true,
        name: '极风工作室',
        description: '专注于极致体验的创作团队'
      },
      encryption: {
        enabled: true,
        algorithm: 'SHA-256 + HMAC-SHA256',
        note: '密钥由环境变量提供，不在代码中存储'
      },
      security: {
        cors_origin: '*',
        rate_limit_enabled: true,
        https_only: true
      }
    });
  }

  // 管理员数据 CRUD - download-links
  if (path === '/api/admin/download-links' || path.match(/^\/api\/admin\/download-links\/.+$/)) {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);

    let links = await kvGet(env, 'download_links') || [];

    const idMatch = path.match(/^\/api\/admin\/download-links\/(.+)$/);

    if (method === 'GET') {
      return jsonResponse({ data: links, total: links.length });
    }

    if (method === 'POST' && !idMatch) {
      try {
        const body = await request.json();
        const item = { id: randomToken(8), ...body, created_at: new Date().toISOString() };
        links.push(item);
        await kvSet(env, 'download_links', links);
        return jsonResponse({ success: true, data: item });
      } catch {
        return jsonResponse({ error: '请求格式错误' }, 400);
      }
    }

    if (idMatch) {
      const id = idMatch[1];
      const idx = links.findIndex(l => l.id === id);

      if (method === 'PUT' && idx >= 0) {
        try {
          const body = await request.json();
          links[idx] = { ...links[idx], ...body, updated_at: new Date().toISOString() };
          await kvSet(env, 'download_links', links);
          return jsonResponse({ success: true, data: links[idx] });
        } catch {
          return jsonResponse({ error: '请求格式错误' }, 400);
        }
      }

      if (method === 'DELETE' && idx >= 0) {
        links.splice(idx, 1);
        await kvSet(env, 'download_links', links);
        return jsonResponse({ success: true });
      }
    }

    return jsonResponse({ error: 'Not Found' }, 404);
  }

  // 管理员数据 CRUD - site-content
  if (path === '/api/admin/site-content' || path.match(/^\/api\/admin\/site-content\/.+$/)) {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);

    let content = await kvGet(env, 'site_content') || [];

    const idMatch = path.match(/^\/api\/admin\/site-content\/(.+)$/);

    if (method === 'GET') {
      return jsonResponse({ data: content, total: content.length });
    }

    if (method === 'POST' && !idMatch) {
      try {
        const body = await request.json();
        const item = { id: randomToken(8), ...body, created_at: new Date().toISOString() };
        content.push(item);
        await kvSet(env, 'site_content', content);
        return jsonResponse({ success: true, data: item });
      } catch {
        return jsonResponse({ error: '请求格式错误' }, 400);
      }
    }

    if (idMatch) {
      const id = idMatch[1];
      const idx = content.findIndex(c => c.id === id);

      if (method === 'PUT' && idx >= 0) {
        try {
          const body = await request.json();
          content[idx] = { ...content[idx], ...body, updated_at: new Date().toISOString() };
          await kvSet(env, 'site_content', content);
          return jsonResponse({ success: true, data: content[idx] });
        } catch {
          return jsonResponse({ error: '请求格式错误' }, 400);
        }
      }

      if (method === 'DELETE' && idx >= 0) {
        content.splice(idx, 1);
        await kvSet(env, 'site_content', content);
        return jsonResponse({ success: true });
      }
    }

    return jsonResponse({ error: 'Not Found' }, 404);
  }

  // 管理员数据 CRUD - repository
  if (path === '/api/admin/repository' || path.match(/^\/api\/admin\/repository\/.+$/)) {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);

    let repos = await kvGet(env, 'repositories') || [];

    const idMatch = path.match(/^\/api\/admin\/repository\/(.+)$/);

    if (method === 'GET') {
      return jsonResponse({ data: repos, total: repos.length });
    }

    if (method === 'POST' && !idMatch) {
      try {
        const body = await request.json();
        const item = { id: randomToken(8), ...body, created_at: new Date().toISOString() };
        repos.push(item);
        await kvSet(env, 'repositories', repos);
        return jsonResponse({ success: true, data: item });
      } catch {
        return jsonResponse({ error: '请求格式错误' }, 400);
      }
    }

    if (idMatch) {
      const id = idMatch[1];
      const idx = repos.findIndex(r => r.id === id);

      if (method === 'PUT' && idx >= 0) {
        try {
          const body = await request.json();
          repos[idx] = { ...repos[idx], ...body, updated_at: new Date().toISOString() };
          await kvSet(env, 'repositories', repos);
          return jsonResponse({ success: true, data: repos[idx] });
        } catch {
          return jsonResponse({ error: '请求格式错误' }, 400);
        }
      }

      if (method === 'DELETE' && idx >= 0) {
        repos.splice(idx, 1);
        await kvSet(env, 'repositories', repos);
        return jsonResponse({ success: true });
      }
    }

    return jsonResponse({ error: 'Not Found' }, 404);
  }

  // 统计信息
  if (path === '/api/admin/stats' && method === 'GET') {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);
    const links = await kvGet(env, 'download_links') || [];
    const content = await kvGet(env, 'site_content') || [];
    const repos = await kvGet(env, 'repositories') || [];
    return jsonResponse({
      download_links: links.length,
      site_content: content.length,
      repositories: repos.length,
      active_links: links.filter(l => l.is_active).length
    });
  }

  // 加密测试
  if (path === '/api/admin/encrypt-test' && method === 'POST') {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);
    try {
      const body = await request.json();
      const text = body.text || '';
      const hash = await sha256(text);
      return jsonResponse({
        plaintext: text,
        sha256: hash,
        algorithm: 'SHA-256',
        note: '使用 Web Crypto API，无密钥无法逆向'
      });
    } catch {
      return jsonResponse({ error: '测试失败' }, 400);
    }
  }

  // 日志
  if (path === '/api/admin/logs' && method === 'GET') {
    if (!isAdmin) return jsonResponse({ error: '未授权' }, 401);
    return jsonResponse({ data: [], total: 0, note: 'Worker 无状态日志存储' });
  }

  return jsonResponse({ error: 'Not Found', path: path }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return jsonResponse({ error: 'Internal Server Error', message: err.message }, 500);
      }
    }

    // 静态文件
    return serveStatic(path, env);
  }
};
