const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const db = require('./db');
const { wafMiddleware, rateLimitMiddleware, botProtection, adminAccessCheck, logSecurityEvent, aiSandboxAnalysis, detectThreats, analyzeUserAgent } = require('./security');
const { logAccess, getAccessStats, getRecentLogs, getSecurityStats } = require('./logger');
const { createCaptcha, verifyCaptcha } = require('./captcha');
const { login, authMiddleware, changePassword, getAdminList } = require('./auth');
const { getConfig, setConfig, isIPBanned, banIP, unbanIP } = require('./db');

const advancedSecurity = require('./security-advanced');
const emailService = require('./email-service');
const wsServer = require('./websocket-server');
const qqAuth = require('./qq-auth');
const { verifyRequestSignature, applySignatureToResponse, isSensitivePath, generateServerToken } = require('./request-signature');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.set('trust proxy', 1);

// Helmet 安全头 - 防止多种 Web 漏洞
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      fontSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

// API请求签名验证中间件（应用于敏感路径）
app.use('/api/', (req, res, next) => {
  if (isSensitivePath(req.path)) {
    return verifyRequestSignature(req, res, next);
  }
  next();
});

// 响应签名中间件
app.use(applySignatureToResponse);

// IP 提取
app.use((req, res, next) => {
  req.ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress;
  next();
});

// CSRF 令牌生成与校验
const csrfTokens = new Map();
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}
function getCSRFToken(req) {
  if (!req._csrfToken) {
    req._csrfToken = generateCSRFToken();
    csrfTokens.set(req._csrfToken, { createdAt: Date.now(), ip: req.ip });
  }
  return req._csrfToken;
}
function verifyCSRFToken(token, ip) {
  if (!token) return false;
  const record = csrfTokens.get(token);
  if (!record) return false;
  // 1小时过期
  if (Date.now() - record.createdAt > 3600 * 1000) {
    csrfTokens.delete(token);
    return false;
  }
  if (record.ip !== ip) return false;
  return true;
}
function consumeCSRFToken(token) {
  csrfTokens.delete(token);
}

// WAF + 日志
app.use(wafMiddleware);
app.use(logAccess);

// 管理后台隐藏访问验证 - 必须放在所有管理页面路由之前
app.use(adminAccessCheck);

// 静态文件先放行（在 WAF 之后）
app.use('/captcha.svg', (req, res) => {
  const captcha = createCaptcha('general');
  res.set('Content-Type', 'image/svg+xml');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.send(captcha.svg);
});

app.use('/api/admin', rateLimitMiddleware(60, 60 * 1000, 'admin_api'));

// 验证码接口
app.get('/captcha', (req, res) => {
  const purpose = req.query.purpose || 'general';
  const captcha = createCaptcha(purpose);
  const csrfToken = generateCSRFToken();
  csrfTokens.set(csrfToken, { createdAt: Date.now(), ip: req.ip });
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({ token: captcha.token, svg: captcha.svg, type: captcha.type, csrfToken });
});

app.get('/blocked-demo', (req, res) => {
  res.render('blocked', {
    requestId: 'demo-request-id-12345',
    reason: 'demo_block',
    severity: 'high',
    time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
  });
});

// 登录接口（带 CSRF 校验 + QQ 二级验证）
app.post('/api/login', rateLimitMiddleware(5, 60 * 1000, 'login'), (req, res) => {
  const { username, password, captcha_token, captcha_answer, csrf_token, behavior_data } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  if (!verifyCSRFToken(csrf_token, req.ip)) {
    return res.status(403).json({ error: '会话已过期，请刷新页面重试', csrf_error: true });
  }

  const captchaResult = verifyCaptcha(captcha_token, captcha_answer, 'login', behavior_data);
  if (!captchaResult.valid) {
    consumeCSRFToken(csrf_token);
    const newCSRF = generateCSRFToken();
    csrfTokens.set(newCSRF, { createdAt: Date.now(), ip: req.ip });
    return res.status(400).json({
      error: captchaResult.reason === 'wrong_answer' ? '验证码错误' :
             captchaResult.reason === 'behavior_check_failed' ? '行为检测未通过，疑似机器人' :
             '验证码已过期',
      captcha_error: true,
      csrf_token: newCSRF
    });
  }

  const result = login(username, password, req.ip);

  if (result.success) {
    consumeCSRFToken(csrf_token);

    // 检查是否配置了 QQ 二级验证
    if (qqAuth.isQQConfigured()) {
      // 密码验证通过，创建二级验证会话，等待 QQ 授权
      const twoFA = qqAuth.create2FASession(result.admin.id, req.ip, req.headers['user-agent']);
      if (twoFA.success) {
        const qqAuthURL = qqAuth.getQQAuthURL(req.ip, '2fa');
        return res.json({
          success: true,
          require_2fa: true,
          twofa_token: twoFA.sessionToken,
          qq_auth_url: qqAuthURL,
          qq_configured: true,
          admin: { id: result.admin.id, username: result.admin.username }
        });
      }
    }

    // 未配置 QQ 验证，直接登录
    res.cookie('admin_token', result.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ success: true, admin: result.admin, qq_configured: false });
  } else {
    consumeCSRFToken(csrf_token);
    const newCSRF = generateCSRFToken();
    csrfTokens.set(newCSRF, { createdAt: Date.now(), ip: req.ip });
    res.status(401).json({ error: result.message, csrf_token: newCSRF });
  }
});

// QQ 授权回调
app.get('/auth/qq/callback', rateLimitMiddleware(10, 60 * 1000, 'qq_callback'), async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send('无效的 QQ 授权回调参数');
  }

  if (!qqAuth.validateOAuthState(state, req.ip)) {
    return res.status(400).send('安全校验失败，请重新登录');
  }

  const tokenResult = await qqAuth.exchangeCodeForToken(code);
  if (tokenResult.error || !tokenResult.access_token) {
    return res.status(500).send(`QQ 授权失败: ${tokenResult.error || '未知错误'}`);
  }

  const openidResult = await qqAuth.getOpenID(tokenResult.access_token);
  if (openidResult.error || !openidResult.openid) {
    return res.status(500).send(`获取 QQ 身份失败: ${openidResult.error || '未知错误'}`);
  }

  const openid = openidResult.openid;
  const userInfoResult = await qqAuth.getUserInfo(tokenResult.access_token, openid);
  const nickname = userInfoResult.nickname || '';
  const avatar = userInfoResult.figureurl_qq_2 || userInfoResult.figureurl_qq_1 || '';

  // 检查是否为绑定流程（管理员在后台发起绑定）
  const bindPurpose = state && state.length > 0;
  const twoFAToken = req.query.twofa_token;

  // 二级验证流程
  if (twoFAToken) {
    const verifyResult = qqAuth.verify2FASession(twoFAToken, req.ip);
    if (!verifyResult.valid) {
      return res.send(`
        <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
          <div style="text-align:center">
            <div style="font-size:48px;margin-bottom:16px">&#9888;</div>
            <h2>二级验证失败</h2>
            <p>${verifyResult.reason || '会话已过期，请重新登录'}</p>
            <p style="color:#888;font-size:14px">3 秒后自动关闭...</p>
          </div>
          <script>setTimeout(()=>window.close(),3000)</script>
        </body></html>
      `);
    }

    // 检查 QQ 是否绑定到该管理员
    const binding = db.prepare('SELECT * FROM admin_qq_bindings WHERE admin_id = ? AND status = ?').get(verifyResult.admin.id, 'active');
    const qqBound = qqAuth.isQQBound(openid);

    // 如果该管理员已绑定 QQ，验证 openid 是否匹配
    if (binding) {
      if (binding.openid !== openid) {
        logSecurityEvent('qq_2fa_failed', 'high', req, `QQ 二级验证失败：使用未绑定的 QQ 号尝试登录`, { openid: openid.slice(0, 8), admin_id: verifyResult.admin.id });
        return res.send(`
          <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
            <div style="text-align:center">
              <div style="font-size:48px;margin-bottom:16px">&#128737;</div>
              <h2>验证失败</h2>
              <p>该 QQ 号未绑定到此管理员账号</p>
              <p style="color:#888;font-size:14px">3 秒后自动关闭...</p>
            </div>
            <script>setTimeout(()=>window.close(),3000)</script>
          </body></html>
        `);
      }
      // 已绑定且匹配，直接通过
    } else {
      // 首次绑定：需要邮箱验证码确认
      if (qqBound) {
        logSecurityEvent('qq_2fa_failed', 'high', req, `QQ 已被其他账号绑定，拒绝登录`, { openid: openid.slice(0, 8) });
        return res.send(`
          <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
            <div style="text-align:center">
              <div style="font-size:48px;margin-bottom:16px">&#128737;</div>
              <h2>验证失败</h2>
              <p>该 QQ 号已绑定到其他管理员</p>
              <p style="color:#888;font-size:14px">3 秒后自动关闭...</p>
            </div>
            <script>setTimeout(()=>window.close(),3000)</script>
          </body></html>
        `);
      }

      // 生成绑定验证码，发送到管理员邮箱
      const bindCode = Math.random().toString().slice(2, 8);
      const bindCodeExpires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

      // 保存到二级验证会话
      db.prepare(`
        UPDATE two_fa_sessions 
        SET qq_openid = ?, qq_nickname = ?, qq_avatar = ?, bind_code = ?, bind_code_expires = ?
        WHERE session_token = ?
      `).run(openid, nickname || '', avatar || '', bindCode, bindCodeExpires, twoFAToken);

      // 发送验证码邮件
      const adminEmail = process.env.ADMIN_EMAIL;
      if (adminEmail) {
        emailService.sendEmail(adminEmail, '【极风工作室】QQ绑定验证码', `
          <div style="font-family:sans-serif;padding:20px;max-width:500px;margin:0 auto;background:#1a1a2e;border-radius:12px">
            <h2 style="color:#00aaff;text-align:center">QQ 绑定验证</h2>
            <p style="color:#fff;font-size:16px">您正在将以下 QQ 账号绑定到管理员账号：</p>
            <div style="text-align:center;margin:20px 0">
              <img src="${avatar || ''}" style="width:64px;height:64px;border-radius:50%;border:2px solid #00aaff">
              <p style="color:#12b7f5;font-size:18px;margin-top:8px">${nickname || 'QQ用户'}</p>
            </div>
            <p style="color:#fff;font-size:16px">验证码：<span style="font-size:32px;font-weight:bold;color:#00ffaa;letter-spacing:8px">${bindCode}</span></p>
            <p style="color:#888;font-size:14px">验证码 10 分钟内有效。如果不是您本人操作，请忽略此邮件。</p>
          </div>
        `).catch(e => console.error('[Email] 发送绑定验证码失败:', e.message));
      }

      // 返回验证码输入页面（不直接绑定）- 含QQ号白名单验证
      return res.send(`
        <html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>
        <body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;padding:20px">
          <div style="text-align:center;max-width:400px;width:100%">
            <div style="font-size:48px;margin-bottom:16px">&#128272;</div>
            <h2>首次绑定需要验证</h2>
            <p style="color:#888;margin-bottom:20px">请输入您的QQ号并完成邮箱验证</p>
            <div style="background:#1a1a2e;padding:20px;border-radius:12px;margin-bottom:20px">
              <p style="color:#12b7f5;font-size:14px;margin-bottom:8px">绑定QQ：${nickname || '未知'}</p>
              <div style="margin-bottom:12px">
                <input type="text" id="qqNumber" placeholder="输入您的QQ号" maxlength="12" 
                  style="width:100%;padding:12px;font-size:16px;text-align:center;border-radius:8px;border:2px solid #00aaff;background:#0a0a0f;color:#fff;box-sizing:border-box;margin-bottom:10px"
                  oninput="validateQQFormat(this)">
              </div>
              <div>
                <input type="text" id="bindCode" placeholder="输入6位验证码" maxlength="6" 
                  style="width:100%;padding:14px;font-size:24px;text-align:center;letter-spacing:8px;border-radius:8px;border:2px solid #00aaff;background:#0a0a0f;color:#fff;box-sizing:border-box">
              </div>
              <p id="bindError" style="color:#ff6b6b;font-size:12px;margin-top:8px;display:none">错误信息</p>
              <p id="qqHint" style="color:#888;font-size:11px;margin-top:6px;display:none"></p>
            </div>
            <button onclick="confirmBind()" style="width:100%;padding:14px;background:linear-gradient(135deg,#00aaff,#00ffaa);color:#000;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer">确认绑定</button>
            <p style="color:#666;font-size:12px;margin-top:16px">请检查邮箱获取验证码（可能被归入垃圾邮件）</p>
            <p style="color:#ffaa00;font-size:11px;margin-top:8px">&#9888; 仅授权白名单内的QQ号可绑定</p>
          </div>
          <script>
            const twofaToken = '${twoFAToken}';
            function validateQQFormat(input){
              const val = input.value.replace(/[^0-9]/g,'');
              if(val !== input.value) input.value = val;
              const hint = document.getElementById('qqHint');
              if(val.length > 0 && (val.length < 5 || val.length > 12)){
                hint.textContent = 'QQ号格式不正确';
                hint.style.color = '#ff6b6b';
                hint.style.display = 'block';
              }else{
                hint.style.display = 'none';
              }
            }
            async function confirmBind(){
              const qqNum = document.getElementById('qqNumber').value.trim();
              const code = document.getElementById('bindCode').value.trim();
              const err = document.getElementById('bindError');
              err.style.display = 'none';
              if(!qqNum || qqNum.length < 5){
                err.textContent = '请输入有效的QQ号';
                err.style.display = 'block';
                return;
              }
              if(!code || code.length !== 6){
                err.textContent = '请输入6位验证码';
                err.style.display = 'block';
                return;
              }
              try{
                const r = await fetch('/api/admin/qq-bind-confirm',{
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  credentials:'include',
                  body:JSON.stringify({twofa_token:twofaToken,code:code,qq_number:qqNum})
                });
                const d = await r.json();
                if(d.success){
                  document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><div style="font-size:48px">&#9989;</div><h2>绑定成功</h2><p>正在进入...</p></div></div>';
                  setTimeout(()=>{
                    if(window.opener && !window.opener.closed){
                      window.opener.postMessage({type:'qq_bind_success'},'*');
                      window.close();
                    }else{
                      window.location.href = '/dashboard.html';
                    }
                  },1000);
                }else{
                  err.textContent = d.error || '验证失败';
                  err.style.display = 'block';
                }
              }catch(e){
                err.textContent = '网络错误，请重试';
                err.style.display = 'block';
              }
            }
            document.getElementById('bindCode').addEventListener('keypress',function(e){
              if(e.key==='Enter') confirmBind();
            });
            document.getElementById('qqNumber').addEventListener('keypress',function(e){
              if(e.key==='Enter') confirmBind();
            });
            document.getElementById('qqNumber').focus();
          </script>
        </body></html>
      `);
    }

    // 验证通过，标记二级验证完成
    qqAuth.mark2FAVerified(twoFAToken, openid);
    if (binding) qqAuth.updateQQLastUsed(openid);

    // 生成最终 JWT
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      throw new Error('[Auth] JWT_SECRET 环境变量未设置');
    }
    const finalToken = jwt.sign(
      { id: verifyResult.admin.id, username: verifyResult.admin.username, role: verifyResult.admin.role, twofa: true },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    logSecurityEvent('qq_2fa_success', 'low', req, 'QQ 二级验证通过', { admin: verifyResult.admin.username });

    res.send(`
      <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
        <div style="text-align:center">
          <div style="font-size:48px;margin-bottom:16px">&#9989;</div>
          <h2>验证通过</h2>
          <p>正在进入管理控制台...</p>
          <p style="color:#888;font-size:14px">1 秒后自动跳转</p>
        </div>
        <script>
          // 兼容 PC 端弹窗模式
          if (window.opener && !window.opener.closed) {
            window.opener.postMessage({type:'qq_2fa_success',token:'${finalToken}'},'*');
          }
          // 兼容移动端直接跳转模式
          setTimeout(()=>{
            if (window.opener && !window.opener.closed) {
              window.close();
            } else {
              window.location.href = '/dashboard.html';
            }
          }, 1000);
        </script>
      </body></html>
    `);
    return;
  }

  // 绑定 QQ 流程（管理员已登录，在设置页绑定）
  const adminToken = req.cookies?.admin_token;
  if (adminToken) {
    const { verifyToken } = require('./auth');
    const verifyResult = verifyToken(adminToken);
    if (verifyResult.valid) {
      // 检查是否已被绑定
      if (qqAuth.isQQBound(openid)) {
        const existingAdmin = qqAuth.getAdminByQQOpenID(openid);
        if (existingAdmin && existingAdmin.id !== verifyResult.admin.id) {
          return res.send(`
            <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
              <div style="text-align:center">
                <div style="font-size:48px;margin-bottom:16px">&#9888;</div>
                <h2>绑定失败</h2>
                <p>该 QQ 号已绑定到其他管理员账号</p>
              </div>
            </body></html>
          `);
        }
      }
      qqAuth.bindQQToAdmin(verifyResult.admin.id, openid, nickname, avatar);
      logSecurityEvent('qq_bind', 'low', req, 'QQ 授权绑定成功', { admin: verifyResult.admin.username });
      return res.send(`
        <html><body style="background:#0a0a0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif">
          <div style="text-align:center">
            <div style="font-size:48px;margin-bottom:16px">&#9989;</div>
            <h2>绑定成功</h2>
            <p>QQ: ${nickname}</p>
            <p style="color:#888;font-size:14px">2 秒后自动关闭...</p>
          </div>
          <script>
            window.opener && window.opener.postMessage({type:'qq_bind_success'},'*');
            setTimeout(()=>window.close(),2000);
          </script>
        </body></html>
      `);
    }
  }

  res.status(400).send('无效的授权流程');
});

// 检查二级验证状态 + 完成登录
app.post('/api/login/2fa-verify', rateLimitMiddleware(10, 60 * 1000, '2fa_verify'), (req, res) => {
  const { twofa_token } = req.body;
  if (!twofa_token) {
    return res.status(400).json({ error: '缺少二级验证令牌' });
  }

  const result = qqAuth.verify2FASession(twofa_token, req.ip);
  if (result.valid) {
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      throw new Error('[Auth] JWT_SECRET 环境变量未设置');
    }
    const finalToken = jwt.sign(
      { id: result.admin.id, username: result.admin.username, role: result.admin.role, twofa: true },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('admin_token', finalToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ success: true, admin: result.admin });
  } else {
    res.status(400).json({ error: result.reason || '二级验证未通过', verified: false });
  }
});

// 获取登录状态（判断是否配置 QQ 验证）
app.get('/api/login/status', (req, res) => {
  res.json({
    qq_configured: qqAuth.isQQConfigured(),
    site_enabled: getConfig('site_enabled') === 'true'
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true });
});

// ============ 管理后台 API ============

// 获取系统配置
app.get('/api/admin/config', authMiddleware, (req, res) => {
  const configs = db.prepare('SELECT key, value, updated_at FROM system_config ORDER BY key').all();
  res.json({ configs });
});

// 更新系统配置
app.post('/api/admin/config', authMiddleware, (req, res) => {
  const { configs } = req.body;
  if (!configs || typeof configs !== 'object') {
    return res.status(400).json({ error: '参数错误' });
  }

  // 允许更新的配置项（白名单）
  const allowedKeys = [
    'site_enabled', 'waf_enabled', 'bot_protection_enabled', 'rate_limit_enabled',
    'download_captcha_enabled', 'login_captcha_enabled', 'auto_ban_enabled',
    'auto_ban_threshold'
  ];

  const updated = [];
  for (const [key, value] of Object.entries(configs)) {
    if (allowedKeys.includes(key)) {
      setConfig(key, String(value));
      updated.push(key);
    }
  }

  logSecurityEvent('config_updated', 'low', req, `配置更新: ${updated.join(', ')}`, configs);
  res.json({ success: true, updated });
});

// 获取网站实时状态
app.get('/api/admin/site-status', authMiddleware, (req, res) => {
  const status = {
    site_enabled: getConfig('site_enabled') === 'true',
    waf_enabled: getConfig('waf_enabled') === 'true',
    bot_protection_enabled: getConfig('bot_protection_enabled') === 'true',
    rate_limit_enabled: getConfig('rate_limit_enabled') === 'true',
    download_captcha_enabled: getConfig('download_captcha_enabled') === 'true',
    login_captcha_enabled: getConfig('login_captcha_enabled') === 'true',
    auto_ban_enabled: getConfig('auto_ban_enabled') === 'true',
    auto_ban_threshold: parseInt(getConfig('auto_ban_threshold') || '3'),
    server_port: PORT,
    server_uptime: process.uptime(),
    node_version: process.version,
    memory_usage: process.memoryUsage(),
    platform: process.platform,
    pid: process.pid,
    timestamp: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
  };
  res.json(status);
});

// 一键开关网站
app.post('/api/admin/toggle-site', authMiddleware, (req, res) => {
  const { enabled } = req.body;
  setConfig('site_enabled', enabled ? 'true' : 'false');
  logSecurityEvent('site_toggled', 'medium', req, `网站${enabled ? '开启' : '关闭'}`, { enabled });
  res.json({ success: true, site_enabled: enabled });
});

// 一键开关各项服务
app.post('/api/admin/toggle-service', authMiddleware, (req, res) => {
  const { service, enabled } = req.body;
  const allowedServices = [
    'waf_enabled', 'bot_protection_enabled', 'rate_limit_enabled',
    'download_captcha_enabled', 'login_captcha_enabled', 'auto_ban_enabled'
  ];

  if (!allowedServices.includes(service)) {
    return res.status(400).json({ error: '未知的服务项' });
  }

  setConfig(service, enabled ? 'true' : 'false');
  logSecurityEvent('service_toggled', 'low', req, `${service} ${enabled ? '开启' : '关闭'}`, { service, enabled });
  res.json({ success: true, [service]: enabled });
});

// 获取封禁 IP 列表
app.get('/api/admin/banned-ips', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const ips = db.prepare(`
    SELECT * FROM banned_ips
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM banned_ips').get().count;
  res.json({ ips, total, limit, offset });
});

// 手动封禁 IP
app.post('/api/admin/ban-ip', authMiddleware, (req, res) => {
  const { ip, reason, severity, expires_at } = req.body;
  if (!ip || !reason) {
    return res.status(400).json({ error: 'IP 和封禁原因为必填' });
  }
  if (isIPBanned(ip)) {
    return res.status(400).json({ error: '该 IP 已被封禁' });
  }
  banIP(ip, reason, severity || 'high', req.admin.username, expires_at || null);
  logSecurityEvent('manual_ban', 'high', req, `手动封禁 IP: ${ip}`, { ip, reason, severity });
  res.json({ success: true, ip, reason });
});

// 解封 IP
app.post('/api/admin/unban-ip', authMiddleware, (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP 为必填' });
  }
  unbanIP(ip);
  logSecurityEvent('manual_unban', 'medium', req, `手动解封 IP: ${ip}`, { ip });
  res.json({ success: true, ip });
});

// 批量解封
app.post('/api/admin/unban-batch', authMiddleware, (req, res) => {
  const { ips } = req.body;
  if (!Array.isArray(ips) || ips.length === 0) {
    return res.status(400).json({ error: 'IP 列表为必填' });
  }
  const stmt = db.prepare('DELETE FROM banned_ips WHERE ip = ?');
  let count = 0;
  for (const ip of ips) {
    if (typeof ip === 'string') {
      stmt.run(ip);
      count++;
    }
  }
  logSecurityEvent('batch_unban', 'medium', req, `批量解封 ${count} 个 IP`, { ips });
  res.json({ success: true, count });
});

// 清空所有封禁
app.post('/api/admin/clear-bans', authMiddleware, (req, res) => {
  const result = db.prepare('DELETE FROM banned_ips').run();
  logSecurityEvent('clear_all_bans', 'high', req, `清空所有封禁 IP (${result.changes} 条)`, null);
  res.json({ success: true, count: result.changes });
});

// 获取安全扫描日志
app.get('/api/admin/scan-logs', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const minScore = parseInt(req.query.min_score) || 0;
  const logs = db.prepare(`
    SELECT * FROM security_scans
    WHERE risk_score >= ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(minScore, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM security_scans WHERE risk_score >= ?').get(minScore).count;
  res.json({ logs, total, limit, offset });
});

// 获取安全事件
app.get('/api/admin/security-events', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const severity = req.query.severity;
  let query = 'SELECT * FROM security_events';
  const params = [];
  if (severity && severity !== 'all') {
    query += ' WHERE severity = ?';
    params.push(severity);
  }
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  const events = db.prepare(query).all(...params);

  let countQuery = 'SELECT COUNT(*) as count FROM security_events';
  let countParams = [];
  if (severity && severity !== 'all') {
    countQuery += ' WHERE severity = ?';
    countParams.push(severity);
  }
  const total = db.prepare(countQuery).get(...countParams).count;

  res.json({ events, total, limit, offset });
});

// 统计数据
app.get('/api/admin/stats', authMiddleware, (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  const accessStats = getAccessStats(hours);
  const securityStats = getSecurityStats(hours);

  // 增加实时统计
  const realtimeStats = {
    banned_ips_count: db.prepare('SELECT COUNT(*) as count FROM banned_ips').get().count,
    scans_today: db.prepare(`SELECT COUNT(*) as count FROM security_scans
      WHERE created_at > datetime('now', '-1 day')`).get().count,
    high_risk_scans: db.prepare(`SELECT COUNT(*) as count FROM security_scans
      WHERE risk_score >= 60 AND created_at > datetime('now', '-1 day')`).get().count,
    active_visitors: db.prepare(`SELECT COUNT(DISTINCT ip) as count FROM access_logs
      WHERE created_at > datetime('now', '-5 minutes')`).get().count,
    total_admins: db.prepare('SELECT COUNT(*) as count FROM admins').get().count
  };

  res.json({ access: accessStats, security: securityStats, realtime: realtimeStats });
});

app.get('/api/admin/logs/access', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const logs = getRecentLogs(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM access_logs').get().count;
  res.json({ logs, total, limit, offset });
});

app.get('/api/admin/logs/security', authMiddleware, (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  const stats = getSecurityStats(hours);
  res.json(stats);
});

app.get('/api/admin/admins', authMiddleware, (req, res) => {
  const admins = getAdminList();
  res.json({ admins });
});

app.post('/api/admin/change-password', authMiddleware, (req, res) => {
  const { old_password, new_password } = req.body;
  const result = changePassword(req.admin.id, old_password, new_password);
  if (result.success) {
    logSecurityEvent('password_changed', 'medium', req, `管理员 ${req.admin.username} 修改密码`, null);
    res.json({ success: true });
  } else {
    res.status(400).json({ error: result.message });
  }
});

// ============ QQ 二级验证 API ============

// 获取当前管理员 QQ 绑定状态
app.get('/api/admin/qq-binding', authMiddleware, (req, res) => {
  const binding = db.prepare('SELECT * FROM admin_qq_bindings WHERE admin_id = ? AND status = ?').get(req.admin.id, 'active');
  res.json({
    qq_configured: qqAuth.isQQConfigured(),
    bound: !!binding,
    binding: binding ? {
      id: binding.id,
      nickname: binding.nickname,
      avatar: binding.avatar,
      last_used_at: binding.last_used_at,
      created_at: binding.created_at,
      openid_preview: binding.openid ? binding.openid.slice(0, 6) + '...' : null
    } : null
  });
});

// 获取 QQ 绑定授权 URL
app.get('/api/admin/qq-bind-url', authMiddleware, (req, res) => {
  if (!qqAuth.isQQConfigured()) {
    return res.status(400).json({ error: 'QQ 互联未配置' });
  }
  const url = qqAuth.getQQAuthURL(req.ip, 'bind');
  res.json({ auth_url: url });
});

// 解绑 QQ
app.post('/api/admin/qq-unbind', authMiddleware, (req, res) => {
  const result = qqAuth.unbindQQ(req.admin.id);
  if (result.success) {
    logSecurityEvent('qq_unbind', 'medium', req, `管理员 ${req.admin.username} 解绑 QQ`, null);
    res.json({ success: true });
  } else {
    res.status(400).json({ error: result.error || '解绑失败' });
  }
});

// 首次绑定QQ验证码确认（含QQ号白名单验证）
app.post('/api/admin/qq-bind-confirm', rateLimitMiddleware(5, 60 * 1000, 'qq_bind_confirm'), (req, res) => {
  const { twofa_token, code, qq_number } = req.body;
  if (!twofa_token || !code) {
    return res.status(400).json({ error: '参数缺失' });
  }

  // 查询二级验证会话
  const session = db.prepare('SELECT * FROM two_fa_sessions WHERE session_token = ?').get(twofa_token);
  if (!session) {
    return res.status(400).json({ error: '会话不存在或已过期' });
  }

  // 检查验证码
  if (!session.bind_code || session.bind_code !== code) {
    return res.status(400).json({ error: '验证码错误' });
  }

  if (!session.bind_code_expires || new Date(session.bind_code_expires) < new Date()) {
    return res.status(400).json({ error: '验证码已过期，请重新发起绑定' });
  }

  // QQ号白名单验证（如果会话中已存储QQ号）
  const qqNumToVerify = qq_number || session.qq_number;
  if (qqNumToVerify) {
    const whitelistCheck = qqAuth.validateQQNumber(qqNumToVerify);
    if (!whitelistCheck.valid) {
      logSecurityEvent('qq_whitelist_reject', 'critical', req, 
        `QQ绑定被拒绝：QQ号 ${qqNumToVerify} 不在白名单中`, 
        { qq_number: qqNumToVerify, whitelist: whitelistCheck.whitelist });
      return res.status(403).json({ 
        error: '该QQ号未授权绑定',
        reason: 'qq_not_whitelisted'
      });
    }
  }

  // 验证通过，完成绑定
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(session.admin_id);
  if (!admin) {
    return res.status(400).json({ error: '管理员不存在' });
  }

  // 检查是否已被绑定
  if (qqAuth.isQQBound(session.qq_openid)) {
    return res.status(400).json({ error: '该QQ已被其他账号绑定' });
  }

  // 执行绑定（传入选中的QQ号）
  const bindResult = qqAuth.bindQQToAdmin(
    session.admin_id, 
    session.qq_openid, 
    session.qq_nickname || '', 
    session.qq_avatar || '',
    qqNumToVerify
  );
  if (!bindResult.success) {
    return res.status(500).json({ error: bindResult.error || '绑定失败' });
  }

  // 标记会话已验证
  qqAuth.mark2FAVerified(twofa_token, session.qq_openid);

  logSecurityEvent('qq_bind', 'low', req, 'QQ 授权绑定成功（邮箱验证通过）', { admin: admin.username, qq_number: qqNumToVerify });

  res.json({ success: true, admin: { id: admin.id, username: admin.username, role: admin.role } });
});

// ============ 安全事件上报 API ============

// 服务端Token下发（短路径，不暴露意图）
app.get('/api/s/i', (req, res) => {
  const token = generateServerToken(req);
  res.setHeader('Cache-Control', 'no-store');
  res.json(token);
});

// 反调试检测上报（短路径）
app.post('/api/s/d', (req, res) => {
  const { m } = req.body;
  
  logSecurityEvent('devtools_detected', 'high', req, 
    `检测到开发者工具: ${m || 'unknown'}`, 
    { detection_method: m });
  
  res.json({ ok: true });
});

// 安全异常上报
app.post('/api/security/incident', rateLimitMiddleware(10, 60 * 1000, 'security_incident'), (req, res) => {
  const { type, description, details } = req.body;
  
  if (!type) {
    return res.status(400).json({ error: '事件类型必填' });
  }
  
  const severity = ['critical', 'high', 'medium', 'low'].includes(req.body.severity) 
    ? req.body.severity 
    : 'medium';
  
  logSecurityEvent(`client_${type}`, severity, req, description || '客户端安全事件', details || {});
  
  res.json({ success: true });
});

// ============ AI 沙盒 API ============

// AI 风险分析接口（管理后台使用）
app.post('/api/admin/ai-analyze', authMiddleware, (req, res) => {
  const { ip, headers, path, behavior_data } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP 为必填' });
  }

  const mockReq = {
    ip,
    headers: headers || {},
    path: path || '/',
    method: 'GET',
    query: {},
    body: {},
    requestId: crypto.randomBytes(16).toString('hex'),
    originalUrl: path || '/'
  };

  const { threats, uaAnalysis } = detectThreats(mockReq);
  const aiResult = aiSandboxAnalysis(mockReq, threats, uaAnalysis, behavior_data);

  res.json({
    success: true,
    ip,
    ai_analysis: aiResult,
    threats,
    ua_analysis: uaAnalysis
  });
});

// 获取 AI 分析记录
app.get('/api/admin/ai-logs', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const riskLevel = req.query.risk_level;
  
  let query = 'SELECT * FROM ai_analysis';
  const params = [];
  
  if (riskLevel && riskLevel !== 'all') {
    query += ' WHERE risk_level = ?';
    params.push(riskLevel);
  }
  
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);
  
  const logs = db.prepare(query).all(...params);
  
  let countQuery = 'SELECT COUNT(*) as count FROM ai_analysis';
  let countParams = [];
  if (riskLevel && riskLevel !== 'all') {
    countQuery += ' WHERE risk_level = ?';
    countParams.push(riskLevel);
  }
  const total = db.prepare(countQuery).get(...countParams).count;
  
  res.json({ logs, total, limit, offset });
});

// AI 沙盒实时扫描状态
app.get('/api/admin/ai-status', authMiddleware, (req, res) => {
  const recentAnalysis = db.prepare(`
    SELECT risk_level, COUNT(*) as count 
    FROM ai_analysis 
    WHERE created_at > datetime('now', '-1 hour') 
    GROUP BY risk_level
  `).all();
  
  const todayStats = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN risk_level = 'safe' THEN 1 ELSE 0 END) as safe
    FROM ai_analysis
    WHERE created_at > datetime('now', '-1 day')
  `).get();
  
  const avgConfidence = db.prepare(`
    SELECT AVG(confidence) as avg_confidence
    FROM ai_analysis
    WHERE created_at > datetime('now', '-1 day')
  `).get().avg_confidence || 0;

  res.json({
    success: true,
    model: 'jifeng_security_v2.0',
    status: 'active',
    recent_analysis: recentAnalysis,
    today_stats: todayStats,
    avg_confidence: Math.round(avgConfidence * 100) / 100
  });
});

// 手动触发 AI 分析并处理
app.post('/api/admin/ai-analyze-and-block', authMiddleware, (req, res) => {
  const { ip, reason } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP 为必填' });
  }

  const mockReq = {
    ip,
    headers: {},
    path: '/manual-ai-check',
    method: 'POST',
    query: {},
    body: {},
    requestId: crypto.randomBytes(16).toString('hex'),
    originalUrl: '/manual-ai-check'
  };

  const { threats, uaAnalysis } = detectThreats(mockReq);
  const aiResult = aiSandboxAnalysis(mockReq, threats, uaAnalysis);

  let action = 'analyzed';
  if (aiResult.risk_level === 'critical' || aiResult.risk_score >= 70) {
    banIP(ip, `AI 手动分析封禁: ${reason || '高危风险'}`, 'critical', req.admin.username);
    action = 'banned';
    logSecurityEvent('ai_manual_ban', 'critical', req, `AI 手动分析封禁 IP: ${ip}`, { 
      ai_result: aiResult, 
      reason 
    });
  } else if (aiResult.risk_level === 'high' || aiResult.risk_score >= 50) {
    banIP(ip, `AI 手动分析封禁: ${reason || '高风险'}`, 'high', req.admin.username);
    action = 'banned';
    logSecurityEvent('ai_manual_ban', 'high', req, `AI 手动分析封禁 IP: ${ip}`, { 
      ai_result: aiResult, 
      reason 
    });
  }

  res.json({
    success: true,
    ip,
    ai_analysis: aiResult,
    action,
    threats
  });
});

// ============ 高级安全 API ============

// 请求动态管理路径（发送到邮箱）
app.post('/api/admin/request-dynamic-path', (req, res) => {
  const ip = req.ip;
  
  // 创建动态路径
  const dynamicPath = advancedSecurity.createDynamicPathForIP(ip);
  
  // 发送邮件
  emailService.sendDynamicPath(dynamicPath, ip);
  
  res.json({ 
    success: true, 
    message: '动态管理路径已发送到管理员邮箱',
    expiresIn: '1小时'
  });
});

// IP 白名单管理
app.get('/api/admin/whitelist', authMiddleware, (req, res) => {
  const list = advancedSecurity.getWhitelist();
  res.json({ whitelist: list });
});

app.post('/api/admin/whitelist/add', authMiddleware, (req, res) => {
  const { ip, description } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP 为必填' });
  }
  
  const success = advancedSecurity.addToWhitelist(ip, description, req.admin.username);
  if (success) {
    logSecurityEvent('whitelist_add', 'low', req, `添加 IP 到白名单: ${ip}`, { ip, description });
  }
  res.json({ success, ip });
});

app.post('/api/admin/whitelist/remove', authMiddleware, (req, res) => {
  const { ip } = req.body;
  advancedSecurity.removeFromWhitelist(ip);
  logSecurityEvent('whitelist_remove', 'low', req, `从白名单移除 IP: ${ip}`, { ip });
  res.json({ success: true });
});

// 登录历史
app.get('/api/admin/login-history', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const history = db.prepare(`
    SELECT * FROM login_history 
    ORDER BY created_at DESC 
    LIMIT ?
  `).all(limit);
  res.json({ history });
});

// 安全警报
app.get('/api/admin/security-alerts', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const alerts = advancedSecurity.getRecentAlerts(limit);
  res.json({ alerts });
});

// ============ 公告管理 API ============

app.get('/api/announcements', (req, res) => {
  const announcements = wsServer.getVisibleAnnouncements();
  res.json({ announcements });
});

app.get('/api/admin/announcements', authMiddleware, (req, res) => {
  const announcements = wsServer.getAllAnnouncements();
  res.json({ announcements });
});

app.post('/api/admin/announcements', authMiddleware, (req, res) => {
  const { title, content, type, priority } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: '标题和内容为必填' });
  }
  
  const announcement = wsServer.createAnnouncement(title, content, type, priority || 0, req.admin.username);
  logSecurityEvent('announcement_created', 'low', req, `发布公告: ${title}`, announcement);
  res.json({ success: true, announcement });
});

app.put('/api/admin/announcements/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  const announcement = wsServer.updateAnnouncement(parseInt(id), updates);
  if (!announcement) {
    return res.status(404).json({ error: '公告不存在' });
  }
  
  logSecurityEvent('announcement_updated', 'low', req, `更新公告: ${id}`, updates);
  res.json({ success: true, announcement });
});

app.delete('/api/admin/announcements/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  wsServer.deleteAnnouncement(parseInt(id));
  logSecurityEvent('announcement_deleted', 'low', req, `删除公告: ${id}`);
  res.json({ success: true });
});

// ============ WebSocket 统计 API ============

app.get('/api/admin/ws-stats', authMiddleware, (req, res) => {
  const stats = wsServer.getOnlineStats();
  res.json({ stats });
});

// ============ AI 服务 API ============
// 提供客服、内容审核、Release 摘要能力，无 Key 时自动降级到本地规则引擎

const aiService = require('./ai-service');

// 初始化 AI 同步状态表（幂等）
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ai_release_sync (
      repo TEXT NOT NULL,
      tag_name TEXT NOT NULL,
      published_at TEXT,
      synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      announcement_id INTEGER,
      PRIMARY KEY (repo, tag_name)
    );
    CREATE TABLE IF NOT EXISTS ai_chat_sessions (
      session_id TEXT PRIMARY KEY,
      ip TEXT,
      ua TEXT,
      messages TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_ai_chat_sessions_ip ON ai_chat_sessions(ip);
  `);
} catch (e) {
  console.error('[DB] AI 表初始化失败:', e.message);
}

const TRACKED_REPOS = [
  { repo: 'Yangchengen-hub/JFToolbox', label: '极风工具箱', type: 'release' },
  { repo: 'Yangchengen-hub/JifengEnvDetect', label: '极风环境检测', type: 'release' },
];

async function fetchGitHubLatest(repo) {
  const url = `https://api.github.com/repos/${repo}/releases/latest`;
  const res = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'jifeng-studio-sync',
      ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(`GitHub ${res.status}: ${t.slice(0, 200)}`);
  }
  return res.json();
}

async function syncOneRepo(repoInfo) {
  const release = await fetchGitHubLatest(repoInfo.repo);
  if (!release || !release.tag_name) {
    return { repo: repoInfo.repo, status: 'no_release' };
  }

  // 检查是否已同步
  const existing = db.prepare('SELECT * FROM ai_release_sync WHERE repo=? AND tag_name=?').get(repoInfo.repo, release.tag_name);
  if (existing) {
    return { repo: repoInfo.repo, tag: release.tag_name, status: 'already_synced', announcement_id: existing.announcement_id };
  }

  // AI 摘要
  const summary = await aiService.summarizeRelease(repoInfo.repo, release);

  // 创建公告（默认可见）
  const title = `[${repoInfo.label}] ${summary.title}`;
  const content = `${summary.body}\n\n---\n来源：${summary.source}`;
  const announcement = wsServer.createAnnouncement(title, content, 'release', 5, 'ai-sync');

  // 记录同步
  db.prepare('INSERT INTO ai_release_sync (repo, tag_name, published_at, announcement_id) VALUES (?,?,?,?)')
    .run(repoInfo.repo, release.tag_name, release.published_at || null, announcement.id || null);

  logSecurityEvent('ai_release_synced', 'low', null, `AI 同步 ${repoInfo.repo} ${release.tag_name}`, { repo: repoInfo.repo, tag: release.tag_name, announcement_id: announcement.id });

  return {
    repo: repoInfo.repo,
    tag: release.tag_name,
    status: 'synced',
    announcement_id: announcement.id,
    summary,
  };
}

// Vercel Cron: 每小时检查仓库更新（无鉴权，使用 VERCEL_CRON_SECRET 校验）
app.get('/api/cron/sync-releases', async (req, res) => {
  // Vercel cron 会带 x-vercel-cron 头；同时支持 ?secret= 手动触发
  const isVercelCron = req.headers['x-vercel-cron'] === '1';
  const secretOk = req.query.secret && req.query.secret === (process.env.VERCEL_CRON_SECRET || process.env.CRON_SECRET);
  if (!isVercelCron && !secretOk) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const results = [];
  for (const repoInfo of TRACKED_REPOS) {
    try {
      results.push(await syncOneRepo(repoInfo));
    } catch (e) {
      results.push({ repo: repoInfo.repo, status: 'error', message: e.message });
    }
  }
  res.json({ success: true, results, timestamp: new Date().toISOString() });
});

// 管理员手动触发同步
app.post('/api/admin/sync-releases', authMiddleware, async (req, res) => {
  const results = [];
  for (const repoInfo of TRACKED_REPOS) {
    try {
      results.push(await syncOneRepo(repoInfo));
    } catch (e) {
      results.push({ repo: repoInfo.repo, status: 'error', message: e.message });
    }
  }
  logSecurityEvent('admin_sync_releases', 'low', req, '管理员手动触发仓库同步', { results });
  res.json({ success: true, results });
});

// 同步状态查询
app.get('/api/admin/sync-status', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM ai_release_sync ORDER BY synced_at DESC').all();
  const tracked = TRACKED_REPOS.map((r) => ({ repo: r.repo, label: r.label }));
  res.json({ success: true, tracked, sync_history: rows });
});

// AI 配置查询（不返回 key 明文）
app.get('/api/admin/ai-config', authMiddleware, (req, res) => {
  const cfg = aiService.getConfig();
  res.json({
    success: true,
    config: {
      enabled: cfg.enabled,
      api_base: cfg.apiBase,
      model: cfg.model,
      has_key: !!cfg.apiKey,
      key_preview: cfg.apiKey ? cfg.apiKey.slice(0, 4) + '****' + cfg.apiKey.slice(-4) : '',
    },
  });
});

// 公开 AI 客服端点（限流 + 会话）
app.post('/api/chat', rateLimitMiddleware(15, 60 * 1000, 'ai_chat'), async (req, res) => {
  const { message, session_id, history } = req.body || {};
  if (!message || !message.trim()) {
    return res.status(400).json({ error: '消息不能为空' });
  }
  if (String(message).length > 800) {
    return res.status(400).json({ error: '消息过长（≤800 字符）' });
  }

  const sid = session_id || aiService.newSessionId();
  const hist = Array.isArray(history) ? history.slice(-6) : [];

  // 简单会话持久化
  try {
    db.prepare(`
      INSERT INTO ai_chat_sessions (session_id, ip, ua, messages, updated_at)
      VALUES (?,?,?,?,datetime('now'))
      ON CONFLICT(session_id) DO UPDATE SET
        messages=excluded.messages, updated_at=datetime('now')
    `).run(sid, req.ip, (req.headers['user-agent'] || '').slice(0, 200), JSON.stringify(hist.concat([{ role: 'user', content: message }])).slice(0, 8000));
  } catch (_) {}

  const r = await aiService.customerService(message, hist, { ip: req.ip });
  res.json({
    success: r.ok,
    session_id: sid,
    reply: r.content,
    model: r.model || (r.fallback ? 'local-fallback' : 'unknown'),
    fallback: !!r.fallback,
  });
});

// 增强：管理员 AI 内容审核
app.post('/api/admin/ai-moderate', authMiddleware, async (req, res) => {
  const { content, nickname } = req.body || {};
  if (!content) return res.status(400).json({ error: 'content 为必填' });
  const r = await aiService.moderate({ content, nickname: nickname || '', ip: req.ip });
  logSecurityEvent('ai_moderate', r.verdict === 'reject' ? 'high' : 'low', req, `AI 审核: ${r.verdict}`, r);
  res.json({ success: true, ...r });
});

// ============ 设备指纹 API ============

app.post('/api/device/fingerprint', (req, res) => {
  const { fingerprint } = req.body;

  if (!fingerprint) {
    return res.status(400).json({ error: '缺少指纹数据' });
  }

  // 检查设备是否已被封禁
  const banCheck = advancedSecurity.isIPAndDeviceBanned(req.ip, fingerprint.hash);
  if (banCheck.deviceBanned) {
    return res.status(403).json({
      error: 'device_banned',
      message: '您的设备已被封禁',
      canAppeal: true
    });
  }

  // 保存设备指纹
  const id = advancedSecurity.saveDeviceFingerprint(req.ip, fingerprint);

  // 记录访客会话
  const sessionToken = advancedSecurity.recordVisitorSession({
    ip: req.ip,
    fingerprintHash: fingerprint.hash,
    userAgent: req.headers['user-agent'] || '',
    deviceBrand: fingerprint.deviceBrand || '',
    deviceModel: fingerprint.deviceModel || '',
    os: fingerprint.os || '',
    osVersion: fingerprint.osVersion || '',
    browser: fingerprint.browser || '',
    browserVersion: fingerprint.browserVersion || '',
    screenResolution: fingerprint.screenInfo ? `${fingerprint.screenInfo.width}x${fingerprint.screenInfo.height}` : '',
    timezone: fingerprint.timezone || '',
    language: fingerprint.language || '',
    isMobile: fingerprint.browserFeatures?.touchSupport || false,
    isBot: fingerprint.browserFeatures?.webdriver || false,
    riskScore: fingerprint.riskScore || 0,
    riskFactors: fingerprint.riskFactors || []
  });

  // 如果风险评分高，记录安全事件
  if (fingerprint.riskScore >= 50) {
    logSecurityEvent('high_risk_device', 'high', req,
      `高风险设备检测: 风险评分 ${fingerprint.riskScore}`,
      { riskFactors: fingerprint.riskFactors, fingerprintHash: fingerprint.hash });

    // 通知管理端
    wsServer.broadcastToAdmins({
      type: 'high_risk_device',
      data: {
        ip: req.ip,
        riskScore: fingerprint.riskScore,
        riskFactors: fingerprint.riskFactors,
        deviceInfo: fingerprint.browserFeatures
      }
    });

    // 发送邮件报警
    const alert = advancedSecurity.createSecurityAlert(
      'high_risk_device', 'high', req.ip,
      `检测到高风险设备访问: IP ${req.ip}, 风险评分 ${fingerprint.riskScore}`,
      fingerprint
    );

    if (alert.shouldNotifyEmail) {
      emailService.sendSecurityAlert({ ...alert, ...fingerprint, ip: req.ip });
    }

    // 风险评分极高，自动封禁设备
    if (fingerprint.riskScore >= 80) {
      advancedSecurity.banDevice(fingerprint.hash, req.ip, fingerprint, '自动封禁: 风险评分极高', 'critical', 'system');
      logSecurityEvent('auto_device_ban', 'critical', req,
        `自动封禁设备: 风险评分 ${fingerprint.riskScore}`, { fingerprintHash: fingerprint.hash });
    }
  }

  res.json({ success: true, id, sessionToken, riskScore: fingerprint.riskScore });
});

// ============ 申诉解封 API ============

// 检查是否被封禁
app.get('/api/appeal/check-ban', (req, res) => {
  const fingerprintHash = req.query.fingerprint;
  const ip = req.ip;

  const banCheck = advancedSecurity.isIPAndDeviceBanned(ip, fingerprintHash);

  if (banCheck.banned) {
    // 获取封禁详情
    let banInfo = null;
    if (banCheck.deviceBanned && fingerprintHash) {
      banInfo = db.prepare('SELECT * FROM banned_devices WHERE fingerprint_hash = ?').get(fingerprintHash);
    } else if (banCheck.ipBanned) {
      banInfo = db.prepare('SELECT * FROM banned_ips WHERE ip = ?').get(ip);
    }

    res.json({
      banned: true,
      type: banCheck.deviceBanned ? 'device' : 'ip',
      reason: banInfo?.reason || '未知原因',
      banId: banInfo?.id,
      appealToken: banInfo?.appeal_token,
      canAppeal: true,
      createdAt: banInfo?.created_at
    });
  } else {
    res.json({ banned: false });
  }
});

// 提交申诉
app.post('/api/appeal/submit', rateLimitMiddleware(3, 60 * 60 * 1000, 'appeal'), (req, res) => {
  const { fingerprint_hash, type, reason, contact_email, appeal_message, device_info } = req.body;

  if (!reason || !contact_email) {
    return res.status(400).json({ error: '申诉理由和联系邮箱为必填' });
  }

  // 创建申诉
  const result = advancedSecurity.createAppeal(
    type || 'ip',
    req.ip,
    fingerprint_hash,
    reason,
    contact_email,
    appeal_message
  );

  if (result.success) {
    // 获取完整申诉记录
    const appeal = db.prepare('SELECT * FROM appeals WHERE appeal_token = ?').get(result.appealToken);

    // 发送邮件通知管理员
    emailService.sendAppealNotification(appeal);

    // 通知管理端WebSocket
    wsServer.broadcastToAdmins({
      type: 'new_appeal',
      data: appeal
    });

    res.json({
      success: true,
      appealToken: result.appealToken,
      message: '申诉已提交，管理员会尽快处理，处理结果将发送到您的邮箱'
    });
  } else {
    res.status(500).json({ error: result.error || '申诉提交失败' });
  }
});

// 管理端 - 获取申诉列表
app.get('/api/admin/appeals', authMiddleware, (req, res) => {
  const status = req.query.status || 'all';
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const appeals = advancedSecurity.getAppeals(status, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM appeals').get().count;
  res.json({ appeals, total, limit, offset });
});

// 管理端 - 处理申诉
app.post('/api/admin/appeals/:id/process', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { status, admin_reply } = req.body;

  if (!status || !['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: '无效的状态' });
  }

  const result = advancedSecurity.processAppeal(parseInt(id), status, admin_reply, req.admin.username);

  if (result.success) {
    // 发送处理结果邮件给申诉者
    if (result.appeal.contact_email) {
      emailService.sendAppealResult(result.appeal, admin_reply);
    }

    logSecurityEvent('appeal_processed', 'medium', req,
      `处理申诉 #${id}: ${status}`, { id, status, admin_reply });

    res.json({ success: true, appeal: result.appeal });
  } else {
    res.status(400).json({ error: result.error });
  }
});

// ============ 设备封禁管理 API ============

// 管理端 - 获取封禁设备列表
app.get('/api/admin/banned-devices', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  const devices = advancedSecurity.getBannedDevices(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM banned_devices').get().count;
  res.json({ devices, total, limit, offset });
});

// 管理端 - 手动封禁设备
app.post('/api/admin/ban-device', authMiddleware, (req, res) => {
  const { fingerprint_hash, ip, device_info, reason, severity } = req.body;
  if (!fingerprint_hash || !reason) {
    return res.status(400).json({ error: '设备指纹和封禁原因为必填' });
  }

  const result = advancedSecurity.banDevice(fingerprint_hash, ip || req.ip, device_info, reason, severity || 'high', req.admin.username);
  if (result.success) {
    logSecurityEvent('manual_device_ban', 'high', req,
      `手动封禁设备: ${fingerprint_hash}`, { fingerprint_hash, reason });
    res.json({ success: true, appealToken: result.appealToken });
  } else {
    res.status(500).json({ error: result.error });
  }
});

// 管理端 - 解封设备
app.post('/api/admin/unban-device', authMiddleware, (req, res) => {
  const { fingerprint_hash } = req.body;
  if (!fingerprint_hash) {
    return res.status(400).json({ error: '设备指纹为必填' });
  }

  advancedSecurity.unbanDevice(fingerprint_hash);
  logSecurityEvent('manual_device_unban', 'medium', req,
    `手动解封设备: ${fingerprint_hash}`, { fingerprint_hash });
  res.json({ success: true });
});

// ============ 访客记录 API ============

// 管理端 - 获取访客会话列表
app.get('/api/admin/visitors', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const visitors = advancedSecurity.getVisitorSessions(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM visitor_sessions').get().count;
  res.json({ visitors, total, limit, offset });
});

// 管理端 - 获取单个访客详情
app.get('/api/admin/visitors/:token', authMiddleware, (req, res) => {
  const visitor = advancedSecurity.getVisitorDetail(req.params.token);
  if (!visitor) {
    return res.status(404).json({ error: '访客记录不存在' });
  }
  res.json({ visitor });
});

// 管理端 - 获取脱敏的作者邮箱
app.get('/api/admin/author-info', authMiddleware, (req, res) => {
  res.json({
    email: advancedSecurity.getMaskedAuthorEmail(),
    emailConfigured: !!process.env.EMAIL_USER && !!process.env.EMAIL_PASS
  });
});

// 下载验证码
app.get('/api/download/verify', (req, res) => {
  const captcha = createCaptcha('download');
  const csrfToken = generateCSRFToken();
  csrfTokens.set(csrfToken, { createdAt: Date.now(), ip: req.ip });
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({
    token: captcha.token,
    svg: captcha.svg,
    type: captcha.type,
    csrfToken
  });
});

// 下载文件（带验证码 + 行为校验）
app.post('/api/download/verify', rateLimitMiddleware(10, 60 * 1000, 'download'), (req, res) => {
  const { captcha_token, captcha_answer, file, behavior_data, csrf_token } = req.body;

  if (!file) {
    return res.status(400).json({ error: '缺少文件名' });
  }

  // CSRF 校验
  if (!verifyCSRFToken(csrf_token, req.ip)) {
    return res.status(403).json({ error: '会话已过期，请刷新页面', csrf_error: true });
  }

  // 验证码校验（带行为数据）
  const captchaResult = verifyCaptcha(captcha_token, captcha_answer, 'download', behavior_data);
  if (!captchaResult.valid) {
    consumeCSRFToken(csrf_token);
    const newCaptcha = createCaptcha('download');
    const newCSRF = generateCSRFToken();
    csrfTokens.set(newCSRF, { createdAt: Date.now(), ip: req.ip });
    return res.status(400).json({
      error: captchaResult.reason === 'wrong_answer' ? '验证码错误' :
             captchaResult.reason === 'behavior_check_failed' ? '行为检测未通过，疑似机器人' :
             '验证码已过期',
      captcha_error: true,
      new_captcha: { token: newCaptcha.token, svg: newCaptcha.svg, type: newCaptcha.type },
      csrf_token: newCSRF
    });
  }

  consumeCSRFToken(csrf_token);

  // 路径安全检查
  const downloadsDir = path.join(__dirname, '..', 'downloads');
  const filePath = path.join(downloadsDir, path.basename(file));
  if (!filePath.startsWith(downloadsDir)) {
    return res.status(400).json({ error: '非法文件路径' });
  }
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: '文件不存在' });
  }

  try {
    db.prepare(`
      INSERT INTO download_logs (ip, file_name, user_agent, captcha_verified)
      VALUES (?, ?, ?, 1)
    `).run(req.ip, file, req.headers['user-agent'] || '');
  } catch (e) {
    console.error('[Download] Log failed:', e.message);
  }

  logSecurityEvent('file_downloaded', 'low', req, `文件下载: ${file}`, { file });
  res.json({ success: true, file, download_url: `/download/serve/${encodeURIComponent(path.basename(file))}?t=${Date.now()}` });
});

// 实际文件服务（短时效）
const recentDownloadTokens = new Map();
app.get('/download/serve/:filename', (req, res) => {
  const { filename } = req.params;
  const token = req.query.t;

  if (!token || !recentDownloadTokens.has(String(token))) {
    return res.status(403).json({ error: '无效的下载链接' });
  }
  recentDownloadTokens.delete(String(token));

  const downloadsDir = path.join(__dirname, '..', 'downloads');
  const filePath = path.join(downloadsDir, path.basename(filename));
  if (!filePath.startsWith(downloadsDir) || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: '文件不存在' });
  }
  res.download(filePath, filename);
});

// 保留旧 GET 接口兼容
app.get('/download/:filename', (req, res) => {
  const { filename } = req.params;
  const { captcha_token, captcha_answer } = req.query;
  const captchaResult = verifyCaptcha(captcha_token, captcha_answer, 'download');
  if (!captchaResult.valid) {
    return res.status(400).json({
      error: captchaResult.reason === 'wrong_answer' ? '验证码错误' : '验证码已过期',
      captcha_error: true
    });
  }

  const downloadsDir = path.join(__dirname, '..', 'downloads');
  const filePath = path.join(downloadsDir, path.basename(filename));
  if (!filePath.startsWith(downloadsDir) || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: '文件不存在' });
  }

  try {
    db.prepare(`
      INSERT INTO download_logs (ip, file_name, user_agent, captcha_verified)
      VALUES (?, ?, ?, 1)
    `).run(req.ip, filename, req.headers['user-agent'] || '');
  } catch (e) {
    console.error('[Download] Log failed:', e.message);
  }

  res.download(filePath, filename);
});

app.get('/api/admin/download-logs', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const logs = db.prepare(`
    SELECT * FROM download_logs
    ORDER BY created_at DESC
    LIMIT ?
  `).all(limit);
  res.json({ logs });
});

// ============ 下载链接管理 API ============

app.get('/api/download-links', (req, res) => {
  const links = db.prepare(`
    SELECT * FROM download_links WHERE is_active = 1 ORDER BY sort_order ASC, id ASC
  `).all();
  res.json({ links });
});

app.get('/api/admin/download-links', authMiddleware, (req, res) => {
  const links = db.prepare(`
    SELECT * FROM download_links ORDER BY sort_order ASC, id ASC
  `).all();
  res.json({ links });
});

app.post('/api/admin/download-links', authMiddleware, (req, res) => {
  const { name, file_name, description, version, file_size, icon, download_url, is_active, sort_order } = req.body;
  if (!name || !file_name || !download_url) {
    return res.status(400).json({ error: '名称、文件名、下载链接为必填' });
  }
  const info = db.prepare(`
    INSERT INTO download_links (name, file_name, description, version, file_size, icon, download_url, is_active, sort_order, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(name, file_name, description || '', version || '', file_size || '', icon || '📦', download_url, is_active ?? 1, sort_order ?? 0);
  logSecurityEvent('download_link_created', 'low', req, `创建下载链接: ${name}`, { id: info.lastInsertRowid });
  res.json({ success: true, id: info.lastInsertRowid });
});

app.put('/api/admin/download-links/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const allowed = ['name', 'file_name', 'description', 'version', 'file_size', 'icon', 'download_url', 'is_active', 'sort_order'];
  const sets = [];
  const values = [];
  for (const key of allowed) {
    if (updates[key] !== undefined) {
      sets.push(`${key} = ?`);
      values.push(updates[key]);
    }
  }
  if (sets.length === 0) {
    return res.status(400).json({ error: '无有效字段' });
  }
  sets.push("updated_at = datetime('now')");
  values.push(parseInt(id));
  const info = db.prepare(`UPDATE download_links SET ${sets.join(', ')} WHERE id = ?`).run(...values);
  if (info.changes === 0) {
    return res.status(404).json({ error: '记录不存在' });
  }
  logSecurityEvent('download_link_updated', 'low', req, `更新下载链接 #${id}`);
  res.json({ success: true });
});

app.delete('/api/admin/download-links/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM download_links WHERE id = ?').run(parseInt(id));
  logSecurityEvent('download_link_deleted', 'low', req, `删除下载链接 #${id}`);
  res.json({ success: true });
});

// ============ 官网内容管理 API ============

app.get('/api/site-content', (req, res) => {
  const contents = db.prepare('SELECT * FROM site_content WHERE is_active = 1').all();
  const map = {};
  contents.forEach(c => { map[c.section] = c; });
  res.json({ content: map });
});

app.get('/api/admin/site-content', authMiddleware, (req, res) => {
  const contents = db.prepare('SELECT * FROM site_content ORDER BY section').all();
  res.json({ contents });
});

app.post('/api/admin/site-content', authMiddleware, (req, res) => {
  const { section, title, content, is_active } = req.body;
  if (!section) {
    return res.status(400).json({ error: 'section 为必填' });
  }
  db.prepare(`
    INSERT OR REPLACE INTO site_content (section, title, content, is_active, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).run(section, title || '', content || '', is_active ?? 1);
  logSecurityEvent('site_content_updated', 'low', req, `更新官网内容: ${section}`);
  res.json({ success: true });
});

// ============ 仓库管理 API ============

app.get('/api/repository', (req, res) => {
  const category = req.query.category;
  let rows;
  if (category && category !== 'all') {
    rows = db.prepare('SELECT * FROM repository_items WHERE is_active = 1 AND category = ? ORDER BY sort_order ASC, id ASC').all(category);
  } else {
    rows = db.prepare('SELECT * FROM repository_items WHERE is_active = 1 ORDER BY category ASC, sort_order ASC, id ASC').all();
  }
  res.json({ repos: rows });
});

app.get('/api/admin/repository', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM repository_items ORDER BY category ASC, sort_order ASC, id ASC').all();
  res.json({ repos: rows });
});

app.post('/api/admin/repository', authMiddleware, (req, res) => {
  const { name, description, category, icon, repo_url, download_url, version, stars, is_active, sort_order } = req.body;
  if (!name) {
    return res.status(400).json({ error: '名称为必填' });
  }
  const info = db.prepare(`
    INSERT INTO repository_items (name, description, category, icon, repo_url, download_url, version, stars, is_active, sort_order, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(name, description || '', category || 'default', icon || '📁', repo_url || '', download_url || '', version || '', stars || 0, is_active ?? 1, sort_order ?? 0);
  logSecurityEvent('repo_created', 'low', req, `创建仓库项: ${name}`, { id: info.lastInsertRowid });
  res.json({ success: true, id: info.lastInsertRowid });
});

app.put('/api/admin/repository/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  const allowed = ['name', 'description', 'category', 'icon', 'repo_url', 'download_url', 'version', 'stars', 'is_active', 'sort_order'];
  const sets = [];
  const values = [];
  for (const key of allowed) {
    if (updates[key] !== undefined) {
      sets.push(`${key} = ?`);
      values.push(updates[key]);
    }
  }
  if (sets.length === 0) {
    return res.status(400).json({ error: '无有效字段' });
  }
  sets.push("updated_at = datetime('now')");
  values.push(parseInt(id));
  const info = db.prepare(`UPDATE repository_items SET ${sets.join(', ')} WHERE id = ?`).run(...values);
  if (info.changes === 0) {
    return res.status(404).json({ error: '记录不存在' });
  }
  logSecurityEvent('repo_updated', 'low', req, `更新仓库项 #${id}`);
  res.json({ success: true });
});

app.delete('/api/admin/repository/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  db.prepare('DELETE FROM repository_items WHERE id = ?').run(parseInt(id));
  logSecurityEvent('repo_deleted', 'low', req, `删除仓库项 #${id}`);
  res.json({ success: true });
});

// ============ 主动防御增强 API ============

// 管理员触发全站扫描
app.post('/api/admin/scan-site', authMiddleware, (req, res) => {
  const { target_url } = req.body;
  logSecurityEvent('admin_scan_triggered', 'high', req, '管理员触发全站安全扫描', { target_url });
  res.json({ success: true, message: '扫描任务已提交，结果稍后在安全扫描页查看' });
});

// 一键阻断所有恶意 IP
app.post('/api/admin/block-all-malicious', authMiddleware, (req, res) => {
  const threshold = parseInt(req.body.threshold) || 3;
  const rows = db.prepare(`
    SELECT ip, COUNT(*) as cnt 
    FROM security_events 
    WHERE severity IN ('critical', 'high') 
    AND created_at > datetime('now', '-1 day')
    GROUP BY ip 
    HAVING cnt >= ?
  `).all(threshold);
  const banned = [];
  for (const row of rows) {
    banIP(row.ip, `自动封禁：24小时内触发 ${row.cnt} 次高危事件`, 'high', 'admin-bulk');
    banned.push(row.ip);
  }
  logSecurityEvent('bulk_malicious_block', 'high', req, `一键阻断 ${banned.length} 个恶意 IP`, { banned_ips: banned });
  res.json({ success: true, banned_count: banned.length, banned_ips: banned });
});

// 公开页面路由
const publicDir = path.join(__dirname, '..');
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/jftoolbox.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'jftoolbox.html'));
});

app.get('/jifengenvdetect.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'jifengenvdetect.html'));
});

app.get('/download.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'download.html'));
});

app.get('/appeal.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'appeal.html'));
});

// 管理页面路由（adminAccessCheck 已隐藏）
app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'dashboard.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

// 秘密路径访问管理后台
app.get('/:secretPath/admin.html', (req, res, next) => {
  const secretPath = getConfig('admin_secret_path');
  if (req.params.secretPath === secretPath) {
    return res.sendFile(path.join(publicDir, 'admin.html'));
  }
  next();
});

app.get('/:secretPath/dashboard.html', (req, res, next) => {
  const secretPath = getConfig('admin_secret_path');
  if (req.params.secretPath === secretPath) {
    return res.sendFile(path.join(publicDir, 'dashboard.html'));
  }
  next();
});

// 安全头和反调试脚本注入中间件
app.use((req, res, next) => {
  if (req.path.endsWith('.html') || req.path === '/') {
    const originalSend = res.send.bind(res);
    const originalSendFile = res.sendFile.bind(res);
    
    res.send = function(body) {
      if (typeof body === 'string' && body.includes('</body>')) {
        body = injectSecurityFeatures(body);
      }
      return originalSend(body);
    };
    
    const originalEnd = res.end.bind(res);
    const chunks = [];
    
    const originalWrite = res.write;
    let captured = false;
    let htmlContent = '';
    
    if (req.accepts('html') && (req.path === '/' || req.path.endsWith('.html'))) {
      captured = true;
      res.write = function(chunk) {
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return true;
      };
      
      res.end = function(chunk) {
        if (chunk) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        if (captured && chunks.length > 0) {
          htmlContent = Buffer.concat(chunks).toString('utf8');
          if (htmlContent.includes('</body>')) {
            htmlContent = injectSecurityFeatures(htmlContent);
            res.setHeader('Content-Length', Buffer.byteLength(htmlContent));
            captured = false;
            return originalEnd(Buffer.from(htmlContent));
          }
        }
        captured = false;
        return originalEnd(chunk);
      };
    }
    
    return next();
  } else {
    next();
  }
});

function injectSecurityFeatures(html) {
  const antiDebugScript = `<script src="/anti-debug.js" defer></script>`;
  const securityMeta = `
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">`;
  
  if (!html.includes('anti-debug.js')) {
    html = html.replace('</head>', `${securityMeta}\n</head>`);
    html = html.replace('</body>', `\n${antiDebugScript}\n</body>`);
  }
  
  return html;
}

// 拦截敏感路径，防止源码和配置文件被下载
const SENSITIVE_PATHS = [
  '/src/', '/api/', '/scripts/', '/.build_backup/',
  '/node_modules/', '/views/', '/data/',
  '/.env', '/.git', '/.vercel', '/.render',
  '/DEPLOY_GUIDE.md', '/render.yaml', '/vercel.json',
  '/package.json', '/package-lock.json', '/README',
  '/jifeng-api', '/jifeng-admin'
];

app.use((req, res, next) => {
  const pathname = req.path;
  const blocked = SENSITIVE_PATHS.some(p => pathname.startsWith(p));
  if (blocked) {
    return res.status(404).send('Not Found');
  }
  next();
});

// 静态文件服务（仅允许特定类型文件）
const ALLOWED_EXTENSIONS = [
  '.html', '.css', '.js', '.svg', '.png', '.jpg', '.jpeg',
  '.gif', '.ico', '.webp', '.woff', '.woff2', '.ttf',
  '.eot', '.mp3', '.mp4', '.pdf', '.txt'
];

app.use(express.static(publicDir, {
  extensions: ['html'],
  index: 'index.html',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  },
  filter: (req, file, cb) => {
    const ext = path.extname(file).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  }
}));

// 404 处理
app.use((req, res) => {
  res.status(404);
  if (req.path.startsWith('/api/')) {
    res.json({ error: '接口不存在' });
  } else {
    res.sendFile(path.join(__dirname, '..', 'views', '404.html'));
  }
});

// 错误处理
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  logSecurityEvent('server_error', 'low', req, err.message, { stack: err.stack });

  res.status(500);
  if (req.path.startsWith('/api/')) {
    res.json({ error: '服务器内部错误' });
  } else {
    res.render('blocked', {
      requestId: req.requestId,
      reason: 'server_error',
      severity: 'low',
      time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
    });
  }
});

if (require.main === module) {
  const server = http.createServer(app);
  wsServer.initWebSocketServer(server);

  server.listen(PORT, () => {
    const secretPath = getConfig('admin_secret_path');
    const accessToken = getConfig('admin_access_token');
    console.log(`
╔════════════════════════════════════════════════╗
║     极风工作室 - 网站服务已启动                ║
╠════════════════════════════════════════════════╣
║  公开地址: http://localhost:${PORT}              ║
║  WebSocket: ws://localhost:${PORT}/ws            ║
║                                                ║
║  管理后台（隐藏访问，仅自己可用）:             ║
║  1. 秘密URL: /${secretPath}/admin.html           ║
║  2. 令牌访问: /admin.html?_key=${accessToken?.slice(0,8) || '未设置'}...
║                                                ║
║  管理员账号: JIFENG                            ║
║  管理员密码: ****** (bcrypt加密存储)           ║
║                                                ║
║  已启用安全防护:                               ║
║  - Helmet 安全头（CSP/HSTS/X-Frame-Options）   ║
║  - WAF 防火墙（SQL注入/XSS/路径遍历检测）      ║
║  - 实时安全扫描引擎 + AI沙盒                   ║
║  - 多重验证码（图形+数学+行为+Turnstile）      ║
║  - IP 自动封禁 + 白名单                        ║
║  - CSRF 防护 + 防爆破                          ║
║  - 速率限制 + 登录锁定                         ║
║  - WebSocket 实时同步                          ║
║  - 邮件异常报警                                ║
╚════════════════════════════════════════════════╝
  `);
  });
}

module.exports = app;
