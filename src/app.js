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

// 新增高级安全模块
const advancedSecurity = require('./security-advanced');
const emailService = require('./email-service');
const wsServer = require('./websocket-server');

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

// 登录接口（带 CSRF 校验）
app.post('/api/login', rateLimitMiddleware(5, 60 * 1000, 'login'), (req, res) => {
  const { username, password, captcha_token, captcha_answer, csrf_token, behavior_data } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  // CSRF 校验
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
    res.cookie('admin_token', result.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ success: true, admin: result.admin });
  } else {
    consumeCSRFToken(csrf_token);
    const newCSRF = generateCSRFToken();
    csrfTokens.set(newCSRF, { createdAt: Date.now(), ip: req.ip });
    res.status(401).json({ error: result.message, csrf_token: newCSRF });
  }
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

// 静态文件服务（防止目录遍历）
app.use(express.static(publicDir, {
  extensions: ['html'],
  index: 'index.html',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
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

// 创建 HTTP 服务器并初始化 WebSocket
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
║  2. 令牌访问: /admin.html?_key=${accessToken.slice(0,8)}...
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

module.exports = app;
