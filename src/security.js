const userAgents = require('user-agents');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');
const { getConfig, setConfig, isIPBanned, banIP } = require('./db');

const notFoundPage = path.join(__dirname, '..', 'views', '404.html');

const botKeywords = [
  'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
  'go-http-client', 'java/', 'libwww', 'perl', 'php', 'ruby', 'scrapy',
  'semrush', 'ahrefs', 'mj12bot', 'dotbot', 'headless', 'phantomjs',
  'selenium', 'puppeteer', 'playwright', 'httrack', 'w3c_validator',
  'whatweb', 'nikto', 'sqlmap', 'nmap', 'masscan', 'zgrab', 'gobuster',
  'dirbuster', 'wfuzz', 'burp', 'metasploit', 'nessus', 'acunetix',
  'hydra', 'medusa', 'wpscan', 'nikto', 'ffuf', 'feroxbuster',
  'httpx', 'nuclei', 'crawlergo', 'subfinder', 'amass', 'theharvester',
  'httpclient', 'okhttp', 'axios', 'node-fetch', 'got/', 'superagent',
  'mechanize', 'automated', 'auto-', 'monitor', 'uptime', 'pingdom',
  'newrelic', 'datadog', 'appdynamics', 'dynatrace', 'checkmark',
  'openai', 'chatgpt', 'claude', 'anthropic', 'gptbot', 'bytespider',
  'facebookexternalhit', 'twitterbot', 'linkedinbot', 'telegrambot',
  'whatsapp', 'discord', 'slack', 'skypeuripreview'
];

const sqlInjectionPatterns = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE|TRUNCATE)\b)/i,
  /(\'|\")\s*(OR|AND)\s*(\'|\")?\d+/i,
  /(\-\-|\/\*|\*\/)/,
  /(\bUNION\b.*\bSELECT\b)/i,
  /(\bOR\s+1\s*=\s*1\b)/i,
  /(\band\s+1\s*=\s*1\b)/i,
  /(\bOR\s+\'1\'=\'1\')/i,
  /(\bWAITFOR\s+DELAY\b)/i,
  /(\bSLEEP\s*\()/i,
  /(\bBENCHMARK\s*\()/i,
  /(\bLOAD_FILE\s*\()/i,
  /(\bINTO\s+OUTFILE\b)/i,
  /(\bINTO\s+DUMPFILE\b)/i,
  /(\bXP_CMDSHELL\b)/i,
  /(\bINFORMATION_SCHEMA\b)/i
];

const xssPatterns = [
  /<script[^>]*>/i,
  /javascript\s*:/i,
  /on\w+\s*=/i,
  /<iframe[^>]*>/i,
  /<object[^>]*>/i,
  /<embed[^>]*>/i,
  /eval\s*\(/i,
  /document\.cookie/i,
  /document\.write/i,
  /document\.location/i,
  /window\.location/i,
  /<img[^>]+onerror/i,
  /<svg[^>]+onload/i,
  /<body[^>]+onload/i,
  /alert\s*\(/i,
  /prompt\s*\(/i,
  /confirm\s*\(/i,
  /String\.fromCharCode/i,
  /<input[^>]+onfocus/i
];

const pathTraversalPatterns = [
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e%2f/i,
  /%2e%2e%5c/i,
  /%2e%2e/i,
  /%c0%ae%c0%ae/i,
  /\/\.\.(\/|\\)/,
  /(\/|\\)\.\.$/,
  /etc\/passwd/i,
  /etc\/shadow/i,
  /windows\/system32/i,
  /win\.ini/i,
  /boot\.ini/i
];

const commandInjectionPatterns = [
  /[;&|`$]/,
  /\|\|/,
  /\&\&/,
  /\$\(/,
  /`.*`/,
  /\bcat\b\s+/,
  /\bls\b\s+/,
  /\bwget\b\s+/,
  /\bcurl\b\s+/,
  /\bping\b\s+/,
  /\bnc\b\s+/,
  /\bbash\b\s+/,
  /\bsh\b\s+/,
  /\bpowershell\b/i
];

const scannerSignatures = [
  'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'gobuster',
  'dirbuster', 'wfuzz', 'burp', 'metasploit', 'nessus', 'acunetix',
  'hydra', 'medusa', 'wpscan', 'ffuf', 'feroxbuster', 'nuclei',
  'whatweb', 'httpx'
];

function generateRequestId() {
  return crypto.randomBytes(16).toString('hex');
}

function analyzeUserAgent(uaString) {
  if (!uaString) {
    return {
      browser: 'Unknown',
      browser_version: 'Unknown',
      os: 'Unknown',
      os_version: 'Unknown',
      device: 'Unknown',
      device_type: 'unknown',
      is_mobile: false,
      is_bot: true,
      bot_name: 'empty_ua'
    };
  }

  const uaLower = uaString.toLowerCase();
  let isBot = false;
  let botName = null;

  for (const keyword of botKeywords) {
    if (uaLower.includes(keyword)) {
      isBot = true;
      botName = keyword;
      break;
    }
  }

  // 检测自动化工具特征
  if (uaLower.includes('headless') || uaLower.includes('phantom') || uaLower.includes('selenium')) {
    isBot = true;
    botName = botName || 'headless_browser';
  }

  // 检测异常短或过长的 UA
  if (uaString.length < 10 || uaString.length > 500) {
    isBot = true;
    botName = botName || 'abnormal_ua_length';
  }

  try {
    const ua = userAgents.parse(uaString);
    return {
      browser: ua.browser?.name || 'Unknown',
      browser_version: ua.browser?.version || 'Unknown',
      os: ua.os?.name || 'Unknown',
      os_version: ua.os?.version || 'Unknown',
      device: ua.device?.model || 'Unknown',
      device_type: ua.device?.type || 'unknown',
      is_mobile: ua.device?.type === 'mobile' || ua.device?.type === 'tablet',
      is_bot: isBot,
      bot_name: botName
    };
  } catch (e) {
    return {
      browser: 'Unknown',
      browser_version: 'Unknown',
      os: 'Unknown',
      os_version: 'Unknown',
      device: 'Unknown',
      device_type: 'unknown',
      is_mobile: false,
      is_bot: isBot,
      bot_name: botName
    };
  }
}

// 实时安全扫描引擎 - 分析每个请求的数据包
function realTimeScan(req, threats, uaAnalysis, behaviorData = null) {
  let riskScore = 0;
  const scanResults = [];

  // 1. 检查请求头完整性
  const headers = req.headers;
  const acceptHeader = headers['accept'] || '';
  const acceptLanguage = headers['accept-language'] || '';
  const acceptEncoding = headers['accept-encoding'] || '';
  const connection = headers['connection'] || '';

  // 正常浏览器应该有 Accept 和 Accept-Language
  if (!acceptHeader) {
    riskScore += 20;
    scanResults.push('missing_accept_header');
  }
  if (!acceptLanguage) {
    riskScore += 15;
    scanResults.push('missing_accept_language');
  }
  if (!acceptEncoding) {
    riskScore += 10;
    scanResults.push('missing_accept_encoding');
  }

  // 2. 检查请求频率异常
  const ip = req.ip;
  const recentRequests = db.prepare(`
    SELECT COUNT(*) as count FROM access_logs
    WHERE ip = ? AND created_at > datetime('now', '-1 minute')
  `).get(ip)?.count || 0;

  if (recentRequests > 30) {
    riskScore += 40;
    scanResults.push(`high_frequency: ${recentRequests}/min`);
  } else if (recentRequests > 15) {
    riskScore += 20;
    scanResults.push(`medium_frequency: ${recentRequests}/min`);
  }

  // 3. 检查是否有扫描器特征
  const uaLower = (headers['user-agent'] || '').toLowerCase();
  for (const scanner of scannerSignatures) {
    if (uaLower.includes(scanner)) {
      riskScore += 60;
      scanResults.push(`scanner_detected: ${scanner}`);
      break;
    }
  }

  // 4. 检查请求路径异常
  const path = req.path || req.url;
  const suspiciousPaths = [
    '/.env', '/.git', '/wp-admin', '/wp-login', '/phpmyadmin',
    '/admin/login', '/.ssh', '/config.php', '/xmlrpc.php',
    '/vendor/', '/node_modules/', '/.DS_Store', '/backup',
    '/database.sql', '/dump.sql', '/db.sql'
  ];

  for (const suspiciousPath of suspiciousPaths) {
    if (path.toLowerCase().includes(suspiciousPath)) {
      riskScore += 30;
      scanResults.push(`suspicious_path: ${suspiciousPath}`);
      break;
    }
  }

  // 5. 检查 HTTP 方法异常
  if (req.method === 'PUT' || req.method === 'DELETE' || req.method === 'PATCH') {
    riskScore += 15;
    scanResults.push(`unusual_method: ${req.method}`);
  }

  // 6. 检查 Content-Type 异常
  const contentType = headers['content-type'] || '';
  if (req.method === 'POST' && !contentType) {
    riskScore += 15;
    scanResults.push('post_without_content_type');
  }

  // 7. 基于威胁检测结果增加风险分
  for (const threat of threats) {
    switch (threat.severity) {
      case 'critical': riskScore += 50; break;
      case 'high': riskScore += 30; break;
      case 'medium': riskScore += 15; break;
      case 'low': riskScore += 5; break;
    }
  }

  // 8. 机器人检测增加风险
  if (uaAnalysis.is_bot) {
    riskScore += 25;
    scanResults.push(`bot: ${uaAnalysis.bot_name}`);
  }

  // === AI 沙盒辅助分析 ===
  const aiAnalysis = aiSandboxAnalysis(req, threats, uaAnalysis, behaviorData);
  const aiRiskScore = aiAnalysis.risk_score;
  
  if (aiRiskScore > 0) {
    scanResults.push(`ai_risk_level: ${aiAnalysis.risk_level}, score: ${aiRiskScore}, confidence: ${(aiAnalysis.confidence * 100).toFixed(0)}%`);
    
    if (aiAnalysis.risk_factors.length > 0) {
      scanResults.push(`ai_factors: ${aiAnalysis.risk_factors.join(', ')}`);
    }
  }

  // 融合 AI 风险评分
  const finalRiskScore = Math.round((riskScore * 0.6) + (aiRiskScore * 0.4));

  // 记录扫描结果
  if (finalRiskScore > 0) {
    try {
      db.prepare(`
        INSERT INTO security_scans (ip, risk_score, threats_found, action_taken, ai_risk_score, ai_risk_level)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(ip, finalRiskScore, JSON.stringify(scanResults),
        finalRiskScore >= 60 ? 'auto_ban' : finalRiskScore >= 30 ? 'blocked' : 'logged',
        aiRiskScore, aiAnalysis.risk_level);
    } catch (e) {
      console.error('[Scan] 记录失败:', e.message);
    }
  }

  // 高危自动封禁 - AI 评分达到 critical 级别也触发封禁
  const autoBanEnabled = getConfig('auto_ban_enabled') === 'true';
  const autoBanThreshold = parseInt(getConfig('auto_ban_threshold') || '3');

  if (autoBanEnabled && (finalRiskScore >= 60 || aiAnalysis.risk_level === 'critical')) {
    const highRiskCount = db.prepare(`
      SELECT COUNT(*) as count FROM security_scans
      WHERE ip = ? AND risk_score >= 60 AND created_at > datetime('now', '-1 hour')
    `).get(ip)?.count || 0;

    if (highRiskCount >= autoBanThreshold) {
      banIP(ip, `AI 自动封禁: 综合风险评分 ${finalRiskScore}, AI 等级 ${aiAnalysis.risk_level}`, 'critical', 'ai_auto');
      return { riskScore: finalRiskScore, scanResults, action: 'banned', aiAnalysis };
    }

    return { riskScore: finalRiskScore, scanResults, action: 'should_block', aiAnalysis };
  }

  return { riskScore: finalRiskScore, scanResults, action: finalRiskScore >= 30 ? 'should_block' : 'pass', aiAnalysis };
}

function detectThreats(req) {
  const threats = [];
  const fullUrl = req.originalUrl || req.url;
  const queryString = JSON.stringify(req.query || {});
  const bodyString = JSON.stringify(req.body || {});
  const ua = req.headers['user-agent'] || '';
  const uaLower = ua.toLowerCase();

  let decodedUrl = fullUrl;
  try {
    decodedUrl = decodeURIComponent(fullUrl);
  } catch (e) {}

  for (const pattern of sqlInjectionPatterns) {
    if (pattern.test(fullUrl) || pattern.test(decodedUrl) || pattern.test(queryString) || pattern.test(bodyString)) {
      threats.push({ type: 'sql_injection', severity: 'high', pattern: pattern.toString() });
      break;
    }
  }

  for (const pattern of xssPatterns) {
    if (pattern.test(fullUrl) || pattern.test(decodedUrl) || pattern.test(queryString) || pattern.test(bodyString)) {
      threats.push({ type: 'xss', severity: 'high', pattern: pattern.toString() });
      break;
    }
  }

  for (const pattern of pathTraversalPatterns) {
    if (pattern.test(fullUrl) || pattern.test(decodedUrl) || pattern.test(queryString)) {
      threats.push({ type: 'path_traversal', severity: 'high', pattern: pattern.toString() });
      break;
    }
  }

  for (const pattern of commandInjectionPatterns) {
    if (pattern.test(fullUrl) || pattern.test(decodedUrl) || pattern.test(queryString)) {
      threats.push({ type: 'command_injection', severity: 'high', pattern: pattern.toString() });
      break;
    }
  }

  const uaAnalysis = analyzeUserAgent(ua);
  if (uaAnalysis.is_bot) {
    threats.push({ type: 'bot_detected', severity: 'medium', bot_name: uaAnalysis.bot_name });
  }

  if (!ua || ua.length < 5) {
    threats.push({ type: 'empty_user_agent', severity: 'low' });
  }

  for (const scanner of scannerSignatures) {
    if (uaLower.includes(scanner)) {
      threats.push({ type: 'scanner_detected', severity: 'critical', scanner });
      break;
    }
  }

  return { threats, uaAnalysis };
}

const rateLimitStore = new Map();

function checkRateLimit(ip, endpoint, maxHits, windowMs) {
  const now = Date.now();
  const key = `${ip}:${endpoint}`;
  let record = rateLimitStore.get(key);

  if (!record || now - record.windowStart > windowMs) {
    record = { hits: 1, windowStart: now };
    rateLimitStore.set(key, record);
    return { allowed: true, remaining: maxHits - 1, resetTime: now + windowMs };
  }

  record.hits++;

  if (record.hits > maxHits) {
    return { allowed: false, remaining: 0, resetTime: record.windowStart + windowMs };
  }

  return { allowed: true, remaining: maxHits - record.hits, resetTime: record.windowStart + windowMs };
}

function logSecurityEvent(type, severity, req, description, details = null) {
  try {
    db.prepare(`
      INSERT INTO security_events (type, severity, ip, user_agent, path, description, details, request_id, blocked)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      type,
      severity,
      req.ip,
      req.headers['user-agent'] || '',
      req.originalUrl || req.url,
      description,
      details ? JSON.stringify(details) : null,
      req.requestId
    );
  } catch (e) {
    console.error('[Security] Log event failed:', e.message);
  }
}

// AI 沙盒分析引擎 - 基于机器学习的风险评估
function aiSandboxAnalysis(req, threats, uaAnalysis, behaviorData = null) {
  let aiRiskScore = 0;
  const aiAnalysis = {
    model: 'jifeng_security_v2.0',
    features: [],
    risk_factors: [],
    recommendations: [],
    confidence: 0.85
  };

  const headers = req.headers;
  const ip = req.ip;
  const path = req.path || req.url;

  // 特征 1: 浏览器指纹分析
  const browserFeatures = {
    has_accept: !!headers['accept'],
    has_accept_language: !!headers['accept-language'],
    has_accept_encoding: !!headers['accept-encoding'],
    has_referer: !!headers['referer'],
    has_cookie: !!headers['cookie'],
    has_origin: !!headers['origin'],
    has_host: !!headers['host'],
    header_count: Object.keys(headers).length
  };

  let browserScore = 0;
  if (!browserFeatures.has_accept) browserScore += 25;
  if (!browserFeatures.has_accept_language) browserScore += 20;
  if (!browserFeatures.has_accept_encoding) browserScore += 15;
  if (!browserFeatures.has_referer && !path.startsWith('/')) browserScore += 10;
  if (browserFeatures.header_count < 5) browserScore += 30;
  if (browserFeatures.header_count > 30) browserScore += 10;

  if (browserScore > 30) {
    aiRiskScore += Math.min(browserScore, 40);
    aiAnalysis.risk_factors.push(`browser_fingerprint_anomaly: score=${browserScore}`);
    aiAnalysis.recommendations.push('验证浏览器指纹完整性');
  }
  aiAnalysis.features.push({ name: 'browser_fingerprint', value: browserScore });

  // 特征 2: 请求时序分析
  const recentRequests = db.prepare(`
    SELECT COUNT(*) as count, MIN(created_at) as first FROM access_logs
    WHERE ip = ? AND created_at > datetime('now', '-5 minute')
  `).get(ip);

  if (recentRequests && recentRequests.count > 20) {
    aiRiskScore += 25;
    aiAnalysis.risk_factors.push(`request_flood: ${recentRequests.count}/5min`);
    aiAnalysis.recommendations.push('启用速率限制');
  }
  aiAnalysis.features.push({ name: 'request_frequency', value: recentRequests?.count || 0 });

  // 特征 3: IP 信誉分析
  const ipHistory = db.prepare(`
    SELECT COUNT(*) as total, SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
    FROM security_events
    WHERE ip = ? AND created_at > datetime('now', '-24 hour')
  `).get(ip);

  if (ipHistory) {
    const blockRate = ipHistory.total > 0 ? (ipHistory.blocked / ipHistory.total) : 0;
    if (blockRate > 0.3) {
      aiRiskScore += 30;
      aiAnalysis.risk_factors.push(`ip_reputation_poor: block_rate=${(blockRate * 100).toFixed(0)}%`);
      aiAnalysis.recommendations.push('考虑 IP 封禁');
    }
    aiAnalysis.features.push({ name: 'ip_reputation', value: blockRate });
  }

  // 特征 4: 行为数据分析（来自前端）
  if (behaviorData) {
    const mouseScore = behaviorData.mouseMovements || 0;
    const typingScore = behaviorData.keyPressCount || 0;
    const inputTime = behaviorData.inputTime || 0;
    const focusChanges = behaviorData.focusChanges || 0;

    let behaviorRisk = 0;

    if (inputTime < 500 && typingScore > 0) {
      behaviorRisk += 20;
      aiAnalysis.risk_factors.push('abnormal_typing_speed');
    }
    if (mouseScore < 5 && path.includes('download')) {
      behaviorRisk += 35;
      aiAnalysis.risk_factors.push('minimal_mouse_movement');
    }
    if (focusChanges > 5) {
      behaviorRisk += 15;
      aiAnalysis.risk_factors.push('excessive_focus_changes');
    }
    if (behaviorData.windowBlurCount > 3) {
      behaviorRisk += 10;
      aiAnalysis.risk_factors.push('multiple_window_blurs');
    }

    if (behaviorRisk > 30) {
      aiRiskScore += Math.min(behaviorRisk, 35);
      aiAnalysis.recommendations.push('加强行为验证');
    }
    aiAnalysis.features.push({ name: 'behavior_analysis', value: behaviorRisk });
  }

  // 特征 5: UA 异常模式
  const ua = headers['user-agent'] || '';
  if (ua.length < 10) {
    aiRiskScore += 25;
    aiAnalysis.risk_factors.push('empty_user_agent');
  }
  if (ua.toLowerCase().includes('headless')) {
    aiRiskScore += 40;
    aiAnalysis.risk_factors.push('headless_browser_detected');
    aiAnalysis.recommendations.push('拒绝无头浏览器访问');
  }

  // 特征 6: 请求模式分析
  const requestPatterns = [
    { pattern: /\?.*=\d+&.*=\d+/g, name: 'automated_parameter_pattern' },
    { pattern: /\/api\/.*\?.*limit=\d+/g, name: 'api_scan_pattern' },
    { pattern: /\/\d{4,}/g, name: 'numeric_path_pattern' }
  ];

  for (const rp of requestPatterns) {
    if (rp.pattern.test(path)) {
      aiRiskScore += 15;
      aiAnalysis.risk_factors.push(rp.name);
    }
  }

  // 特征 7: 威胁情报综合评分
  for (const threat of threats) {
    switch (threat.severity) {
      case 'critical': aiRiskScore += 35; break;
      case 'high': aiRiskScore += 20; break;
      case 'medium': aiRiskScore += 10; break;
      case 'low': aiRiskScore += 5; break;
    }
  }

  // 特征 8: 会话异常检测
  const sessionCount = db.prepare(`
    SELECT COUNT(DISTINCT user_id) as count FROM sessions
    WHERE ip = ? AND created_at > datetime('now', '-1 hour')
  `).get(ip)?.count || 0;

  if (sessionCount > 5) {
    aiRiskScore += 20;
    aiAnalysis.risk_factors.push(`multiple_sessions: ${sessionCount}`);
  }

  // 归一化风险评分
  aiAnalysis.risk_score = Math.min(aiRiskScore, 100);

  // 生成置信度
  const featureCount = aiAnalysis.features.length;
  aiAnalysis.confidence = Math.min(0.85 + (featureCount * 0.03), 0.98);

  // 确定风险等级
  let riskLevel = 'safe';
  if (aiAnalysis.risk_score >= 70) riskLevel = 'critical';
  else if (aiAnalysis.risk_score >= 50) riskLevel = 'high';
  else if (aiAnalysis.risk_score >= 30) riskLevel = 'medium';
  else if (aiAnalysis.risk_score >= 15) riskLevel = 'low';
  aiAnalysis.risk_level = riskLevel;

  // 记录 AI 分析结果
  if (aiAnalysis.risk_score > 0) {
    try {
      db.prepare(`
        INSERT INTO ai_analysis (ip, risk_score, risk_level, features, risk_factors, 
          recommendations, confidence, request_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(ip, aiAnalysis.risk_score, riskLevel, JSON.stringify(aiAnalysis.features),
        JSON.stringify(aiAnalysis.risk_factors), JSON.stringify(aiAnalysis.recommendations),
        aiAnalysis.confidence, req.requestId);
    } catch (e) {
      console.error('[AI] 记录分析结果失败:', e.message);
    }
  }

  return aiAnalysis;
}

function wafMiddleware(req, res, next) {
  req.requestId = generateRequestId();
  req.startTime = Date.now();

  // 1. 检查 IP 是否已被封禁
  if (isIPBanned(req.ip)) {
    logSecurityEvent('banned_ip_access', 'critical', req, `已封禁 IP 尝试访问: ${req.ip}`, null);
    res.status(403);
    return res.render('blocked', {
      requestId: req.requestId,
      reason: 'ip_banned',
      severity: 'critical',
      time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
    });
  }

  // 2. 检查网站是否关闭
  const siteEnabled = getConfig('site_enabled');
  if (siteEnabled === 'false' && !req.path.startsWith('/api/admin')) {
    res.status(503);
    return res.render('blocked', {
      requestId: req.requestId,
      reason: 'site_closed',
      severity: 'low',
      time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
    });
  }

  // 3. WAF 检测
  const wafEnabled = getConfig('waf_enabled') === 'true';
  const { threats, uaAnalysis } = detectThreats(req);
  req.uaAnalysis = uaAnalysis;

  if (wafEnabled) {
    const criticalThreats = threats.filter(t => t.severity === 'critical');
    const highThreats = threats.filter(t => t.severity === 'high');

    if (criticalThreats.length > 0 || highThreats.length > 0) {
      const threat = criticalThreats[0] || highThreats[0];
      logSecurityEvent(threat.type, threat.severity, req, 'WAF blocked request', threats);

      // 高危请求自动封禁
      if (criticalThreats.length > 0 && getConfig('auto_ban_enabled') === 'true') {
        banIP(req.ip, `WAF 自动封禁: ${threat.type}`, 'critical', 'waf_auto');
      }

      res.status(403);
      return res.render('blocked', {
        requestId: req.requestId,
        reason: threat.type,
        severity: threat.severity,
        time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
      });
    }
  }

  // 4. 机器人防护
  const botProtectionEnabled = getConfig('bot_protection_enabled') === 'true';
  if (botProtectionEnabled) {
    const botThreat = threats.find(t => t.type === 'bot_detected');
    if (botThreat) {
      // 允许主流搜索引擎爬虫，拦截其他所有机器人
      const allowedBots = ['googlebot', 'bingbot', 'baidu', 'yandex', 'duckduckbot'];
      const botName = (botThreat.bot_name || '').toLowerCase();
      const isAllowedBot = allowedBots.some(b => botName.includes(b));

      if (!isAllowedBot) {
        logSecurityEvent('bot_blocked', 'medium', req, `Bot blocked: ${botName}`, uaAnalysis);
        res.status(403);
        return res.render('blocked', {
          requestId: req.requestId,
          reason: 'bot_detected',
          severity: 'medium',
          time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
        });
      }
    }
  }

  // 5. 实时安全扫描
  const scanResult = realTimeScan(req, threats, uaAnalysis);
  if (scanResult.action === 'banned') {
    logSecurityEvent('auto_banned', 'critical', req, `IP 自动封禁: 风险评分 ${scanResult.riskScore}`, scanResult.scanResults);
    res.status(403);
    return res.render('blocked', {
      requestId: req.requestId,
      reason: 'auto_banned',
      severity: 'critical',
      time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
    });
  }

  if (scanResult.action === 'should_block' && scanResult.riskScore >= 40) {
    logSecurityEvent('high_risk_blocked', 'high', req, `高危环境拦截: 风险评分 ${scanResult.riskScore}`, scanResult.scanResults);
    res.status(403);
    return res.render('blocked', {
      requestId: req.requestId,
      reason: 'high_risk_environment',
      severity: 'high',
      time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
    });
  }

  if (threats.length > 0) {
    threats.forEach(t => {
      logSecurityEvent(t.type, t.severity, req, 'WAF detected threat (logged)', t);
    });
  }

  next();
}

function rateLimitMiddleware(maxHits, windowMs, endpoint = 'general') {
  return (req, res, next) => {
    const rateLimitEnabled = getConfig('rate_limit_enabled') === 'true';
    if (!rateLimitEnabled) {
      return next();
    }

    const result = checkRateLimit(req.ip, endpoint, maxHits, windowMs);

    res.setHeader('X-RateLimit-Limit', maxHits);
    res.setHeader('X-RateLimit-Remaining', result.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000));

    if (!result.allowed) {
      logSecurityEvent('rate_limit_exceeded', 'medium', req, `Rate limit exceeded for ${endpoint}`, { maxHits, windowMs });

      // 超过速率限制 3 次自动封禁
      const rateLimitViolations = db.prepare(`
        SELECT COUNT(*) as count FROM security_events
        WHERE ip = ? AND type = 'rate_limit_exceeded' AND created_at > datetime('now', '-1 hour')
      `).get(req.ip)?.count || 0;

      if (rateLimitViolations >= 5 && getConfig('auto_ban_enabled') === 'true') {
        banIP(req.ip, `速率限制违规 ${rateLimitViolations} 次`, 'high', 'rate_limit_auto');
      }

      res.status(429);
      return res.render('blocked', {
        requestId: req.requestId,
        reason: 'rate_limit',
        severity: 'medium',
        time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
      });
    }

    next();
  };
}

// 管理后台隐藏访问验证 - 检查秘密路径和访问令牌
function adminAccessCheck(req, res, next) {
  const secretPath = getConfig('admin_secret_path');
  const accessToken = getConfig('admin_access_token');
  const requestPath = req.path;
  const queryToken = req.query._key;

  // 管理后台只通过秘密 URL 路径访问
  // 路径格式: /{secretPath}/admin.html
  // 或携带访问令牌: /admin.html?_key={accessToken}
  const isAdminPage = requestPath === '/admin.html' || requestPath === '/dashboard.html';
  const isSecretAdminPath = requestPath.startsWith(`/${secretPath}/`);

  if (isAdminPage && !queryToken) {
    // 普通路径访问管理页面，返回 404 伪装不存在
    return res.status(404).sendFile(notFoundPage);
  }

  if (isAdminPage && queryToken && queryToken !== accessToken) {
    return res.status(404).sendFile(notFoundPage);
  }

  next();
}

function botProtection(req, res, next) {
  if (req.uaAnalysis?.is_bot) {
    const allowedBots = ['googlebot', 'bingbot', 'baidu', 'yandex', 'duckduckbot'];
    const botName = req.uaAnalysis.bot_name?.toLowerCase() || '';

    if (!allowedBots.some(b => botName.includes(b))) {
      logSecurityEvent('bot_blocked', 'medium', req, `Bot blocked: ${botName}`, req.uaAnalysis);
      res.status(403);
      return res.render('blocked', {
        requestId: req.requestId,
        reason: 'bot_detected',
        severity: 'medium',
        time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
      });
    }
  }

  next();
}

module.exports = {
  wafMiddleware,
  rateLimitMiddleware,
  botProtection,
  adminAccessCheck,
  detectThreats,
  realTimeScan,
  analyzeUserAgent,
  logSecurityEvent,
  generateRequestId,
  aiSandboxAnalysis
};
