const sec = require('../../lib/security');
function shDate(d){d=d||new Date();return new Date(d.getTime()+8*3600*1000).toISOString().slice(0,10)}
function shHour(d){d=d||new Date();return new Date(d.getTime()+8*3600*1000).toISOString().slice(0,13)}
const db = require('../../lib/db');
const auth = require('../../lib/auth');
const email = require('../../lib/email');
const wa = require('../../lib/webauthn');
const enc = require('../../lib/crypto');
const { setSecurityHeaders } = require('../../lib/api');

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Captcha,X-Fp',
    'Access-Control-Max-Age': '86400',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1;mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Type': 'application/json'
  };
}

function makeRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: '',
    setHeader(k, v) { this.headers[k] = v; },
    end(b) { this.body = b; }
  };
  return res;
}

function makeReq(event) {
  const url = new URL(event.rawUrl || ('http://localhost' + event.path));
  const segs = event.path.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const body = event.body ? (event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString() : event.body) : '{}';
  return {
    method: event.httpMethod,
    url: event.path,
    query: { path: segs },
    headers: event.headers,
    body: body,
    clientIp: event.headers['x-forwarded-for'] || event.headers['client-ip'] || '0.0.0.0'
  };
}

async function parseBody(req) {
  try { return JSON.parse(req.body || '{}'); } catch (e) { return {}; }
}

function json(res, data, status) {
  res.statusCode = status || 200;
  Object.assign(res.headers, corsHeaders());
  res.end(JSON.stringify(data));
}

exports.handler = async function(event, context) {
  const req = makeReq(event);
  const res = makeRes();

  if (req.method === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders(), body: '' };
  }

  req.body = await parseBody(req);
  const segs = req.query.path || [];
  const route = segs.join('/');
  const method = req.method;
  const ip = sec.getClientIp(req);
  req.clientIp = ip;
  const fid = (req.body.fp && req.body.fp.fid) || req.body.fid || req.headers['x-fp'] || (event.queryStringParameters && event.queryStringParameters.fid) || '';

  // Admin exemption - authenticated admins skip all security checks
  let isAdminRequest = false;
  try { isAdminRequest = !!auth.checkAdmin(req); } catch(e) {}

  try {
    // Ban check (skip for admins)
    const banned = isAdminRequest ? null : await sec.isBanned(ip, fid);
    if (banned && !['appeals/submit','commitment/submit','commitment/check','site/status','auth/login','auth/captcha','auth/sendcode','auth/verify','auth/trust','auth/check-trust','auth/wa/status','auth/wa/reg-options','auth/wa/reg-verify','auth/wa/login-options','auth/wa/login-verify'].includes(route)) {
      await sec.logSecurityEvent('blocked', '已封禁IP/设备尝试访问 ' + route, { ip, fid });
      return { statusCode: 403, headers: corsHeaders(), body: JSON.stringify({ ok: false, banned: true, permanent: !!banned.permanent, error: banned.permanent ? '永久限制' : '访问受限', appealUrl: './appeal.html' }) };
    }

    // Rate limit (skip for admins)
    const rl = isAdminRequest ? {limited:false} : await sec.rateLimit(ip + ':' + route, 60, 60000);
    if (rl.limited) {
      const wc = await sec.addWarning(ip, fid, '频率限制');
      if (wc >= 3) {
        await sec.ban(ip, fid, '频率限制3次警告', 'temporary');
        return { statusCode: 403, headers: corsHeaders(), body: JSON.stringify({ ok: false, banned: true, error: '已被临时封禁' }) };
      }
      return { statusCode: 429, headers: corsHeaders(), body: JSON.stringify({ ok: false, warning: true, warningCount: wc, error: '请求过于频繁（警告' + wc + '/3）' }) };
    }

    // Attack detection (skip for admins)
    const attack = isAdminRequest ? null : sec.detectAttack(req);
    if (attack && !['auth/login', 'auth/captcha', 'auth/sendcode', 'auth/verify', 'auth/trust', 'auth/check-trust'].includes(route)) {
      const anomalies = sec.detectAnomaly(req, req.body.fp);
      const reason = attack + (anomalies.length ? ' (' + anomalies.join(',') + ')' : '');
      const wc = await sec.addWarning(ip, fid, reason);
      if (wc >= 3) {
        const isRepeat = await db.get('repeat:' + ip);
        await sec.ban(ip, fid, attack + ' (3次警告)', isRepeat ? 'permanent' : 'temporary');
        if (isRepeat) {
          try { await email.securityAlert({ type: '二次违规永久封禁', message: 'IP: ' + ip, meta: { ip, fid } }); } catch (e) {}
        }
        return { statusCode: 403, headers: corsHeaders(), body: JSON.stringify({ ok: false, banned: true, permanent: !!isRepeat, error: '已被' + (isRepeat ? '永久' : '临时') + '封禁' }) };
      }
      return { statusCode: 403, headers: corsHeaders(), body: JSON.stringify({ ok: false, warning: true, warningCount: wc, warningMax: 3, error: '异常请求（警告' + wc + '/3）' }) };
    }

    // Route handling - inline the catch-all logic
    const result = await handleRoute(route, method, req, res, { ip, fid });
    if (result) return result;

    return { statusCode: res.statusCode, headers: res.headers, body: res.body };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, headers: corsHeaders(), body: JSON.stringify({ ok: false, error: '服务器内部错误' }) };
  }
};

async function handleRoute(route, method, req, res, ctx) {
  const { ip, fid } = ctx;
  const j = (data, status) => ({ statusCode: status || 200, headers: corsHeaders(), body: JSON.stringify(data) });

  // Auto daily report check (poor man's cron - runs on first invocation after report time)
  try {
    const settings = (await db.get('settings')) || {};
    const reportTime = settings.reportTime || '09:00';
    const [rh, rm] = reportTime.split(':').map(Number);
    const now = new Date(Date.now() + 8*3600000); // Shanghai time
    const lastReport = await db.get('lastDailyReport');
    const today = now.toISOString().slice(0,10);
    if (settings.emailAlert !== false && lastReport !== today && (now.getUTCHours() > rh || (now.getUTCHours() === rh && now.getUTCMinutes() >= rm))) {
      await db.set('lastDailyReport', today);
      const visitors = await db.get('stats:visitors:' + today) || 0;
      const attacks = await db.get('stats:attacks:' + today) || 0;
      const activeBans = (await db.lrange('bans:list', 0, -1)).filter(b => b.active).length;
      await email.dailyReport('今日访问: ' + visitors + '\n今日攻击: ' + attacks + '\n当前封禁: ' + activeBans);
    }
  } catch(e) { console.error('Daily report error:', e.message); }

  // auth/login
  if (route === 'auth/login' && method === 'POST') {
    const { username, password } = req.body;
    const AU = process.env.ADMIN_USER || 'NUOYAN';
    const AP = process.env.ADMIN_PASS || 'JIFENG1457';
    if (username !== AU || password !== AP) {
      await sec.logSecurityEvent('auth', '登录失败 - ' + username, { ip });
      const fc = await db.incr('loginfail:' + ip);
      await db.expire('loginfail:' + ip, 1800);
      if (fc >= 5) await sec.ban(ip, '', '暴力破解', 'temporary');
      return j({ ok: false, error: '账号或密码错误' });
    }
    await db.del('loginfail:' + ip);
    return j({ ok: true });
  }

  if (route === 'auth/captcha' && method === 'POST') return j({ ok: true });

  if (route === 'auth/sendcode' && method === 'POST') {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await db.set('emailcode:' + ip, { code, expires: Date.now() + 600000 }, 600);
    const result = await email.verificationCode(code);
    if (!result.ok) return j({ ok: false, error: '邮件发送失败' });
    return j({ ok: true });
  }

  if (route === 'auth/verify' && method === 'POST') {
    const { code } = req.body;
    const stored = await db.get('emailcode:' + ip);
    if (!stored || Date.now() > stored.expires) return j({ ok: false, error: '验证码已过期' });
    if (stored.code !== code) return j({ ok: false, error: '验证码错误' });
    await db.del('emailcode:' + ip);
    const token = auth.sign({ user: process.env.ADMIN_USER || 'NUOYAN', role: 'admin', exp: Date.now() + 86400000 });
    await sec.logSecurityEvent('auth', '管理员登录成功', { ip });
    return j({ ok: true, token });
  }

  if (route === 'auth/check') {
    const payload = auth.checkAdmin(req);
    return j(payload ? { ok: true, user: payload.user } : { ok: false }, payload ? 200 : 401);
  }

  // Trust device - generate long-lived token after full login
  if (route === 'auth/trust' && method === 'POST') {
    const payload = auth.checkAdmin(req);
    if (!payload) return j({ ok: false, error: '未授权' }, 401);
    const { deviceName, fp } = req.body;
    const deviceId = 'dev_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    const deviceToken = auth.sign({ deviceId, role: 'device', exp: Date.now() + 30 * 86400000 });
    const devices = (await db.get('trusted_devices')) || [];
    devices.unshift({
      id: deviceId,
      name: deviceName || '未知设备',
      fp: fp || '',
      ip: enc.maskIP(ip),
      createdAt: Date.now(),
      lastUsed: Date.now(),
      userAgent: (req.headers['user-agent'] || '').substring(0, 100)
    });
    await db.set('trusted_devices', devices.slice(0, 20));
    await sec.logSecurityEvent('auth', '信任设备添加: ' + (deviceName || '未知'), { ip });
    return j({ ok: true, deviceToken, deviceId });
  }

  // Check trusted device token for auto-login
  if (route === 'auth/check-trust' && method === 'POST') {
    const { deviceToken } = req.body;
    if (!deviceToken) return j({ ok: false });
    try {
      const payload = auth.verify(deviceToken);
      if (!payload || payload.role !== 'device') return j({ ok: false });
      const devices = (await db.get('trusted_devices')) || [];
      const device = devices.find(d => d.id === payload.deviceId);
      if (!device) return j({ ok: false });
      device.lastUsed = Date.now();
      device.ip = enc.maskIP(ip);
      await db.set('trusted_devices', devices);
      const adminToken = auth.sign({ user: process.env.ADMIN_USER || 'NUOYAN', role: 'admin', exp: Date.now() + 86400000 });
      return j({ ok: true, token: adminToken, device });
    } catch (e) { return j({ ok: false }); }
  }

  // WebAuthn biometric auth
  if (route === 'auth/wa/status' && method === 'GET') {
    return j({ ok: true, registered: await wa.isRegistered() });
  }
  if (route === 'auth/wa/reg-options' && method === 'POST') {
    if (!auth.checkAdmin(req)) return j({ ok: false, error: '请先登录' }, 401);
    const options = await wa.getRegOptions();
    return j({ ok: true, options });
  }
  if (route === 'auth/wa/reg-verify' && method === 'POST') {
    if (!auth.checkAdmin(req)) return j({ ok: false, error: '请先登录' }, 401);
    const result = await wa.verifyReg(req.body);
    return j(result, result.ok ? 200 : 400);
  }
  if (route === 'auth/wa/login-options' && method === 'GET') {
    const result = await wa.getLoginOptions();
    return j(result, result.ok ? 200 : 400);
  }
  if (route === 'auth/wa/login-verify' && method === 'POST') {
    const result = await wa.verifyLogin(req.body);
    if (result.ok) {
      const adminToken = auth.sign({ user: 'NUOYAN', role: 'admin', wa: true });
      return j({ ok: true, token: adminToken });
    }
    return j(result, 401);
  }

  // visitor
  if (route === 'visitor' && method === 'POST') {
    const { fp: fpData } = req.body;
    if (!fpData || !fpData.fid) return j({ ok: false }, 400);
    await sec.logVisitor(ip, fpData, fpData.page || '/', fpData.ref || '');
    return j({ ok: true });
  }

  if (route === 'visitor/security-event' && method === 'POST') {
    const { type, fp: fpData } = req.body;
    await sec.addWarning(ip, (fpData && fpData.fid) || '', '前端: ' + (type || 'unknown'));
    return j({ ok: true });
  }

  if (route === 'visitor/behavior' && method === 'POST') {
    const { fid: bfid, actions, clicks, scrollDepth } = req.body;
    const visitors = await db.lrange('visitors:recent', 0, 199);
    const hashedFid = bfid ? enc.hashFp(bfid) : '';
    const updated = visitors.map(v => {
      if (hashedFid && v.fid === hashedFid) {
        v.clicks = (v.clicks || 0) + (clicks || 0);
        v.maxScroll = Math.max(v.maxScroll || 0, scrollDepth || 0);
        if (actions && actions.length) v.actions = (v.actions || []).concat(actions).slice(-100);
      }
      return v;
    });
    await db.del('visitors:recent');
    for (let i = updated.length - 1; i >= 0; i--) await db.lpush('visitors:recent', updated[i]);
    return j({ ok: true });
  }

  if (route === 'visitor/session' && method === 'POST') {
    const { fid: sfid, session } = req.body;
    if (!sfid || !session) return j({ ok: true });
    const visitors = await db.lrange('visitors:recent', 0, 199);
    const hashedFid = enc.hashFp(sfid);
    const updated = visitors.map(v => {
      if (v.fid === hashedFid) {
        v.duration = session.duration || 0;
        v.clicks = session.clicks || v.clicks || 0;
        v.maxScroll = session.maxScroll || v.maxScroll || 0;
        if (session.actions && session.actions.length) v.actions = (v.actions || []).concat(session.actions).slice(-100);
      }
      return v;
    });
    await db.del('visitors:recent');
    for (let i = updated.length - 1; i >= 0; i--) await db.lpush('visitors:recent', updated[i]);
    return j({ ok: true });
  }

  // Public site status (maintenance/shutdown/ban check)
  if (route === 'site/status' && method === 'GET') {
    const settings = (await db.get('settings')) || {};
    const mode = settings.siteMode || 'normal';
    const banned = await sec.isBanned(ip, fid);
    const wl = (await db.get('whitelist')) || [];
    const isWhitelisted = wl.some(w => w.ip === ip);
    return j({
      ok: true,
      mode: mode,
      banned: banned && !isWhitelisted ? {
        permanent: !!banned.permanent,
        appealUrl: './appeal.html'
      } : null,
      maintenanceMsg: settings.maintenanceMsg || '网站正在维护中，请稍后再访。',
      shutdownMsg: settings.shutdownMsg || '网站已关停。'
    });
  }

  // announcement
  if (route === 'announcement' && method === 'GET') {
    const list = await db.lrange('announcements:list', 0, 0);
    if (list && list[0]) {
      const a = list[0];
      return j({ ok: true, data: { title: a.title, content: a.content, time: a.time, time_str: new Date(a.time).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) } });
    }
    return j({ ok: true, data: { title: '欢迎访问极风工作室', content: '官网已全面升级，安全体系全面加强。', time: Date.now(), time_str: '刚刚' } });
  }

  // Admin routes - check auth
  const adminRoutes = ['announcement/all', 'announcement/publish', 'announcement/delete', 'stats/overview', 'stats/visitors', 'stats/devices', 'stats/security', 'logs/realtime', 'security/ban', 'security/unban', 'security/unban-ip', 'security/permanent', 'security/warnings', 'security/whitelist', 'security/whitelist/add', 'security/whitelist/remove', 'security/events', 'security/score', 'appeals', 'appeals/handle', 'reports/generate', 'reports/send-daily', 'settings', 'devices', 'devices/revoke', 'data/export', 'admin/site-mode', 'admin/report-time'];
  if (adminRoutes.includes(route)) {
    if (!auth.checkAdmin(req)) return j({ ok: false, error: '未授权' }, 401);
  }

  if (route === 'announcement/all') {
    return j({ ok: true, data: await db.lrange('announcements:list', 0, 49) });
  }

  if (route === 'announcement/publish' && method === 'POST') {
    const { title, content } = req.body;
    if (!title || !content) return j({ ok: false, error: '标题和内容不能为空' });
    await db.lpush('announcements:list', { id: 'ann_' + Date.now().toString(36), title, content, time: Date.now() });
    return j({ ok: true });
  }

  if (route === 'announcement/delete' && method === 'POST') {
    const { id } = req.body;
    const list = await db.lrange('announcements:list', 0, -1);
    const filtered = list.filter(a => a.id !== id);
    await db.del('announcements:list');
    for (let i = filtered.length - 1; i >= 0; i--) await db.lpush('announcements:list', filtered[i]);
    return j({ ok: true });
  }

  if (route === 'stats/overview') {
    const today = shDate();
    const yesterday = shDate(new Date(Date.now() - 86400000));
    const visitors = await db.get('stats:visitors:' + today) || 0;
    const yv = await db.get('stats:visitors:' + yesterday) || 0;
    const attacks = await db.get('stats:attacks:' + today) || 0;
    const bans = (await db.lrange('bans:list', 0, -1)).filter(b => b.active);
    const trend = yv > 0 ? Math.round((visitors - yv) / yv * 100) : (visitors > 0 ? 100 : 0);
    const hours = [], traffic = [];
    for (let i = 23; i >= 0; i--) {
      const d = new Date(Date.now() - i * 3600000);
      const sh = new Date(d.getTime() + 8*3600000);
      hours.push(sh.getUTCHours() + ':00');
      traffic.push(await db.get('stats:visitors:hour:' + shHour(d)) || 0);
    }
    return j({ ok: true, data: { visitors, attacks, bans: bans.length, permBans: bans.filter(b => b.type === 'permanent').length, visitorTrend: trend, trafficLabels: hours, trafficData: [{ data: traffic, color: '#ff6900' }] } });
  }

  if (route === 'stats/visitors') {
    const today = shDate();
    const total = await db.get('stats:visitors:total') || 0;
    const mobile = await db.get('stats:mobile:' + today) || 0;
    const desktop = await db.get('stats:desktop:' + today) || 0;
    const recent = await db.lrange('visitors:recent', 0, 49);
    const pageKeys = await db.keys('stats:page:*');
    const pageStats = [];
    for (const k of pageKeys.slice(0, 10)) {
      pageStats.push({ page: k.replace('stats:page:', ''), count: await db.get(k) || 0 });
    }
    pageStats.sort((a, b) => b.count - a.count);
    return j({ ok: true, data: { total, mobile, desktop, todayNew: await db.get('stats:visitors:' + today) || 0, deviceLabels: ['移动端', '桌面端'], pageLabels: pageStats.map(p => p.page), pageData: pageStats.map(p => p.count), recent } });
  }

  if (route === 'stats/devices') {
    const all = await db.lrange('visitors:recent', 0, 199);
    const groups = {};
    all.forEach(function(v) {
      var key = v.fid || ('ip:' + v.ip);
      if (!groups[key]) {
        groups[key] = {
          fid: v.fid || '',
          ip: v.ip,
          ips: [v.ip],
          brand: v.brand || '',
          model: v.model || '',
          os: v.os || '',
          browser: v.browser || '',
          kernel: v.kernel || '',
          androidVer: v.androidVer || '',
          screen: v.screen || '',
          gpu: v.gpu || '',
          network: v.network || '',
          colorScheme: v.colorScheme || '',
          firstSeen: v.time,
          lastSeen: v.time,
          visits: 0,
          totalDuration: 0,
          totalClicks: 0,
          maxScroll: 0,
          actions: [],
          pages: [],
          warnings: 0,
          banned: false
        };
      }
      var g = groups[key];
      g.visits++;
      g.lastSeen = Math.max(g.lastSeen, v.time);
      g.firstSeen = Math.min(g.firstSeen, v.time);
      if (v.duration) g.totalDuration += v.duration;
      if (v.clicks) g.totalClicks += v.clicks;
      if (v.maxScroll) g.maxScroll = Math.max(g.maxScroll, v.maxScroll);
      if (v.ip && g.ips.indexOf(v.ip) === -1) g.ips.push(v.ip);
      if (v.page && g.pages.indexOf(v.page) === -1) g.pages.push(v.page);
      if (v.actions && v.actions.length) {
        v.actions.forEach(function(a) { g.actions.push(a); });
      }
      // Keep latest device info
      if (v.brand) g.brand = v.brand;
      if (v.model) g.model = v.model;
      if (v.browser) g.browser = v.browser;
    });
    var devices = Object.values(groups).sort(function(a,b){return b.lastSeen - a.lastSeen});
    // Check ban status for each
    for (var d of devices) {
      var banCheck = await sec.isBanned(d.ip, d.fid);
      d.banned = !!banCheck;
      d.permanentBan = !!(banCheck && banCheck.permanent);
    }
    return j({ ok: true, data: devices });
  }

  if (route === 'stats/security') {
    const today = shDate();
    const total = await db.get('stats:attacks:total') || 0;
    const todayCount = await db.get('stats:attacks:' + today) || 0;
    const bans = await db.lrange('bans:list', 0, -1);
    const activeBans = bans.filter(b => b.active);
    const events = await db.lrange('events:list', 0, -1);
    const typeMap = {};
    events.forEach(e => {
      if (e.type === 'warning' && e.meta && e.meta.reason) typeMap[e.meta.reason] = (typeMap[e.meta.reason] || 0) + 1;
      else if (e.meta && e.meta.attack) typeMap[e.meta.attack] = (typeMap[e.meta.attack] || 0) + 1;
    });
    const days = [], trend = [];
    for (let i = 6; i >= 0; i--) {
      const d = shDate(new Date(Date.now() - i * 86400000));
      days.push(d.slice(5));
      trend.push(await db.get('stats:attacks:' + d) || 0);
    }
    const visitors = await db.get('stats:visitors:' + today) || 1;
    return j({ ok: true, data: { total, today: todayCount, banned: activeBans.length, permBanned: activeBans.filter(b => b.type === 'permanent').length, rate: Math.round(todayCount / (todayCount + visitors) * 100) || 0, typeLabels: Object.keys(typeMap), typeData: Object.values(typeMap), trendLabels: days, trendData: trend, bans: bans.slice(0, 50) } });
  }

  if (route === 'logs/realtime') {
    const events = await db.lrange('events:list', 0, 20);
    const typeLabels = { attack: '攻击拦截', ban: '封禁操作', unban: '解封操作', blocked: '拦截访问', auth: '认证事件', warning: '安全警告', appeal: '申诉提交' };
    return j({ ok: true, data: events.map(e => ({ type: e.type === 'ban' || e.type === 'blocked' ? 'ban' : (e.type === 'warning' ? 'attack' : e.type), typeLabel: typeLabels[e.type] || e.type, message: e.message, timeStr: e.timeStr, time: e.time })) });
  }

  if (route === 'security/ban' && method === 'POST') {
    const { ip: banIp, fid: banFid, reason, type } = req.body;
    if (!banIp) return j({ ok: false, error: 'IP不能为空' });
    await sec.ban(banIp, banFid || '', reason || '手动封禁', type || 'temporary');
    return j({ ok: true });
  }

  if (route === 'security/unban' && method === 'POST') {
    await sec.unban(req.body.id);
    return j({ ok: true });
  }

  if (route === 'security/unban-ip' && method === 'POST') {
    const { ip: uip, fid: ufid } = req.body;
    if (uip) await sec.unbanByIp(uip);
    if (ufid) await db.srem('banned:fids', ufid);
    await sec.logSecurityEvent('unban', '管理员解封IP: ' + uip, { ip });
    return j({ ok: true });
  }

  if (route === 'security/permanent' && method === 'POST') {
    const { ip: banIp, fid: banFid, reason } = req.body;
    if (!banIp) return j({ ok: false, error: 'IP不能为空' });
    await sec.ban(banIp, banFid || '', reason || '永久封禁', 'permanent');
    return j({ ok: true });
  }

  if (route === 'security/warnings') {
    const keys = await db.keys('warnings:*');
    const warnings = [];
    for (const k of keys.slice(0, 50)) {
      const w = await db.get(k);
      if (w) warnings.push({ ip: k.replace('warnings:', ''), ...w });
    }
    return j({ ok: true, data: warnings });
  }

  if (route === 'appeals') {
    const list = await db.lrange('appeals:list', 0, -1);
    return j({ ok: true, data: list.filter(a => a.status === 'pending') });
  }

  if (route === 'appeals/submit' && method === 'POST') {
    const { content, fid: appealFid } = req.body;
    if (!content || content.length < 20) return j({ ok: false, error: '申诉内容至少20字' });
    const existing = await db.lrange('appeals:list', 0, -1);
    if (existing.some(a => a.ip === ip && a.status === 'pending')) return j({ ok: false, error: '已有待审核申诉' });
    const bans = await db.lrange('bans:list', 0, -1);
    const br = bans.find(b => b.ip === ip && b.active);
    if (br && br.type === 'permanent') return j({ ok: false, error: '永久封禁不可申诉' });
    await db.lpush('appeals:list', { id: 'appeal_' + Date.now().toString(36), ip, fid: appealFid || '', banReason: br ? br.reason : '未知', content, time: Date.now(), status: 'pending' });
    await sec.logSecurityEvent('appeal', '收到申诉 ' + enc.maskIP(ip), { ip });
    await email.appealNotice({ ip: enc.maskIP(ip), fid: appealFid || '', banReason: br ? br.reason : '未知', content, time: Date.now() });
    return j({ ok: true });
  }

  if (route === 'appeals/handle' && method === 'POST') {
    const { id, action } = req.body;
    const list = await db.lrange('appeals:list', 0, -1);
    const appeal = list.find(a => a.id === id);
    if (!appeal) return j({ ok: false, error: '申诉不存在' });
    if (action === 'approve') {
      appeal.status = 'approved'; appeal.handledAt = Date.now();
      await sec.unbanByIp(appeal.ip);
      await db.set('commitment_pending:' + appeal.ip, true, 86400);
    } else if (action === 'reject') {
      appeal.status = 'rejected'; appeal.handledAt = Date.now();
    } else if (action === 'permanent') {
      appeal.status = 'permanent'; appeal.handledAt = Date.now();
      await sec.ban(appeal.ip, appeal.fid, '申诉后永久封禁', 'permanent');
    }
    const updated = list.map(a => a.id === id ? appeal : a);
    await db.del('appeals:list');
    for (let i = updated.length - 1; i >= 0; i--) await db.lpush('appeals:list', updated[i]);
    return j({ ok: true });
  }

  if (route === 'commitment/check' && method === 'GET') {
    return j({ ok: true, required: !!(await db.get('commitment_pending:' + ip)) });
  }

  if (route === 'commitment/submit' && method === 'POST') {
    const { content: cContent, fid: cFid, name } = req.body;
    if (!(await db.get('commitment_pending:' + ip))) return j({ ok: false, error: '无需提交承诺书' });
    if (!cContent || cContent.length < 10) return j({ ok: false, error: '承诺书内容不完整' });
    await db.lpush('commitments:list', { id: 'commit_' + Date.now().toString(36), ip, fid: cFid || '', name: name || '', content: cContent, time: Date.now() });
    await db.del('commitment_pending:' + ip);
    await db.set('repeat:' + ip, true);
    await sec.resetWarnings(ip);
    await email.commitmentNotice({ ip: enc.maskIP(ip), fid: cFid || '', content: cContent });
    return j({ ok: true });
  }

  if (route === 'reports/generate' && method === 'POST') {
    const { type } = req.body;
    const now = new Date();
    const today = shDate(now);
    let content = '═══════════════════════════════════\n  极风工作室 · 运维报告\n  ' + now.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) + '\n═══════════════════════════════════\n\n';
    const visitors = await db.get('stats:visitors:' + today) || 0;
    const attacks = await db.get('stats:attacks:' + today) || 0;
    const activeBans = (await db.lrange('bans:list', 0, -1)).filter(b => b.active);
    content += '【今日数据】\n  访问: ' + visitors + '\n  攻击: ' + attacks + '\n  封禁: ' + activeBans.length + '\n  永久封禁: ' + activeBans.filter(b => b.type === 'permanent').length + '\n\n';
    if (type === 'attack' || type === 'full') {
      content += '【法律取证建议】\n  依据《网络安全法》第二十一条、第二十七条\n  依据《刑法》第二百八十五条、第二百八十六条\n  保存日志+截图+损失评估，向公安机关网安部门报案\n';
    }
    return j({ ok: true, data: { content } });
  }

  if (route === 'reports/send-daily' && method === 'POST') {
    const today = shDate();
    const visitors = await db.get('stats:visitors:' + today) || 0;
    const attacks = await db.get('stats:attacks:' + today) || 0;
    const activeBans = (await db.lrange('bans:list', 0, -1)).filter(b => b.active).length;
    const result = await email.dailyReport('今日访问: ' + visitors + '\n今日攻击: ' + attacks + '\n当前封禁: ' + activeBans);
    return j({ ok: result.ok, error: result.error });
  }

  if (route === 'settings') {
    if (method === 'GET') return j({ ok: true, data: (await db.get('settings')) || {} });
    if (method === 'POST') {
      const { key, value } = req.body;
      const settings = (await db.get('settings')) || {};
      settings[key] = value;
      await db.set('settings', settings);
      return j({ ok: true });
    }
  }

  // Site mode control (maintenance/shutdown)
  if (route === 'admin/site-mode' && method === 'POST') {
    try {
      const { mode, msg } = req.body;
      if (!['normal', 'maintenance', 'shutdown'].includes(mode)) return j({ ok: false, error: '无效模式' });
      const settings = (await db.get('settings')) || {};
      settings.siteMode = mode;
      if (msg) {
        if (mode === 'maintenance') settings.maintenanceMsg = msg;
        if (mode === 'shutdown') settings.shutdownMsg = msg;
      }
      await db.set('settings', settings);
      await sec.logSecurityEvent('auth', '网站模式切换为: ' + mode, { ip });
      return j({ ok: true });
    } catch(e) {
      return j({ ok: false, error: e.message });
    }
  }

  // Report time setting
  if (route === 'admin/report-time' && method === 'POST') {
    const { time, enabled } = req.body;
    const settings = (await db.get('settings')) || {};
    if (time) settings.reportTime = time;
    if (enabled !== undefined) settings.dailyReport = enabled;
    await db.set('settings', settings);
    return j({ ok: true });
  }

  // Trusted devices management
  if (route === 'devices' && method === 'GET') {
    const devices = (await db.get('trusted_devices')) || [];
    return j({ ok: true, data: devices });
  }

  if (route === 'devices/revoke' && method === 'POST') {
    const { id } = req.body;
    let devices = (await db.get('trusted_devices')) || [];
    devices = devices.filter(d => d.id !== id);
    await db.set('trusted_devices', devices);
    await sec.logSecurityEvent('auth', '信任设备已移除: ' + id, { ip });
    return j({ ok: true });
  }

  // IP Whitelist
  if (route === 'security/whitelist' && method === 'GET') {
    return j({ ok: true, data: (await db.get('whitelist')) || [] });
  }

  if (route === 'security/whitelist/add' && method === 'POST') {
    const { ip: wlIp, note } = req.body;
    if (!wlIp) return j({ ok: false, error: 'IP不能为空' });
    let wl = (await db.get('whitelist')) || [];
    if (!wl.some(w => w.ip === wlIp)) {
      wl.unshift({ ip: wlIp, note: note || '', time: Date.now() });
      await db.set('whitelist', wl);
    }
    return j({ ok: true });
  }

  if (route === 'security/whitelist/remove' && method === 'POST') {
    const { ip: wlIp } = req.body;
    let wl = (await db.get('whitelist')) || [];
    wl = wl.filter(w => w.ip !== wlIp);
    await db.set('whitelist', wl);
    return j({ ok: true });
  }

  // Security events with filtering
  if (route === 'security/events' && method === 'GET') {
    const events = await db.lrange('events:list', 0, 99);
    const type = req.query.type || event.queryStringParameters?.type;
    let filtered = events;
    if (type && type !== 'all') filtered = events.filter(e => e.type === type);
    return j({ ok: true, data: filtered });
  }

  // Security score
  if (route === 'security/score' && method === 'GET') {
    const today = shDate();
    const attacks = await db.get('stats:attacks:' + today) || 0;
    const visitors = await db.get('stats:visitors:' + today) || 0;
    const bans = (await db.lrange('bans:list', 0, -1)).filter(b => b.active).length;
    const settings = (await db.get('settings')) || {};
    let score = 100;
    score -= Math.min(attacks * 2, 30);
    score -= bans > 10 ? 10 : 0;
    if (!settings.antiDebug !== false) score += 0;
    score = Math.max(0, Math.min(100, score));
    const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'D';
    const checks = [
      { name: '反调试保护', status: settings.antiDebug !== false },
      { name: '自动封禁', status: settings.autoBan !== false },
      { name: '邮件告警', status: settings.emailAlert !== false },
      { name: '设备指纹', status: settings.fpTrack !== false },
      { name: '数据加密', status: true },
      { name: 'HTTPS强制', status: true },
      { name: '安全头设置', status: true },
      { name: '频率限制', status: true }
    ];
    return j({ ok: true, data: { score, grade, attacks, visitors, bans, checks } });
  }

  // Data export
  if (route === 'data/export' && method === 'POST') {
    const { type } = req.body;
    let data = {};
    if (type === 'all' || type === 'security') {
      data.events = await db.lrange('events:list', 0, 199);
      data.bans = await db.lrange('bans:list', 0, -1);
      data.warnings = [];
      const wKeys = await db.keys('warnings:*');
      for (const k of wKeys.slice(0, 50)) data.warnings.push({ ip: k, ...(await db.get('warnings:' + k)) });
    }
    if (type === 'all' || type === 'visitors') {
      data.visitors = await db.lrange('visitors:recent', 0, 99);
    }
    if (type === 'all') {
      data.announcements = await db.lrange('announcements:list', 0, -1);
      data.appeals = await db.lrange('appeals:list', 0, -1);
      data.commitments = await db.lrange('commitments:list', 0, -1);
      data.devices = await db.get('trusted_devices') || [];
      data.exportTime = new Date().toISOString();
    }
    return j({ ok: true, data });
  }

  return j({ ok: false, error: 'Not found' }, 404);
}
