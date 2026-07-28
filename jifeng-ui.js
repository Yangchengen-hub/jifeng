/* ============================================================
   极风工作室 · 通用 UI 脚本 v2.0
   ============================================================ */
(function () {
  'use strict';

  // 北京时间
  function BT() {
    return new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
  }
  window.BT = BT;

  // 背景光球（每页注入一次）
  function injectOrbs() {
    if (document.querySelector('.bg-orbs')) return;
    const wrap = document.createElement('div');
    wrap.className = 'bg-orbs';
    wrap.innerHTML = '<div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div><div class="orb orb-4"></div>';
    document.body.insertBefore(wrap, document.body.firstChild);
  }

  // 主题切换（跟随系统，用户可手动覆盖）
  function initThemeToggle() {
    if (document.querySelector('.theme-toggle')) return;
    const btn = document.createElement('div');
    btn.className = 'theme-toggle';
    btn.setAttribute('role', 'button');
    btn.setAttribute('aria-label', '切换主题');
    btn.title = '切换亮/暗主题';
    const saved = localStorage.getItem('jifeng_theme');
    function icon() {
      const dark = document.documentElement.getAttribute('data-theme') === 'dark' ||
        (!document.documentElement.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme:dark)').matches);
      btn.textContent = dark ? '\u2600\uFE0F' : '\u{1F319}';
    }
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    icon();
    btn.addEventListener('click', function () {
      const cur = document.documentElement.getAttribute('data-theme');
      const sysDark = window.matchMedia('(prefers-color-scheme:dark)').matches;
      let next;
      if (cur === 'dark') next = 'light';
      else if (cur === 'light') next = 'dark';
      else next = sysDark ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('jifeng_theme', next);
      icon();
    });
    document.body.appendChild(btn);
  }

  // Toast 容器
  function injectToastWrap() {
    if (document.querySelector('#toast-wrap')) return;
    const w = document.createElement('div');
    w.id = 'toast-wrap';
    document.body.appendChild(w);
  }

  // Toast
  window.JifengToast = function (title, body, type) {
    injectToastWrap();
    const wrap = document.getElementById('toast-wrap');
    const t = document.createElement('div');
    t.className = 'toast ' + (type || '');
    t.innerHTML = '<div class="toast-title">' + title + '</div>' + (body ? '<div class="toast-body">' + body + '</div>' : '');
    wrap.appendChild(t);
    setTimeout(function () {
      t.classList.add('out');
      setTimeout(function () { t.remove(); }, 400);
    }, 4500);
  };

  // 滚动入场 + 导航高亮
  function initScrollReveal() {
    const items = document.querySelectorAll('.r');
    if (!items.length) return;
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(function (e) {
        e.forEach(function (x) { if (x.isIntersecting) { x.target.classList.add('v'); io.unobserve(x.target); } });
      }, { threshold: 0.1 });
      items.forEach(function (it) { io.observe(it); });
    } else {
      items.forEach(function (it) { it.classList.add('v'); });
    }
  }

  // 导航滚动样式
  function initNavScroll() {
    const nav = document.querySelector('nav');
    if (!nav) return;
    const onScroll = function () { nav.classList.toggle('s', window.scrollY > 20); };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  // 页脚时间
  function initFooterTime() {
    const el = document.getElementById('ftt');
    if (!el) return;
    const tick = function () { el.textContent = BT().split(' ')[1]; };
    tick();
    setInterval(tick, 1000);
  }

  // 数字滚动动画
  window.JifengCountTo = function (el, target, duration) {
    duration = duration || 800;
    const start = parseInt(el.textContent) || 0;
    const startTime = performance.now();
    function step(now) {
      const p = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(start + (target - start) * eased);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  };

  // 访客记录 + 攻击检测（共享）
  function recordVisitor() {
    const I = { ua: navigator.userAgent, lang: navigator.language, plat: navigator.platform, scr: screen.width + 'x' + screen.height, ref: document.referrer || 'direct', ts: BT(), page: location.pathname };
    const ua = navigator.userAgent.toLowerCase();
    const vpnK = ['vpn', 'proxy', 'shadowsocks', 'v2ray', 'clash', 'trojan', 'wireguard', 'openvpn', 'lantern', 'psiphon'];
    I.isVPN = vpnK.some(function (k) { return ua.includes(k); });
    I.isAcc = I.isVPN;
    let L = JSON.parse(localStorage.getItem('jifeng_vl') || '[]');
    L.unshift(I); if (L.length > 500) L = L.slice(0, 500);
    localStorage.setItem('jifeng_vl', JSON.stringify(L));
    window.__visitorInfo = I;
    // 实时推送：新访客
    if (window.JifengRT) window.JifengRT.emit('visitor', I);
    return I;
  }

  // 攻击检测引擎（共享）
  const AttackEngine = {
    patterns: {
      sql_injection: [/union[\s]+select/i, /drop[\s]+table/i, /delete[\s]+from/i, /insert[\s]+into/i, /';[\s]*--/i, /1[\s]*=[\s]*1[\s]*--/i, /exec[\s]*\(/i, /sleep[\s]*\(/i],
      xss: [/<script/i, /javascript:/i, /onerror[\s]*=/i, /onload[\s]*=/i, /alert[\s]*\(/i, /eval[\s]*\(/i, /<iframe/i, /<object/i, /<embed/i],
      csrf: [/csrf/i, /xsrf/i, /authenticity.token/i, /csrf.token/i],
      path_traversal: [/\.\.\//i, /%2e%2e%2f/i, /etc\/passwd/i, /etc\/shadow/i, /windows\/win\.ini/i, /boot\.ini/i],
      rce: [/python[\s]+-c/i, /curl[\s]+/i, /wget[\s]+/i, /bash[\s]+-c/i, /cmd\.exe/i, /powershell/i, /\|[\s]*sh/i, /\${IFS}/i, /system[\s]*\(/i, /shell_exec[\s]*\(/i],
      lfi: [/file:\/\//i, /php:\/\/filter/i, /zip:\/\//i, /data:\/\/text/i],
      scanner: [/sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i, /gobuster/i, /burp[\s]+suite/i, /owasp[\s]+zap/i, /acunetix/i],
      bot: [/bot\//i, /crawler/i, /spider/i, /scraper/i, /curl\//i, /wget\//i, /python-requests/i, /googlebot/i, /bingbot/i, /baiduspider/i],
      ddos: [/flooding/i, /slowloris/i, /rudy/i, /loic/i, /hoic/i, /hping/i, /sockstress/i],
      brute_force: [/wp-login/i, /admin\/login/i, /login\.php/i, /signin/i, /authenticate/i, /admin\.php/i, /wp-admin/i, /cpanel/i],
      data_exfil: [/base64_decode[\s]*\(/i, /base64_encode[\s]*\(/i, /gzinflate[\s]*\(/i, /extract[\s]*\(/i, /parse_str[\s]*\(/i],
      command_injection: [/;[\s]*cat[\s]+/i, /;[\s]*ls[\s]+/i, /;[\s]*id[\s]*/i, /\|[\s]*cat[\s]+/i, /\|[\s]*ls[\s]+/i, /\|[\s]*id[\s]*/i]
    },
    detectAttack: function (data) {
      const results = [];
      const testStr = (data.ua || '') + ' ' + (data.ref || '') + ' ' + (data.url || '');
      for (const [category, patterns] of Object.entries(this.patterns)) {
        for (const pattern of patterns) {
          if (pattern.test(testStr)) {
            let level = 'medium';
            if (['sql_injection', 'xss', 'rce', 'command_injection', 'path_traversal'].includes(category)) level = 'high';
            else if (['csrf', 'lfi', 'data_exfil'].includes(category)) level = 'medium';
            else level = 'low';
            results.push({ category: category.replace(/_/g, ' ').toUpperCase(), pattern: pattern.toString().slice(0, 50), level: level, timestamp: BT(), data: data });
          }
        }
      }
      return results;
    },
    classifyLevel: function (attacks) {
      const high = attacks.filter(function (a) { return a.level === 'high'; });
      const medium = attacks.filter(function (a) { return a.level === 'medium'; });
      const low = attacks.filter(function (a) { return a.level === 'low'; });
      if (high.length >= 2) return { overall: 'CRITICAL', color: 'var(--err)', score: 100 };
      if (high.length === 1) return { overall: 'HIGH', color: 'var(--err)', score: 85 };
      if (medium.length >= 3) return { overall: 'MEDIUM', color: 'var(--warn)', score: 60 };
      if (medium.length >= 1 || low.length >= 5) return { overall: 'LOW', color: 'var(--info)', score: 30 };
      return { overall: 'SAFE', color: 'var(--ok)', score: 0 };
    }
  };
  window.AttackEngine = AttackEngine;

  // GitHub API（共享，带缓存）
  async function fetchRepo(repo, key) {
    const c = 'gh_' + key, t = c + '_time', ca = localStorage.getItem(c), ct = localStorage.getItem(t);
    if (ca && ct && Date.now() - parseInt(ct) < 300000) return JSON.parse(ca);
    try {
      const r = await fetch('https://api.github.com/repos/' + repo, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
      if (!r.ok) throw new Error();
      const d = await r.json();
      localStorage.setItem(c, JSON.stringify(d)); localStorage.setItem(t, Date.now().toString());
      return d;
    } catch (e) { return ca ? JSON.parse(ca) : null; }
  }
  async function fetchRel(repo, key) {
    const c = 'gh_rel_' + key, t = c + '_time', ca = localStorage.getItem(c), ct = localStorage.getItem(t);
    if (ca && ct && Date.now() - parseInt(ct) < 300000) return ca === 'null' ? null : JSON.parse(ca);
    try {
      const r = await fetch('https://api.github.com/repos/' + repo + '/releases/latest', { headers: { 'Accept': 'application/vnd.github.v3+json' } });
      if (r.status === 404) { localStorage.setItem(c, 'null'); return null; }
      if (!r.ok) throw new Error();
      const d = await r.json();
      localStorage.setItem(c, JSON.stringify(d)); localStorage.setItem(t, Date.now().toString());
      return d;
    } catch (e) { return ca && ca !== 'null' ? JSON.parse(ca) : null; }
  }
  async function fetchReleases(repo, key, per_page) {
    per_page = per_page || 10;
    const c = 'gh_rels_' + key, t = c + '_time', ca = localStorage.getItem(c), ct = localStorage.getItem(t);
    if (ca && ct && Date.now() - parseInt(ct) < 300000) return JSON.parse(ca);
    try {
      const r = await fetch('https://api.github.com/repos/' + repo + '/releases?per_page=' + per_page + '&sort=created', { headers: { 'Accept': 'application/vnd.github.v3+json' } });
      if (!r.ok) throw new Error();
      const d = await r.json();
      localStorage.setItem(c, JSON.stringify(d)); localStorage.setItem(t, Date.now().toString());
      return d;
    } catch (e) { return ca ? JSON.parse(ca) : []; }
  }
  async function fetchIssues(repo, state, per_page) {
    state = state || 'open'; per_page = per_page || 10;
    try {
      const r = await fetch('https://api.github.com/repos/' + repo + '/issues?state=' + state + '&per_page=' + per_page + '&sort=created', { headers: { 'Accept': 'application/vnd.github.v3+json' } });
      if (!r.ok) return [];
      const d = await r.json();
      return d.filter(function (i) { return !i.pull_request; });
    } catch (e) { return []; }
  }
  window.JifengGH = { fetchRepo: fetchRepo, fetchRel: fetchRel, fetchReleases: fetchReleases, fetchIssues: fetchIssues };

  // Bug 反馈同步到 GitHub Issues
  window.JifengReportBug = function () {
    const ty = prompt('类型：1-闪退 2-卡顿 3-刷机失败 4-UI异常 5-网络 6-其他');
    if (!ty) return;
    const T = { 1: '闪退', 2: '卡顿', 3: '刷机失败', 4: 'UI异常', 5: '网络', 6: '其他' };
    const d = prompt('描述：');
    if (!d) return;
    const c = prompt('联系方式（选填）：') || '';
    const R = { id: 'b' + Date.now(), type: T[ty] || '其他', desc: d, contact: c, page: location.pathname, ua: navigator.userAgent, ts: BT(), st: 'pending' };
    let B = JSON.parse(localStorage.getItem('jifeng_br') || '[]');
    B.unshift(R); if (B.length > 50) B = B.slice(0, 50);
    localStorage.setItem('jifeng_br', JSON.stringify(B));
    // 实时推送到管理端
    if (window.JifengRT) window.JifengRT.emit('bug', R);
    if (confirm('已保存！是否同步到GitHub Issues？')) {
      const ti = encodeURIComponent('[Bug] ' + R.type + ': ' + d.slice(0, 50));
      const bo = encodeURIComponent('**类型**: ' + R.type + '\n**描述**: ' + d + '\n**联系方式**: ' + (c || '未提供') + '\n**页面**: ' + location.pathname + '\n**UA**: ' + navigator.userAgent + '\n**时间**: ' + R.ts);
      window.open('https://github.com/Yangchengen-hub/jifeng/issues/new?title=' + ti + '&body=' + bo, '_blank');
    }
  };

  // 安全检测 + 实时推送
  function runSecurityCheck() {
    const attacks = AttackEngine.detectAttack(window.__visitorInfo || {});
    if (attacks.length > 0) {
      const cls = AttackEngine.classifyLevel(attacks);
      if (cls.overall !== 'SAFE') {
        const entry = { ts: BT(), attacks: attacks, cls: cls, page: location.pathname };
        let secLog = JSON.parse(localStorage.getItem('jifeng_sec_log') || '[]');
        secLog.unshift(entry); if (secLog.length > 100) secLog = secLog.slice(0, 100);
        localStorage.setItem('jifeng_sec_log', JSON.stringify(secLog));
        // 实时推送：攻击事件
        if (window.JifengRT) window.JifengRT.emit('attack', entry);
      }
    }
  }

  // 免责弹窗
  function initDisclaimer() {
    const K = 'jifeng_d4';
    if (localStorage.getItem(K)) return;
    const M = document.getElementById('dm');
    if (!M) return;
    M.style.display = 'flex';
    let s = 5;
    const B = document.getElementById('agb'), C = document.getElementById('cd');
    const T = setInterval(function () {
      s--; if (C) C.textContent = s;
      if (s <= 0) { clearInterval(T); B.disabled = false; B.classList.add('e'); B.innerHTML = '我已阅读并同意'; }
    }, 1000);
    B.addEventListener('click', function () { localStorage.setItem(K, '1'); M.style.display = 'none'; });
    const lb = document.getElementById('lb');
    if (lb) lb.addEventListener('click', function () { window.location.href = 'about:blank'; });
  }

  // 客服浮动按钮
  function initFloatBtn() {
    const bb = document.getElementById('bb');
    if (!bb) return;
    bb.addEventListener('click', window.JifengReportBug);
  }

  // Changelog 解析（共享）
  window.JifengShowChangelog = function (id, release) {
    const container = document.getElementById(id + '-changelog');
    const changesDiv = document.getElementById(id + '-changes');
    if (!container || !changesDiv) return;
    let html = '';
    if (release.body) {
      const lines = release.body.split('\n');
      let inChanges = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed.match(/^(##\s*)?(新增|添加|Added|Features|新功能)/i)) { inChanges = true; html += '<div style="margin-top:.5rem"><strong style="color:var(--ok)">&#10011; 新增</strong></div>'; continue; }
        if (trimmed.match(/^(##\s*)?(修复|修正|Fixed|Bug Fixes)/i)) { inChanges = true; html += '<div style="margin-top:.5rem"><strong style="color:var(--warn)">&#128295; 修复</strong></div>'; continue; }
        if (trimmed.match(/^(##\s*)?(删除|移除|Removed|Deleted)/i)) { inChanges = true; html += '<div style="margin-top:.5rem"><strong style="color:var(--err)">&#10006; 移除</strong></div>'; continue; }
        if (trimmed.match(/^(##\s*)?(变更|修改|Changed|改进|优化)/i)) { inChanges = true; html += '<div style="margin-top:.5rem"><strong style="color:var(--info)">&#9998; 变更</strong></div>'; continue; }
        if (trimmed.startsWith('#')) { inChanges = false; continue; }
        if (inChanges && (trimmed.startsWith('-') || trimmed.startsWith('*'))) {
          html += '<div style="padding-left:1rem">&#8226; ' + trimmed.substring(1).trim() + '</div>';
        }
      }
    }
    if (html) { changesDiv.innerHTML = html; container.style.display = 'block'; }
  };

  // 初始化
  function init() {
    injectOrbs();
    injectToastWrap();
    initThemeToggle();
    initScrollReveal();
    initNavScroll();
    initFooterTime();
    initDisclaimer();
    initFloatBtn();
    recordVisitor();
    runSecurityCheck();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
