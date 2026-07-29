(function() {
  'use strict';

  // === 主题管理 ===
  var Theme = {
    init: function() {
      var saved = localStorage.getItem('jf-theme');
      var prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
      var theme = saved || (prefersLight ? 'light' : 'dark');
      this.set(theme, true);

      var self = this;
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(e) {
        if (!localStorage.getItem('jf-theme')) {
          self.set(e.matches ? 'light' : 'dark');
        }
      });

      var toggle = document.getElementById('themeToggle');
      if (toggle) {
        toggle.addEventListener('click', function() {
          var current = document.documentElement.getAttribute('data-theme') || 'dark';
          self.set(current === 'dark' ? 'light' : 'dark');
        });
      }
    },
    set: function(theme, silent) {
      document.documentElement.setAttribute('data-theme', theme);
      if (!silent) localStorage.setItem('jf-theme', theme);
      var toggle = document.getElementById('themeToggle');
      if (toggle) toggle.textContent = theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19';
      var meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', theme === 'dark' ? '#06060a' : '#f0f2f8');
      document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: theme } }));
    },
    get: function() {
      return document.documentElement.getAttribute('data-theme') || 'dark';
    }
  };

  // === 动态背景 ===
  var Background = {
    init: function() {
      var layer = document.createElement('div');
      layer.className = 'bg-layer';
      layer.innerHTML =
        '<div class="bg-gradient"></div>' +
        '<div class="bg-orb"></div>' +
        '<div class="bg-orb"></div>' +
        '<div class="bg-orb"></div>';
      if (!document.body.querySelector('.bg-layer')) {
        document.body.insertBefore(layer, document.body.firstChild);
      }
    }
  };

  // === 设备检测 ===
  var Device = {
    info: {},
    detect: function() {
      var ua = navigator.userAgent;
      var dpr = window.devicePixelRatio || 1;
      var w = window.innerWidth;
      var h = window.innerHeight;

      this.info = {
        isMobile: /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua),
        isTablet: /iPad|tablet|PlayBook/i.test(ua) || (w >= 600 && w <= 1024 && dpr > 1.5),
        isDesktop: !/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua) && w > 1024,
        isWatch: w <= 320,
        browser: this.getBrowser(ua),
        os: this.getOS(ua),
        screen: w + 'x' + h,
        dpr: dpr,
        hasWebGL: !!document.createElement('canvas').getContext('webgl'),
        hasGlass: this.supportsGlass(),
        hasReducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
        touch: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
        language: navigator.language
      };

      document.documentElement.setAttribute('data-device',
        this.info.isWatch ? 'watch' :
        this.info.isMobile ? 'mobile' :
        this.info.isTablet ? 'tablet' : 'desktop');
      document.documentElement.setAttribute('data-browser', this.info.browser);
      document.documentElement.setAttribute('data-os', this.info.os);
      document.documentElement.setAttribute('data-dpr', String(dpr));
    },
    getBrowser: function(ua) {
      if (/Chrome\/\d+/.test(ua) && !/Edg\//.test(ua)) return 'chrome';
      if (/Edg\//.test(ua)) return 'edge';
      if (/Firefox\/\d+/.test(ua)) return 'firefox';
      if (/Safari\/\d+/.test(ua) && !/Chrome/.test(ua)) return 'safari';
      if (/OPR\/|Opera/.test(ua)) return 'opera';
      if (/MSIE |Trident/.test(ua)) return 'ie';
      return 'other';
    },
    getOS: function(ua) {
      if (/Windows NT 10/.test(ua)) return 'win10';
      if (/Windows NT/.test(ua)) return 'win';
      if (/Mac OS X/.test(ua)) return 'macos';
      if (/Android \d/.test(ua)) return 'android';
      if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
      if (/Linux/.test(ua)) return 'linux';
      return 'other';
    },
    supportsGlass: function() {
      var test = document.createElement('div');
      return ('backdropFilter' in test.style) || ('webkitBackdropFilter' in test.style);
    }
  };

  // === 安全检测 ===
  var Security = {
    init: function() {
      this.blockShortcuts();
      this.detectDevTools();
      this.detectAutomation();
      this.injectCanvasFingerprint();
    },
    blockShortcuts: function() {
      document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
      document.addEventListener('keydown', function(e) {
        if (e.key === 'F12') { e.preventDefault(); return; }
        if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
          e.preventDefault();
        }
        if (e.ctrlKey && e.key === 'U' && e.key === 'u') { e.preventDefault(); }
        if (e.ctrlKey && e.key === 'S' && e.key === 's') { e.preventDefault(); }
      });
    },
    detectDevTools: function() {
      var threshold = 160;
      setInterval(function() {
        var widthDiff = window.outerWidth - window.innerWidth;
        var heightDiff = window.outerHeight - window.innerHeight;
        if (widthDiff > threshold || heightDiff > threshold) {
          document.body.style.userSelect = 'none';
        }
      }, 1000);

      var devtools = /./;
      devtools.toString = function() { return 'jifeng-devtools'; };
      setInterval(function() {
        if (devtools.toString() !== 'jifeng-devtools') {
          document.body.style.opacity = '0.4';
        }
      }, 1500);
    },
    detectAutomation: function() {
      var suspicious = [
        '_phantom', '__nightmare', '__selenium_', '__webdriver',
        'domAutomation', '_Selenium_IDE_Recorder', 'callPhantom',
        'callSelenium', 'spawn', 'emit', 'Buffer', 'prefs',
        'domAutomationController', '_Selenium_IDE_Recorder'
      ];
      for (var i = 0; i < suspicious.length; i++) {
        try {
          if (suspicious[i] in window || navigator.webdriver) {
            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#888;font-family:sans-serif;text-align:center;padding:2rem">访问被拒绝<br><small style="color:#555">检测到自动化工具</small></div>';
            return;
          }
        } catch (e) {}
      }

      try {
        var canvas = document.createElement('canvas');
        canvas.style.display = 'none';
        document.body.appendChild(canvas);
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#f0f0f0';
        ctx.fillRect(0, 0, 20, 20);
        ctx.fillStyle = '#00f5ff';
        ctx.fillRect(2, 2, 16, 16);
        ctx.fillStyle = '#7b5cff';
        ctx.fillText('AI', 4, 15);
        var dataUrl = canvas.toDataURL();
        canvas.remove();

        var stored = sessionStorage.getItem('jf-fingerprint');
        if (stored && stored !== dataUrl) {
          document.body.style.opacity = '0.3';
        }
        sessionStorage.setItem('jf-fingerprint', dataUrl);
      } catch (e) {}
    },
    injectCanvasFingerprint: function() {
      try {
        var c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60'; ctx.fillRect(0, 0, 50, 50);
        ctx.fillStyle = '#069'; ctx.fillRect(25, 25, 125, 30);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('JIFENG-SECURE', 2, 2);
        var fp = c.toDataURL();
        sessionStorage.setItem('jf-canvas-fp', fp);
      } catch (e) {}
    }
  };

  // === AI 对话 ===
  var AIChat = {
    panel: null,
    input: null,
    messages: null,
    isOpen: false,
    init: function() {
      this.buildWidget();
      this.bindEvents();
      this.addBotMessage('你好，我是极风工作室AI助手。我可以为你介绍我们的工作室文化、JFToolbox和JifengEnvDetect的使用方法。请用中文向我提问。');
    },
    buildWidget: function() {
      var widget = document.createElement('div');
      widget.className = 'ai-widget';
      widget.innerHTML =
        '<button class="ai-toggle" aria-label="打开AI对话">' +
          '<span class="ai-icon" aria-hidden="true">' +
            '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>' +
          '</span>' +
        '</button>' +
        '<div class="ai-panel glass-strong" role="dialog" aria-label="极风AI助手">' +
          '<div class="ai-header">' +
            '<div class="ai-title">' +
              '<div class="ai-avatar">' +
                '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>' +
              '</div>' +
              '极风AI助手' +
            '</div>' +
            '<button class="ai-close" aria-label="关闭">✕</button>' +
          '</div>' +
          '<div class="ai-messages" aria-live="polite"></div>' +
          '<form class="ai-input" onsubmit="return false">' +
            '<input type="text" placeholder="请输入中文问题..." maxlength="100" autocomplete="off" spellcheck="false">' +
            '<button type="submit" aria-label="发送">' +
              '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>' +
            '</button>' +
          '</form>' +
        '</div>';
      document.body.appendChild(widget);
      this.panel = widget.querySelector('.ai-panel');
      this.input = widget.querySelector('.ai-input input');
      this.messages = widget.querySelector('.ai-messages');
      this.toggleBtn = widget.querySelector('.ai-toggle');
      this.closeBtn = widget.querySelector('.ai-close');
      this.form = widget.querySelector('.ai-input');
    },
    bindEvents: function() {
      var self = this;
      this.toggleBtn.addEventListener('click', function() { self.toggle(); });
      this.closeBtn.addEventListener('click', function() { self.toggle(); });
      this.form.addEventListener('submit', function(e) {
        e.preventDefault();
        self.sendMessage();
      });
    },
    toggle: function() {
      this.isOpen = !this.isOpen;
      this.panel.classList.toggle('open', this.isOpen);
      if (this.isOpen) this.input.focus();
    },
    addBotMessage: function(text) {
      var msg = document.createElement('div');
      msg.className = 'ai-msg bot';
      msg.textContent = text;
      this.messages.appendChild(msg);
      this.scrollToBottom();
    },
    addUserMessage: function(text) {
      var msg = document.createElement('div');
      msg.className = 'ai-msg user';
      msg.textContent = text;
      this.messages.appendChild(msg);
      this.scrollToBottom();
    },
    showTyping: function() {
      var msg = document.createElement('div');
      msg.className = 'ai-msg bot typing';
      msg.innerHTML = '<span></span><span></span><span></span>';
      this.messages.appendChild(msg);
      this.scrollToBottom();
      return msg;
    },
    removeTyping: function(el) { if (el && el.parentNode) el.remove(); },
    scrollToBottom: function() {
      this.messages.scrollTop = this.messages.scrollHeight;
    },
    validateChinese: function(text) {
      if (!text || text.trim().length === 0) return false;
      var chineseRegex = /[\u4e00-\u9fff]/;
      var hasChinese = chineseRegex.test(text);
      var cleanText = text.replace(/[\u4e00-\u9fff]/g, '').trim();
      var allowedExtra = /^[a-zA-Z0-9\s，。！？、：；""''（）《》\-—…·]*$/;
      if (!hasChinese) return false;
      if (cleanText.length > 5) return false;
      if (!allowedExtra.test(cleanText)) return false;
      return true;
    },
    sendMessage: function() {
      var text = this.input.value.trim();
      if (!text) return;

      if (!this.validateChinese(text)) {
        this.addUserMessage(text);
        var typingEl = this.showTyping();
        var self = this;
        setTimeout(function() {
          self.removeTyping(typingEl);
          self.addBotMessage('请用中文提问哦～我只能回答关于极风工作室文化和产品使用的问题。');
        }, 600);
        this.input.value = '';
        return;
      }

      this.addUserMessage(text);
      this.input.value = '';

      var typingEl = this.showTyping();
      var response = this.getResponse(text);
      var self = this;

      setTimeout(function() {
        self.removeTyping(typingEl);
        self.addBotMessage(response);
      }, 800 + Math.random() * 600);
    },
    getResponse: function(text) {
      var t = text.toLowerCase();

      var studioKeywords = ['工作室', '团队', '文化', '理念', '介绍', '你们', '团队', '极风'];
      var productKeywords = {
        'jftoolbox': ['工具箱', 'JFToolbox', '刷机', 'OTG', 'ADB', '分区'],
        'jifengenvdetect': ['环境检测', 'JifengEnvDetect', 'Root', '安全', '检测', 'SafetyNet']
      };
      var generalKeywords = ['使用', '怎么', '如何', '下载', '安装', '特色', '功能', '优点', '特点'];

      var isStudio = studioKeywords.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });
      var isJFToolbox = productKeywords.jftoolbox.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });
      var isJED = productKeywords.jifengenvdetect.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });

      if (isJFToolbox) {
        var answers = [
          'JFToolbox是极风工具箱，一款免Root的OTG全能刷机/调试工具箱。主要功能包括：OTG刷机（支持Recovery、Boot等分区）、ADB调试（命令执行、文件传输、日志抓取）、分区管理（查看、备份、擦除、刷入各分区）、日志分析（实时抓取系统/内核/崩溃日志）、设备信息查看、Root检测等。下载地址在官网产品页。',
          'JFToolbox的核心特色是免Root OTG刷机，无需Root权限即可通过OTG连接刷入镜像。它支持完整的ADB Shell命令、分区管理和日志分析，是安卓发烧友的专业工具。去官网产品页可以找到下载链接。',
          '使用JFToolbox很简单：1.手机开启USB调试并连接OTG；2.安装JFToolbox APK；3.打开工具选择需要的功能（刷机/ADB/分区等）；4.按照引导操作即可。所有功能都支持免Root运行。'
        ];
        return answers[Math.floor(Math.random() * answers.length)];
      }

      if (isJED) {
        var jedAnswers = [
          'JifengEnvDetect是极风环境检测工具，Android环境安全审计工具。提供7大检测探针：Root状态检测（su、Magisk、KingRoot）、SafetyNet状态检测、调试状态检测（USB调试、ADB、开发者选项）、签名验证、安全补丁检查、模拟器检测等。',
          'JifengEnvDetect的特色是全方位安全审计，覆盖Root状态、SafetyNet、调试状态、签名验证、安全补丁、模拟器6大检测维度。打开APP后点击"开始检测"即可一键完成所有安全检测。',
          '使用JifengEnvDetect：1.安装APK后打开；2.授予必要权限；3.点击"开始检测"；4.查看检测报告，了解设备安全状态。所有检测均在本地完成，保护隐私。'
        ];
        return jedAnswers[Math.floor(Math.random() * jedAnswers.length)];
      }

      if (isStudio) {
        var studioAnswers = [
          '极风工作室是一个专注于安卓玩机工具开发的开源团队。我们的理念是"为发烧而生"，致力于为安卓发烧友打造专业、易用的工具。目前我们的开源项目包括JFToolbox（极风工具箱）和JifengEnvDetect（极风环境检测）。',
          '极风工作室由热爱安卓技术的开发者组成，坚持开源精神，所有项目均在GitHub上开源。我们相信好的工具应该让技术更纯粹，让发烧友能更自由地探索设备的潜力。',
          '我们的团队文化：专注技术、开源共享、用户至上。每一行代码都为用户而写，每一个功能都经过反复打磨。我们欢迎所有对安卓技术感兴趣的朋友关注和贡献代码。'
        ];
        return studioAnswers[Math.floor(Math.random() * studioAnswers.length)];
      }

      return '抱歉，我只能回答关于极风工作室文化背景、JFToolbox（极风工具箱）和JifengEnvDetect（极风环境检测）的使用方法及特色。请换个问题试试吧～';
    }
  };

  // === 免责声明 ===
  var Disclaimer = {
    init: function() {
      if (sessionStorage.getItem('jf-disclaimer-accepted')) return;
      this.show();
    },
    show: function() {
      var overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.id = 'disclaimer-modal';
      overlay.innerHTML =
        '<div class="modal-content glass-strong">' +
          '<div class="modal-icon">⚖️</div>' +
          '<h2>免责声明</h2>' +
          '<p>' +
            '欢迎访问极风工作室官网。在使用本网站前，请您仔细阅读以下声明：<br><br>' +
            '1. 本网站提供的所有工具和信息仅供学习研究使用，严禁用于任何违法用途。<br>' +
            '2. 用户下载和使用本站工具所产生的一切后果，由用户自行承担。<br>' +
            '3. 极风工作室及相关贡献者不对任何直接或间接损失承担责任。<br>' +
            '4. 通过使用本站服务，即视为您已阅读并同意本声明。' +
          '</p>' +
          '<div class="modal-actions">' +
            '<button class="bt bt-primary" id="disclaimer-accept">我已阅读并同意</button>' +
          '</div>' +
        '</div>';
      document.body.appendChild(overlay);
      var self = this;
      document.getElementById('disclaimer-accept').addEventListener('click', function() {
        sessionStorage.setItem('jf-disclaimer-accepted', '1');
        overlay.remove();
      });
    }
  };

  // === 导航 ===
  var Nav = {
    init: function() {
      this.initMobileToggle();
      this.initScrollEffect();
      this.markActive();
    },
    initMobileToggle: function() {
      var toggle = document.getElementById('navToggle');
      var menu = document.querySelector('.nl');
      if (!toggle || !menu) return;
      toggle.addEventListener('click', function() {
        menu.classList.toggle('open');
      });
      menu.querySelectorAll('a').forEach(function(link) {
        link.addEventListener('click', function() {
          menu.classList.remove('open');
        });
      });
    },
    initScrollEffect: function() {
      var nav = document.querySelector('nav');
      if (!nav) return;
      var onScroll = function() {
        if (window.scrollY > 20) {
          nav.classList.add('nav-glass');
        } else {
          nav.classList.remove('nav-glass');
        }
      };
      window.addEventListener('scroll', onScroll, { passive: true });
      onScroll();
    },
    markActive: function() {
      var path = location.pathname.split('/').pop() || 'index.html';
      document.querySelectorAll('.nl a').forEach(function(a) {
        var href = a.getAttribute('href');
        if (href === path) a.classList.add('active');
      });
    }
  };

  // === GitHub API ===
  var GitHub = {
    cache: {},
    fetch: function(repo, callback) {
      if (this.cache[repo]) {
        callback(null, this.cache[repo]);
        return;
      }
      var xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://api.github.com/repos/' + repo, true);
      xhr.setRequestHeader('Accept', 'application/vnd.github+json');
      xhr.onload = function() {
        if (xhr.status === 200) {
          try {
            var data = JSON.parse(xhr.responseText);
            GitHub.cache[repo] = data;
            callback(null, data);
          } catch (e) { callback(e); }
        } else {
          callback(new Error('GitHub API: ' + xhr.status));
        }
      };
      xhr.onerror = function() { callback(new Error('网络错误')); };
      xhr.timeout = 10000;
      xhr.send();
    },
    fetchReleases: function(repo, callback) {
      var url = 'https://api.github.com/repos/' + repo + '/releases?per_page=5';
      var xhr = new XMLHttpRequest();
      xhr.open('GET', url, true);
      xhr.setRequestHeader('Accept', 'application/vnd.github+json');
      xhr.onload = function() {
        if (xhr.status === 200) {
          try { callback(null, JSON.parse(xhr.responseText)); }
          catch (e) { callback(e); }
        } else { callback(new Error('HTTP ' + xhr.status)); }
      };
      xhr.onerror = function() { callback(new Error('网络错误')); };
      xhr.send();
    },
    fmtStars: function(n) { return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n); }
  };

  // === 北京时间 ===
  var Clock = {
    init: function() {
      var el = document.getElementById('ftt');
      if (!el) return;
      var update = function() {
        el.textContent = new Date().toLocaleString('zh-CN', {
          timeZone: 'Asia/Shanghai',
          year: 'numeric', month: '2-digit', day: '2-digit',
          hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
      };
      update();
      setInterval(update, 1000);
    }
  };

  // === Toast ===
  window.toast = function(msg, type) {
    type = type || 'info';
    var existing = document.getElementById('jf-toast');
    if (existing) existing.remove();

    var el = document.createElement('div');
    el.id = 'jf-toast';
    el.className = 'toast-fix';
    var colors = {
      info: 'rgba(0,245,255,0.2)',
      success: 'rgba(57,255,20,0.2)',
      warn: 'rgba(255,234,0,0.2)',
      error: 'rgba(255,42,109,0.2)'
    };
    el.style.background = 'var(--glass-bg)';
    el.style.borderColor = colors[type] || colors.info;
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(function() { if (el.parentNode) el.remove(); }, 3000);
  };

  // === 数据绑定 ===
  var Data = {
    init: function() {
      var repoEls = document.querySelectorAll('[data-repo]');
      repoEls.forEach(function(el) {
        var repo = el.getAttribute('data-repo');
        var type = el.getAttribute('data-type');
        GitHub.fetch(repo, function(err, data) {
          if (err) return;
          if (type === 'stars') {
            var target = document.querySelector('[data-stars="' + repo + '"]');
            if (target && data.stargazers_count) target.textContent = GitHub.fmtStars(data.stargazers_count);
          }
          if (type === 'version') {
            var target = document.querySelector('[data-version="' + repo + '"]');
            if (target && data['latest_release'] && data['latest_release'].tag_name) {
              target.textContent = data['latest_release'].tag_name.replace(/^v/, '');
            }
          }
        });
      });
    }
  };

  // === 启动 ===
  document.addEventListener('DOMContentLoaded', function() {
    Background.init();
    Device.detect();
    Theme.init();
    Security.init();
    Nav.init();
    Clock.init();
    Data.init();

    if (document.querySelector('.ai-widget-anchor') || document.body.querySelector('.hero')) {
      AIChat.init();
    }

    if (document.querySelector('.release-item') || document.getElementById('release-list')) {
      var releases = document.getElementById('release-list');
      if (releases) {
        var repo = releases.getAttribute('data-repo');
        if (repo) {
          GitHub.fetchReleases(repo, function(err, data) {
            if (err) { releases.textContent = '加载失败，请刷新重试'; return; }
            if (!data || !data.length) { releases.textContent = '暂无发布记录'; return; }
            var html = '';
            data.slice(0, 5).forEach(function(rel) {
              var date = rel.published_at ? new Date(rel.published_at).toLocaleDateString('zh-CN') : '--';
              var body = (rel.body || '').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
              html += '<div class="release-item glass">';
              html += '<div class="release-header">';
              html += '<span class="release-tag">' + rel.tag_name + '</span>';
              html += '<span class="release-date">' + date + '</span>';
              html += '</div>';
              html += '<div class="release-body">' + body + '</div>';
              if (rel.assets && rel.assets.length) {
                html += '<div class="release-assets">';
                rel.assets.forEach(function(a) {
                  html += '<a href="' + a.browser_download_url + '" target="_blank" rel="noopener" class="release-asset">' + a.name + '</a>';
                });
                html += '</div>';
              }
              html += '</div>';
            });
            releases.innerHTML = html;
          });
        }
      }
    }

    if (!sessionStorage.getItem('jf-disclaimer-accepted')) {
      setTimeout(function() { Disclaimer.init(); }, 500);
    }
  });

})();
