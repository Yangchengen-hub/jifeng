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
      if (meta) meta.setAttribute('content', theme === 'dark' ? '#06060c' : '#f0f2f8');
      document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: theme } }));
    },
    get: function() {
      return document.documentElement.getAttribute('data-theme') || 'dark';
    }
  };

  // === 动态背景 ===
  var Background = {
    init: function() {
      if (document.body.querySelector('.bg-layer')) return;
      var layer = document.createElement('div');
      layer.className = 'bg-layer';
      layer.innerHTML =
        '<div class="bg-gradient"></div>' +
        '<div class="bg-orb"></div>' +
        '<div class="bg-orb"></div>' +
        '<div class="bg-orb"></div>';
      document.body.insertBefore(layer, document.body.firstChild);
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
      if (/Android \\d/.test(ua)) return 'android';
      if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
      if (/Linux/.test(ua)) return 'linux';
      return 'other';
    },
    supportsGlass: function() {
      var test = document.createElement('div');
      return ('backdropFilter' in test.style) || ('webkitBackdropFilter' in test.style);
    }
  };

  // === 安全检测（轻量版，不再误伤合法用户）===
  var Security = {
    init: function() {
      // 只屏蔽右键菜单和常用快捷键，不检测自动化工具
      this.blockShortcuts();
    },
    blockShortcuts: function() {
      document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
      document.addEventListener('keydown', function(e) {
        if (e.key === 'F12') { e.preventDefault(); return; }
        if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
          e.preventDefault();
        }
        if (e.ctrlKey && (e.key === 'U' || e.key === 'u')) { e.preventDefault(); }
        if (e.ctrlKey && (e.key === 'S' || e.key === 's')) { e.preventDefault(); }
      });
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
      this.addBotMessage('\u4f60\u597d\uff0c\u6211\u662f\u6781\u98ce\u5de5\u4f5c\u5ba4AI\u52a9\u624b\u3002\u6211\u53ef\u4ee5\u4e3a\u4f60\u4ecb\u7ecd\u6211\u4eec\u7684\u5de5\u4f5c\u5ba4\u6587\u5316\u3001JFToolbox\u548cJifengEnvDetect\u7684\u4f7f\u7528\u65b9\u6cd5\u3002\u8bf7\u7528\u4e2d\u6587\u5411\u6211\u63d0\u95ee\u3002');
    },
    buildWidget: function() {
      var widget = document.createElement('div');
      widget.className = 'ai-widget';
      widget.innerHTML =
        '<button class="ai-toggle" aria-label="\u6253\u5f00AI\u5bf9\u8bdd">' +
          '<span class="ai-icon" aria-hidden="true">' +
            '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>' +
          '</span>' +
        '</button>' +
        '<div class="ai-panel glass-strong" role="dialog" aria-label="\u6781\u98ceAI\u52a9\u624b">' +
          '<div class="ai-header">' +
            '<div class="ai-title">' +
              '<div class="ai-avatar">' +
                '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>' +
              '</div>' +
              '\u6781\u98ceAI\u52a9\u624b' +
            '</div>' +
            '<button class="ai-close" aria-label="\u5173\u95ed">\u2715</button>' +
          '</div>' +
          '<div class="ai-messages" aria-live="polite"></div>' +
          '<form class="ai-input" onsubmit="return false">' +
            '<input type="text" placeholder="\u8bf7\u8f93\u5165\u4e2d\u6587\u95ee\u9898..." maxlength="200" autocomplete="off" spellcheck="false">' +
            '<button type="submit" aria-label="\u53d1\u9001">' +
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
    validateInput: function(text) {
      // 放宽验证：只要包含至少一个中文字符即可
      if (!text || text.trim().length === 0) return false;
      var chineseRegex = /[\u4e00-\u9fff]/;
      return chineseRegex.test(text);
    },
    sendMessage: function() {
      var text = this.input.value.trim();
      if (!text) return;

      if (!this.validateInput(text)) {
        this.addUserMessage(text);
        var typingEl = this.showTyping();
        var self = this;
        setTimeout(function() {
          self.removeTyping(typingEl);
          self.addBotMessage('\u8bf7\u7528\u4e2d\u6587\u63d0\u95ee\u54e6~\u6211\u53ea\u80fd\u56de\u7b54\u5173\u4e8e\u6781\u98ce\u5de5\u4f5c\u5ba4\u6587\u5316\u548c\u4ea7\u54c1\u4f7f\u7528\u7684\u95ee\u9898\u3002');
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

      var studioKeywords = ['\u5de5\u4f5c\u5ba4', '\u56e2\u961f', '\u6587\u5316', '\u7406\u5ff5', '\u4ecb\u7ecd', '\u4f60\u4eec', '\u6781\u98ce'];
      var productKeywords = {
        'jftoolbox': ['\u5de5\u5177\u7bb1', 'jftoolbox', '\u5237\u673a', 'otg', 'adb', '\u5206\u533a'],
        'jifengenvdetect': ['\u73af\u5883\u68c0\u6d4b', 'jifengenvdetect', 'root', '\u5b89\u5168', '\u68c0\u6d4b', 'safetynet']
      };

      var isStudio = studioKeywords.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });
      var isJFToolbox = productKeywords.jftoolbox.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });
      var isJED = productKeywords.jifengenvdetect.some(function(k) { return t.indexOf(k.toLowerCase()) !== -1; });

      if (isJFToolbox) {
        var answers = [
          'JFToolbox\u662f\u6781\u98ce\u5de5\u5177\u7bb1\uff0c\u4e00\u6b3e\u514dRoot\u7684OTG\u5168\u80fd\u5237\u673a/\u8c03\u8bd5\u5de5\u5177\u7bb1\u3002\u4e3b\u8981\u529f\u80fd\u5305\u62ec\uff1aOTG\u5237\u673a\uff08\u652f\u6301Recovery\u3001Boot\u7b49\u5206\u533a\uff09\u3001ADB\u8c03\u8bd5\uff08\u547d\u4ee4\u6267\u884c\u3001\u6587\u4ef6\u4f20\u8f93\u3001\u65e5\u5fd7\u6293\u53d6\uff09\u3001\u5206\u533a\u7ba1\u7406\uff08\u67e5\u770b\u3001\u5907\u4efd\u3001\u64e6\u9664\u3001\u5237\u5165\u5404\u5206\u533a\uff09\u3001\u65e5\u5fd7\u5206\u6790\uff08\u5b9e\u65f6\u6293\u53d6\u7cfb\u7edf/\u5185\u6838/\u5d29\u6e83\u65e5\u5fd7\uff09\u3001\u8bbe\u5907\u4fe1\u606f\u67e5\u770b\u3001Root\u68c0\u6d4b\u7b49\u3002\u4e0b\u8f7d\u5730\u5740\u5728\u5b98\u7f51\u4ea7\u54c1\u9875\u3002',
          'JFToolbox\u7684\u6838\u5fc3\u7279\u8272\u662f\u514dRoot OTG\u5237\u673a\uff0c\u65e0\u9700Root\u6743\u9650\u5373\u53ef\u901a\u8fc7OTG\u8fde\u63a5\u5237\u5165\u955c\u50cf\u3002\u5b83\u652f\u6301\u5b8c\u6574\u7684ADB Shell\u547d\u4ee4\u3001\u5206\u533a\u7ba1\u7406\u548c\u65e5\u5fd7\u5206\u6790\uff0c\u662f\u5b89\u5353\u53d1\u70e7\u53cb\u7684\u4e13\u4e1a\u5de5\u5177\u3002\u53bb\u5b98\u7f51\u4ea7\u54c1\u9875\u53ef\u4ee5\u627e\u5230\u4e0b\u8f7d\u94fe\u63a5\u3002',
          '\u4f7f\u7528JFToolbox\u5f88\u7b80\u5355\uff1a1.\u624b\u673a\u5f00\u542fUSB\u8c03\u8bd5\u5e76\u8fde\u63a5OTG\uff1b2.\u5b89\u88c5JFToolbox APK\uff1b3.\u6253\u5f00\u5de5\u5177\u9009\u62e9\u9700\u8981\u7684\u529f\u80fd\uff08\u5237\u673a/ADB/\u5206\u533a\u7b49\uff09\uff1b4.\u6309\u7167\u5f15\u5bfc\u64cd\u4f5c\u5373\u53ef\u3002\u6240\u6709\u529f\u80fd\u90fd\u652f\u6301\u514dRoot\u8fd0\u884c\u3002'
        ];
        return answers[Math.floor(Math.random() * answers.length)];
      }

      if (isJED) {
        var jedAnswers = [
          'JifengEnvDetect\u662f\u6781\u98ce\u73af\u5883\u68c0\u6d4b\u5de5\u5177\uff0cAndroid\u73af\u5883\u5b89\u5168\u5ba1\u8ba1\u5de5\u5177\u3002\u63d0\u4f9b7\u5927\u68c0\u6d4b\u63a2\u9488\uff1aRoot\u72b6\u6001\u68c0\u6d4b\uff08su\u3001Magisk\u3001KingRoot\uff09\u3001SafetyNet\u72b6\u6001\u68c0\u6d4b\u3001\u8c03\u8bd5\u72b6\u6001\u68c0\u6d4b\uff08USB\u8c03\u8bd5\u3001ADB\u3001\u5f00\u53d1\u8005\u9009\u9879\uff09\u3001\u7b7e\u540d\u9a8c\u8bc1\u3001\u5b89\u5168\u8865\u4e01\u68c0\u67e5\u3001\u6a21\u62df\u5668\u68c0\u6d4b\u7b49\u3002',
          'JifengEnvDetect\u7684\u7279\u8272\u662f\u5168\u65b9\u4f4d\u5b89\u5168\u5ba1\u8ba1\uff0c\u8986\u76d6Root\u72b6\u6001\u3001SafetyNet\u3001\u8c03\u8bd5\u72b6\u6001\u3001\u7b7e\u540d\u9a8c\u8bc1\u3001\u5b89\u5168\u8865\u4e01\u3001\u6a21\u62df\u56686\u5927\u68c0\u6d4b\u7ef4\u5ea6\u3002\u6253\u5f00APP\u540e\u70b9\u51fb"\u5f00\u59cb\u68c0\u6d4b"\u5373\u53ef\u4e00\u952e\u5b8c\u6210\u6240\u6709\u5b89\u5168\u68c0\u6d4b\u3002',
          '\u4f7f\u7528JifengEnvDetect\uff1a1.\u5b89\u88c5APK\u540e\u6253\u5f00\uff1b2.\u6388\u4e88\u5fc5\u8981\u6743\u9650\uff1b3.\u70b9\u51fb"\u5f00\u59cb\u68c0\u6d4b"\uff1b4.\u67e5\u770b\u68c0\u6d4b\u62a5\u544a\uff0c\u4e86\u89e3\u8bbe\u5907\u5b89\u5168\u72b6\u6001\u3002\u6240\u6709\u68c0\u6d4b\u5747\u5728\u672c\u5730\u5b8c\u6210\uff0c\u4fdd\u62a4\u9690\u79c1\u3002'
        ];
        return jedAnswers[Math.floor(Math.random() * jedAnswers.length)];
      }

      if (isStudio) {
        var studioAnswers = [
          '\u6781\u98ce\u5de5\u4f5c\u5ba4\u662f\u4e00\u4e2a\u4e13\u6ce8\u4e8e\u5b89\u5353\u73a9\u673a\u5de5\u5177\u5f00\u53d1\u7684\u5f00\u6e90\u56e2\u961f\u3002\u6211\u4eec\u7684\u7406\u5ff5\u662f"\u4e3a\u53d1\u70e7\u800c\u751f"\uff0c\u81f4\u529b\u4e8e\u4e3a\u5b89\u5353\u53d1\u70e7\u53cb\u6253\u9020\u4e13\u4e1a\u3001\u6613\u7528\u7684\u5de5\u5177\u3002\u76ee\u524d\u6211\u4eec\u7684\u5f00\u6e90\u9879\u76ee\u5305\u62ecJFToolbox\uff08\u6781\u98ce\u5de5\u5177\u7bb1\uff09\u548cJifengEnvDetect\uff08\u6781\u98ce\u73af\u5883\u68c0\u6d4b\uff09\u3002',
          '\u6781\u98ce\u5de5\u4f5c\u5ba4\u7531\u70ed\u7231\u5b89\u5353\u6280\u672f\u7684\u5f00\u53d1\u8005\u7ec4\u6210\uff0c\u575a\u6301\u5f00\u6e90\u7cbe\u795e\uff0c\u6240\u6709\u9879\u76ee\u5747\u5728GitHub\u4e0a\u5f00\u6e90\u3002\u6211\u4eec\u76f8\u4fe1\u597d\u7684\u5de5\u5177\u5e94\u8be5\u8ba9\u6280\u672f\u66f4\u7eaf\u7cb9\uff0c\u8ba9\u53d1\u70e7\u53cb\u80fd\u66f4\u81ea\u7531\u5730\u63a2\u7d22\u8bbe\u5907\u7684\u6f5c\u529b\u3002',
          '\u6211\u4eec\u7684\u56e2\u961f\u6587\u5316\uff1a\u4e13\u6ce8\u6280\u672f\u3001\u5f00\u6e90\u5171\u4eab\u3001\u7528\u6237\u81f3\u4e0a\u3002\u6bcf\u4e00\u884c\u4ee3\u7801\u90fd\u4e3a\u7528\u6237\u800c\u5199\uff0c\u6bcf\u4e00\u4e2a\u529f\u80fd\u90fd\u7ecf\u8fc7\u53cd\u590d\u6253\u78e8\u3002\u6211\u4eec\u6b22\u8fce\u6240\u6709\u5bf9\u5b89\u5353\u6280\u672f\u611f\u5174\u8da3\u7684\u670b\u53cb\u5173\u6ce8\u548c\u8d21\u732e\u4ee3\u7801\u3002'
        ];
        return studioAnswers[Math.floor(Math.random() * studioAnswers.length)];
      }

      return '\u62b1\u6b49\uff0c\u6211\u53ea\u80fd\u56de\u7b54\u5173\u4e8e\u6781\u98ce\u5de5\u4f5c\u5ba4\u6587\u5316\u80cc\u666f\u3001JFToolbox\uff08\u6781\u98ce\u5de5\u5177\u7bb1\uff09\u548cJifengEnvDetect\uff08\u6781\u98ce\u73af\u5883\u68c0\u6d4b\uff09\u7684\u4f7f\u7528\u65b9\u6cd5\u53ca\u7279\u8272\u3002\u8bf7\u6362\u4e2a\u95ee\u9898\u8bd5\u8bd5\u5426~';
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
          '<div class="modal-icon">\u2696\ufe0f</div>' +
          '<h2>\u514d\u8d23\u58f0\u660e</h2>' +
          '<p>' +
            '\u6b22\u8fce\u8bbf\u95ee\u6781\u98ce\u5de5\u4f5c\u5ba4\u5b98\u7f51\u3002\u5728\u4f7f\u7528\u672c\u7f51\u7ad9\u524d\uff0c\u8bf7\u60a8\u4ed4\u7ec6\u9605\u8bfb\u4ee5\u4e0b\u58f0\u660e\uff1a<br><br>' +
            '1. \u672c\u7f51\u7ad9\u63d0\u4f9b\u7684\u6240\u6709\u5de5\u5177\u548c\u4fe1\u606f\u4ec5\u4f9b\u5b66\u4e60\u7814\u7a76\u4f7f\u7528\uff0c\u4e25\u7981\u7528\u4e8e\u4efb\u4f55\u8fdd\u6cd5\u7528\u9014\u3002<br>' +
            '2. \u7528\u6237\u4e0b\u8f7d\u548c\u4f7f\u7528\u672c\u7ad9\u5de5\u5177\u6240\u4ea7\u751f\u7684\u4e00\u5207\u540e\u679c\uff0c\u7531\u7528\u6237\u81ea\u884c\u627f\u62c5\u3002<br>' +
            '3. \u6781\u98ce\u5de5\u4f5c\u5ba4\u53ca\u76f8\u5173\u8d21\u732e\u8005\u4e0d\u5bf9\u4efb\u4f55\u76f4\u63a5\u6216\u95f4\u63a5\u635f\u5931\u627f\u62c5\u8d23\u4efb\u3002<br>' +
            '4. \u901a\u8fc7\u4f7f\u7528\u672c\u7ad9\u670d\u52a1\uff0c\u5373\u89c6\u4e3a\u60a8\u5df2\u9605\u8bfb\u5e76\u540c\u610f\u672c\u58f0\u660e\u3002' +
          '</p>' +
          '<div class="modal-actions">' +
            '<button class="bt bt-p" id="disclaimer-accept">\u6211\u5df2\u9605\u8bfb\u5e76\u540c\u610f</button>' +
          '</div>' +
        '</div>';
      document.body.appendChild(overlay);
      var self = this;
      document.getElementById('disclaimer-accept').addEventListener('click', function() {
        sessionStorage.setItem('jf-disclaimer-accepted', '1');
        overlay.style.animation = 'fadeIn 0.2s var(--ease) reverse';
        setTimeout(function() { overlay.remove(); }, 200);
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
        toggle.classList.toggle('active');
      });
      menu.querySelectorAll('a').forEach(function(link) {
        link.addEventListener('click', function() {
          menu.classList.remove('open');
          toggle.classList.remove('active');
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
      xhr.onerror = function() { callback(new Error('\u7f51\u7edc\u9519\u8bef')); };
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
      xhr.onerror = function() { callback(new Error('\u7f51\u7edc\u9519\u8bef')); };
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

  // === 滚动渐入 ===
  var Reveal = {
    init: function() {
      var els = document.querySelectorAll('[data-reveal]');
      if (!els.length) return;
      var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
            observer.unobserve(entry.target);
          }
        });
      }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
      els.forEach(function(el) { observer.observe(el); });
    }
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
    Reveal.init();

    if (document.querySelector('.ai-widget-anchor') || document.body.querySelector('.hero, .hr')) {
      AIChat.init();
    }

    if (document.querySelector('.release-item') || document.getElementById('release-list')) {
      var releases = document.getElementById('release-list');
      if (releases) {
        var repo = releases.getAttribute('data-repo');
        if (repo) {
          GitHub.fetchReleases(repo, function(err, data) {
            if (err) { releases.textContent = '\u52a0\u8f7d\u5931\u8d25\uff0c\u8bf7\u5237\u65b0\u91cd\u8bd5'; return; }
            if (!data || !data.length) { releases.textContent = '\u6682\u65e0\u53d1\u5e03\u8bb0\u5f55'; return; }
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
