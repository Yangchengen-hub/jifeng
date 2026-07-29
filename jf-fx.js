/**
 * jf-fx.js — 极风顶级增强层动效驱动
 * 负责：鼠标光晕 / 粒子流 / 3D 倾斜 / 磁吸按钮 / 逐字显现 / 涟漪 / 数字滚动 / 视差
 * 独立 IIFE，不依赖也不修改 jifeng-ui.js，可在任意页面引入。
 * 仅在支持 hover 的桌面端启用，移动端自动降级。
 */
(function () {
  'use strict';

  var isCoarse = window.matchMedia('(hover:none) and (pointer:coarse)').matches;
  var reduceMotion = window.matchMedia('(prefers-reduced-motion:reduce)').matches;

  /* ---------- 1. 鼠标光晕跟随 ---------- */
  function initCursorGlow() {
    var glow = document.getElementById('cursorGlow');
    if (!glow || isCoarse) return;
    document.body.classList.add('cur-on');

    var raf = null, tx = 0, ty = 0, cx = 0, cy = 0;
    function loop() {
      cx += (tx - cx) * 0.18;
      cy += (ty - cy) * 0.18;
      glow.style.left = cx + 'px';
      glow.style.top = cy + 'px';
      if (Math.abs(tx - cx) > 0.5 || Math.abs(ty - cy) > 0.5) {
        raf = requestAnimationFrame(loop);
      } else { raf = null; }
    }
    window.addEventListener('mousemove', function (e) {
      tx = e.clientX; ty = e.clientY;
      if (!raf) raf = requestAnimationFrame(loop);
    }, { passive: true });
    // 进入交互元素时增强光晕
    document.addEventListener('mouseover', function (e) {
      var t = e.target;
      if (t && (t.closest && (t.closest('.bt') || t.closest('.cd') || t.closest('a')))) {
        glow.style.opacity = '1';
        glow.style.transform = 'translate(-50%,-50%) scale(1.25)';
      }
    });
    document.addEventListener('mouseout', function () {
      glow.style.transform = 'translate(-50%,-50%) scale(1)';
    });
  }

  /* ---------- 2. 粒子流 ---------- */
  function initParticles() {
    var box = document.getElementById('particles');
    if (!box || isCoarse || reduceMotion) return;
    var N = 22;
    var frag = document.createDocumentFragment();
    for (var i = 0; i < N; i++) {
      var s = document.createElement('span');
      var dur = 8 + Math.random() * 14;
      var delay = -Math.random() * dur;
      var drift = (Math.random() * 120 - 60) + 'px';
      s.style.left = (Math.random() * 100) + '%';
      s.style.animationDuration = dur + 's';
      s.style.animationDelay = delay + 's';
      s.style.setProperty('--drift', drift);
      var scale = 0.5 + Math.random() * 1.2;
      s.style.transform = 'scale(' + scale + ')';
      frag.appendChild(s);
    }
    box.appendChild(frag);
  }

  /* ---------- 3. 3D 倾斜卡片 ---------- */
  function initTilt() {
    if (isCoarse || reduceMotion) return;
    var nodes = document.querySelectorAll('.tilt');
    if (!nodes.length) return;
    Array.prototype.forEach.call(nodes, function (el) {
      // 注入 inner wrapper（若不存在）
      if (!el.querySelector(':scope > .tilt-inner')) {
        var inner = document.createElement('div');
        inner.className = 'tilt-inner';
        while (el.firstChild) inner.appendChild(el.firstChild);
        el.appendChild(inner);
      }
      var MAX = 12;
      el.addEventListener('mousemove', function (e) {
        var r = el.getBoundingClientRect();
        var px = (e.clientX - r.left) / r.width;
        var py = (e.clientY - r.top) / r.height;
        var rx = (0.5 - py) * MAX;
        var ry = (px - 0.5) * MAX;
        el.style.transform = 'perspective(800px) rotateX(' + rx + 'deg) rotateY(' + ry + 'deg)';
        el.style.setProperty('--mx', (px * 100) + '%');
        el.style.setProperty('--my', (py * 100) + '%');
      });
      el.addEventListener('mouseleave', function () {
        el.style.transform = 'perspective(800px) rotateX(0) rotateY(0)';
      });
    });
  }

  /* ---------- 4. 磁吸按钮 ---------- */
  function initMagnetic() {
    if (isCoarse || reduceMotion) return;
    var nodes = document.querySelectorAll('.bt.magnetic, .magnetic');
    if (!nodes.length) return;
    Array.prototype.forEach.call(nodes, function (el) {
      var STRONG = 18;
      el.addEventListener('mousemove', function (e) {
        var r = el.getBoundingClientRect();
        var cx = r.left + r.width / 2;
        var cy = r.top + r.height / 2;
        var dx = (e.clientX - cx) / r.width * STRONG;
        var dy = (e.clientY - cy) / r.height * STRONG;
        el.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
      });
      el.addEventListener('mouseleave', function () {
        el.style.transform = '';
      });
    });
  }

  /* ---------- 5. 文字逐字显现 ---------- */
  function initSplitText() {
    var nodes = document.querySelectorAll('.split-text');
    if (!nodes.length) return;
    Array.prototype.forEach.call(nodes, function (el) {
      if (el.dataset.splitDone) return;
      var html = el.innerHTML;
      // 仅处理纯文本节点（保留 <br> 与 <span class="ac">）
      var tmp = document.createElement('div');
      tmp.innerHTML = html;
      var out = '';
      function walk(node) {
        node.childNodes.forEach(function (c) {
          if (c.nodeType === 3) {
            var t = c.textContent;
            for (var i = 0; i < t.length; i++) {
              var ch = t[i];
              if (ch === ' ') out += '<span class="ch space"> </span>';
              else if (ch === '\n') out += '<br>';
              else out += '<span class="ch">' + ch + '</span>';
            }
          } else if (c.nodeType === 1) {
            var tag = c.tagName.toLowerCase();
            out += '<' + tag;
            for (var a = 0; a < c.attributes.length; a++) {
              out += ' ' + c.attributes[a].name + '="' + c.attributes[a].value + '"';
            }
            out += '>';
            walk(c);
            out += '</' + tag + '>';
          }
        });
      }
      walk(tmp);
      el.innerHTML = out;
      el.dataset.splitDone = '1';
      // 逐字延迟
      var chs = el.querySelectorAll('.ch');
      for (var i = 0; i < chs.length; i++) {
        chs[i].style.animationDelay = (i * 0.04) + 's';
      }
    });
  }

  /* ---------- 6. 按钮涟漪 ---------- */
  function initRipple() {
    document.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('.bt');
      if (!btn) return;
      var r = btn.getBoundingClientRect();
      var size = Math.max(r.width, r.height);
      var ripple = document.createElement('span');
      ripple.className = 'ripple';
      ripple.style.width = ripple.style.height = size + 'px';
      ripple.style.left = (e.clientX - r.left) + 'px';
      ripple.style.top = (e.clientY - r.top) + 'px';
      // 确保按钮是定位上下文
      if (getComputedStyle(btn).position === 'static') btn.style.position = 'relative';
      btn.appendChild(ripple);
      setTimeout(function () { ripple.remove(); }, 600);
    });
  }

  /* ---------- 7. 数字滚动 ---------- */
  function initCountRoll() {
    var nodes = document.querySelectorAll('.count-roll');
    if (!nodes.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        var el = en.target;
        if (el.dataset.counted) return;
        el.dataset.counted = '1';
        var target = parseFloat(el.getAttribute('data-count') || '0');
        var suffix = el.getAttribute('data-suffix') || '';
        var dur = 1400, start = performance.now();
        function tick(now) {
          var p = Math.min((now - start) / dur, 1);
          var e = 1 - Math.pow(1 - p, 3);
          var val = Math.floor(target * e);
          el.textContent = val.toLocaleString('zh-CN') + suffix;
          if (p < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
        io.unobserve(el);
      });
    }, { threshold: 0.4 });
    Array.prototype.forEach.call(nodes, function (n) { io.observe(n); });
  }

  /* ---------- 8. 滚动揭示带 stagger ---------- */
  function initRevealStagger() {
    var groups = document.querySelectorAll('[data-stagger]');
    Array.prototype.forEach.call(groups, function (g) {
      var items = g.querySelectorAll('.r');
      Array.prototype.forEach.call(items, function (it, i) {
        it.style.setProperty('--i', i);
      });
    });
  }

  /* ---------- 9. Hero 标题霓虹扫光 data-text 注入 ---------- */
  function initHeroSweep() {
    var h1 = document.querySelector('.hc h1 .ac');
    if (h1 && !h1.getAttribute('data-text')) {
      h1.setAttribute('data-text', h1.textContent.trim());
    }
  }

  /* ---------- 10. 自动给关键元素加增强 class ---------- */
  function autoEnhance() {
    if (reduceMotion) return;
    // 产品卡 → 3D 倾斜
    var cards = document.querySelectorAll('.product-card, .feature-item, .cd');
    Array.prototype.forEach.call(cards, function (c) {
      if (!c.classList.contains('tilt')) c.classList.add('tilt');
    });
    // 主按钮 → 磁吸
    var btns = document.querySelectorAll('.bt-p, .hero .bt');
    Array.prototype.forEach.call(btns, function (b) {
      if (!b.classList.contains('magnetic')) b.classList.add('magnetic');
    });
    // Hero 标题 → 逐字显现
    var heroTitle = document.getElementById('heroTitle');
    if (heroTitle && !heroTitle.classList.contains('split-text') && !heroTitle.dataset.splitDone) {
      // 保留原有 <br> 与 <span class="ac">，由 initSplitText 处理
      heroTitle.classList.add('split-text');
    }
  }

  /* ---------- 启动 ---------- */
  function boot() {
    autoEnhance();
    initCursorGlow();
    initParticles();
    initTilt();
    initMagnetic();
    initSplitText();
    initRipple();
    initCountRoll();
    initRevealStagger();
    initHeroSweep();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // 暴露给外部（便于动态加载内容后重新初始化）
  window.jfFX = {
    refresh: boot,
    initTilt: initTilt,
    initSplitText: initSplitText,
    initCountRoll: initCountRoll
  };
})();
