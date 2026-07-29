/**
 * Jifeng UI Toolkit - Clean Rewrite
 * Animations and utilities only. No secrets. No obfuscation.
 */

(function () {
  'use strict';

  // ---- Toast styles (injected once) ----
  (function injectToastStyles() {
    if (document.getElementById('jifeng-toast-style')) return;
    const style = document.createElement('style');
    style.id = 'jifeng-toast-style';
    style.textContent = `
      .toast { position: fixed; top: 24px; right: 24px; padding: 14px 20px; border-radius: 8px;
        background: rgba(15,23,42,0.95); color: #e2e8f0; font-size: 14px; display: flex;
        align-items: center; gap: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        border: 1px solid rgba(56,189,248,0.2); transform: translateX(120%);
        transition: transform 0.35s cubic-bezier(0.22,1,0.36,1); z-index: 99999; }
      .toast.show { transform: translateX(0); }
      .toast-success { border-color: rgba(34,197,94,0.4); }
      .toast-error   { border-color: rgba(239,68,68,0.4); }
      .toast-warning { border-color: rgba(234,179,8,0.4); }
      .toast-icon { font-size: 16px; }
    `;
    document.head.appendChild(style);
  })();

  // ---- 3D Tilt Effect ----
  function initTilt() {
    const cards = document.querySelectorAll('.tilt-card');
    cards.forEach(card => {
      card.addEventListener('mousemove', e => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const cx = rect.width / 2;
        const cy = rect.height / 2;
        const rx = ((y - cy) / cy) * -8;
        const ry = ((x - cx) / cx) * 8;
        card.style.transform = 'perspective(800px) rotateX(' + rx + 'deg) rotateY(' + ry + 'deg) scale3d(1.02,1.02,1.02)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(800px) rotateX(0) rotateY(0) scale3d(1,1,1)';
      });
    });
  }

  // ---- Magnetic Buttons ----
  function initMagnetic() {
    const buttons = document.querySelectorAll('.magnetic-btn');
    buttons.forEach(btn => {
      btn.addEventListener('mousemove', e => {
        const rect = btn.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        btn.style.transform = 'translate(' + (x * 0.25) + 'px, ' + (y * 0.25) + 'px)';
      });
      btn.addEventListener('mouseleave', () => {
        btn.style.transform = 'translate(0,0)';
      });
    });
  }

  // ---- Mouse-follow Glow ----
  function initGlow() {
    const glows = document.querySelectorAll('.mouse-glow');
    if (!glows.length) return;
    document.addEventListener('mousemove', e => {
      glows.forEach(g => {
        const rect = g.getBoundingClientRect();
        g.style.setProperty('--gx', (e.clientX - rect.left) + 'px');
        g.style.setProperty('--gy', (e.clientY - rect.top) + 'px');
      });
    });
  }

  // ---- Particle Stream (Canvas) ----
  function initParticles() {
    const canvases = document.querySelectorAll('.particle-canvas');
    canvases.forEach(canvas => {
      const ctx = canvas.getContext('2d');
      let particles = [];
      let w, h, raf;

      function resize() {
        w = canvas.width = canvas.offsetWidth;
        h = canvas.height = canvas.offsetHeight;
      }
      resize();
      window.addEventListener('resize', resize);

      function createParticle() {
        return {
          x: Math.random() * w,
          y: h + Math.random() * 20,
          size: Math.random() * 2 + 1,
          speed: Math.random() * 1 + 0.5,
          opacity: Math.random() * 0.5 + 0.2
        };
      }

      for (let i = 0; i < 40; i++) particles.push(createParticle());

      function draw() {
        ctx.clearRect(0, 0, w, h);
        particles.forEach((p, i) => {
          p.y -= p.speed;
          if (p.y < -10) particles[i] = createParticle();
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(56,189,248,' + p.opacity + ')';
          ctx.fill();
        });
        raf = requestAnimationFrame(draw);
      }
      draw();

      // cleanup observer
      const obs = new IntersectionObserver(entries => {
        entries.forEach(en => {
          if (en.isIntersecting && !raf) draw();
          else if (!en.isIntersecting && raf) { cancelAnimationFrame(raf); raf = null; }
        });
      });
      obs.observe(canvas);
    });
  }

  // ---- Scroll Reveal ----
  function initReveal() {
    const items = document.querySelectorAll('.reveal');
    if (!items.length) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    items.forEach(item => obs.observe(item));
  }

  // ---- Navbar Scroll Effect ----
  function initNavbar() {
    const nav = document.querySelector('.navbar');
    if (!nav) return;
    window.addEventListener('scroll', () => {
      if (window.scrollY > 20) nav.classList.add('scrolled');
      else nav.classList.remove('scrolled');
    });
  }

  // ---- Smooth Scroll for Anchor Links ----
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(a => {
      a.addEventListener('click', e => {
        const id = a.getAttribute('href');
        if (id === '#') return;
        const target = document.querySelector(id);
        if (target) {
          e.preventDefault();
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });
  }

  // ---- Mobile Menu Toggle ----
  function initMobileMenu() {
    const toggle = document.querySelector('.menu-toggle');
    const menu = document.querySelector('.nav-menu');
    if (!toggle || !menu) return;
    toggle.addEventListener('click', () => {
      menu.classList.toggle('open');
      toggle.classList.toggle('active');
    });
  }

  // ---- Number Counter Animation ----
  function initCounters() {
    const counters = document.querySelectorAll('.counter');
    if (!counters.length) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const el = entry.target;
        const target = parseInt(el.dataset.target || '0', 10);
        const duration = parseInt(el.dataset.duration || '1500', 10);
        const start = performance.now();
        function update(now) {
          const p = Math.min((now - start) / duration, 1);
          const ease = 1 - Math.pow(1 - p, 3);
          el.textContent = Math.floor(ease * target).toLocaleString();
          if (p < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
        obs.unobserve(el);
      });
    }, { threshold: 0.5 });
    counters.forEach(c => obs.observe(c));
  }

  // ---- Dark Mode Toggle (if present) ----
  function initDarkMode() {
    const btn = document.getElementById('dark-mode-toggle');
    if (!btn) return;
    const saved = localStorage.getItem('theme');
    if (saved === 'dark') document.documentElement.classList.add('dark');
    btn.addEventListener('click', () => {
      document.documentElement.classList.toggle('dark');
      localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
    });
  }

  // ---- Initialize All ----
  function init() {
    initTilt();
    initMagnetic();
    initGlow();
    initParticles();
    initReveal();
    initNavbar();
    initSmoothScroll();
    initMobileMenu();
    initCounters();
    initDarkMode();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
