/**
 * 极风工作室 - Turnstile 验证码封装
 * 干净的实现，无混淆，无密钥硬编码
 */
(function() {
  'use strict';

  const SITE_KEY = window.__turnstileSiteKey || '';
  const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js';

  let widgetId = null;
  let token = null;
  let ready = false;
  let loadCallbacks = [];

  function loadScript(callback) {
    if (ready) {
      if (callback) callback();
      return;
    }
    if (callback) loadCallbacks.push(callback);

    if (document.querySelector('script[src*="turnstile/v0/api.js"]')) return;

    const script = document.createElement('script');
    script.src = SCRIPT_URL;
    script.async = true;
    script.defer = true;
    script.onload = function() {
      ready = true;
      loadCallbacks.forEach(function(cb) { cb(); });
      loadCallbacks = [];
    };
    script.onerror = function() {
      console.error('[Turnstile] 脚本加载失败');
    };
    document.head.appendChild(script);
  }

  function render(containerId, callback) {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error('[Turnstile] 容器不存在:', containerId);
      return;
    }
    if (!SITE_KEY) {
      console.warn('[Turnstile] Site Key 未配置');
      return;
    }

    loadScript(function() {
      if (!window.turnstile) {
        console.error('[Turnstile] API 不可用');
        return;
      }
      if (widgetId) {
        window.turnstile.remove(widgetId);
      }
      widgetId = window.turnstile.render('#' + containerId, {
        sitekey: SITE_KEY,
        theme: 'dark',
        size: 'normal',
        callback: function(t) {
          token = t;
          if (callback) callback(t);
        },
        'error-callback': function(err) {
          console.error('[Turnstile] 验证错误:', err);
          token = null;
        },
        'expired-callback': function() {
          token = null;
        }
      });
    });
  }

  function getToken() {
    return token;
  }

  function reset() {
    token = null;
    if (widgetId && window.turnstile) {
      window.turnstile.reset(widgetId);
    }
  }

  function remove() {
    token = null;
    if (widgetId && window.turnstile) {
      window.turnstile.remove(widgetId);
      widgetId = null;
    }
  }

  window.JifengTurnstile = {
    render: render,
    getToken: getToken,
    reset: reset,
    remove: remove,
    isReady: function() { return ready; }
  };
})();
