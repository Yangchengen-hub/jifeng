/**
 * 极风工作室 - Cloudflare Turnstile 验证码集成
 * 专业级机器人防护，防自动化攻击
 * 
 * 使用方法：
 * 1. 在 https://dash.cloudflare.com/ 获取 Site Key 和 Secret Key
 * 2. 设置环境变量: TURNSTILE_SITE_KEY 和 TURNSTILE_SECRET_KEY
 * 3. 在页面中引入此脚本
 */

(function() {
  'use strict';
  
  // 配置
  const TURNSTILE_SITE_KEY = window.TURNSTILE_SITE_KEY || '';
  const TURNSTILE_SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
  
  // 状态
  let turnstileWidgetId = null;
  let turnstileToken = null;
  let isLoaded = false;
  
  // 加载 Turnstile 脚本
  function loadTurnstile(callback) {
    if (isLoaded) {
      callback && callback();
      return;
    }
    
    const script = document.createElement('script');
    script.src = TURNSTILE_SCRIPT_URL + '?render=explicit';
    script.async = true;
    script.defer = true;
    
    script.onload = function() {
      isLoaded = true;
      callback && callback();
    };
    
    script.onerror = function() {
      console.error('Turnstile 脚本加载失败');
      // 回退到本地验证码
      if (window.loadCaptcha) {
        window.loadCaptcha();
      }
    };
    
    document.head.appendChild(script);
  }
  
  // 渲染 Turnstile 组件
  function renderTurnstile(containerId, callback) {
    if (!window.turnstile) {
      loadTurnstile(function() {
        _renderWidget(containerId, callback);
      });
    } else {
      _renderWidget(containerId, callback);
    }
  }
  
  function _renderWidget(containerId, callback) {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error('Turnstile 容器不存在:', containerId);
      return;
    }
    
    try {
      turnstileWidgetId = turnstile.render('#' + containerId, {
        sitekey: TURNSTILE_SITE_KEY || '0x4AAAAAA', // 测试站点密钥
        theme: 'dark',
        size: 'normal',
        callback: function(token) {
          turnstileToken = token;
          if (callback) {
            callback(token);
          }
        },
        'error-callback': function(error) {
          console.error('Turnstile 验证失败:', error);
          // 回退处理
          if (window.loadCaptcha) {
            window.loadCaptcha();
          }
        },
        'expired-callback': function() {
          turnstileToken = null;
          console.log('Turnstile token 已过期');
        }
      });
    } catch (e) {
      console.error('Turnstile 渲染失败:', e);
    }
  }
  
  // 获取 Token
  function getToken() {
    return turnstileToken;
  }
  
  // 重置
  function reset() {
    if (window.turnstile && turnstileWidgetId) {
      turnstile.reset(turnstileWidgetId);
      turnstileToken = null;
    }
  }
  
  // 移除
  function remove() {
    if (window.turnstile && turnstileWidgetId) {
      turnstile.remove(turnstileWidgetId);
      turnstileWidgetId = null;
      turnstileToken = null;
    }
  }
  
  // 暴露 API
  window.JiFengTurnstile = {
    load: loadTurnstile,
    render: renderTurnstile,
    getToken: getToken,
    reset: reset,
    remove: remove,
    isLoaded: () => isLoaded
  };
  
})();

/**
 * 服务端验证代码 (需要在 Node.js 后端使用)
 * 
 * async function verifyTurnstile(token, ip) {
 *   const fetch = require('node-fetch');
 *   
 *   const formData = new URLSearchParams();
 *   formData.append('secret', process.env.TURNSTILE_SECRET_KEY);
 *   formData.append('response', token);
 *   formData.append('remoteip', ip);
 *   
 *   const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
 *     method: 'POST',
 *     body: formData
 *   });
 *   
 *   const result = await response.json();
 *   return result.success === true;
 * }
 */