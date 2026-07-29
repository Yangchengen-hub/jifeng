/**
 * Admin API Client - Clean Rewrite
 * No obfuscation. No hardcoded secrets. No decryption logic.
 */

const API_BASE = '/api';

async function apiRequest(endpoint, options = {}) {
  const url = API_BASE + endpoint;
  const defaults = {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  };

  const config = { ...defaults, ...options };
  if (options.body && typeof options.body === 'object') {
    config.body = JSON.stringify(options.body);
  }

  try {
    const response = await fetch(url, config);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || 'Request failed: ' + response.status);
    }
    return data;
  } catch (err) {
    console.error('[API] Error:', err.message);
    throw err;
  }
}

let loginCaptchaToken = '';

async function loadLoginCaptcha() {
  try {
    const res = await apiRequest('/auth/captcha');
    loginCaptchaToken = res.token || '';
    const container = document.getElementById('captcha-container');
    if (container && res.svg) {
      container.innerHTML = res.svg;
      container.style.cursor = 'pointer';
      container.title = '点击刷新验证码';
      container.onclick = loadLoginCaptcha;
    }
  } catch (e) {
    console.error('[Captcha] Failed to load:', e);
  }
}

async function doLogin() {
  const username = document.getElementById('login-username')?.value?.trim();
  const password = document.getElementById('login-password')?.value;
  const captcha = document.getElementById('login-captcha')?.value?.trim();
  const statusEl = document.getElementById('login-status');
  const btn = document.getElementById('login-btn');

  if (!username || !password) {
    if (statusEl) statusEl.textContent = '请输入用户名和密码';
    return;
  }
  if (!captcha) {
    if (statusEl) statusEl.textContent = '请输入验证码';
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.textContent = '登录中...';
  }
  if (statusEl) statusEl.textContent = '';

  try {
    const res = await apiRequest('/auth/login', {
      method: 'POST',
      body: { username, password, captcha, captchaToken: loginCaptchaToken }
    });

    if (res.success) {
      localStorage.setItem('admin_token', res.token || '');
      localStorage.setItem('admin_user', JSON.stringify(res.admin || {}));
      showToast('登录成功', 'success');
      setTimeout(() => {
        window.location.href = '/dashboard.html';
      }, 500);
    } else {
      throw new Error(res.message || '登录失败');
    }
  } catch (err) {
    if (statusEl) statusEl.textContent = err.message;
    loadLoginCaptcha();
    const captchaInput = document.getElementById('login-captcha');
    if (captchaInput) captchaInput.value = '';
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '进入控制台';
    }
  }
}

async function doLogout() {
  try {
    await apiRequest('/auth/logout', { method: 'POST' });
  } catch (e) {
    // ignore
  }
  localStorage.removeItem('admin_token');
  localStorage.removeItem('admin_user');
  window.location.href = '/admin.html';
}

function checkLogin() {
  return !!localStorage.getItem('admin_token');
}

function getAuthHeaders() {
  const token = localStorage.getItem('admin_token');
  return token ? { 'Authorization': 'Bearer ' + token } : {};
}

async function loadStats(days = 7) {
  try {
    const res = await apiRequest('/admin/stats?days=' + days, {
      headers: getAuthHeaders()
    });
    return res;
  } catch (e) {
    console.error('[Stats] Error:', e);
    return null;
  }
}

async function loadAccessLogs(page = 1, limit = 20) {
  try {
    const res = await apiRequest('/admin/logs/access?page=' + page + '&limit=' + limit, {
      headers: getAuthHeaders()
    });
    return res.data || [];
  } catch (e) {
    console.error('[AccessLogs] Error:', e);
    return [];
  }
}

async function loadSecurityLogs(page = 1) {
  try {
    const res = await apiRequest('/admin/logs/security?page=' + page, {
      headers: getAuthHeaders()
    });
    return res;
  } catch (e) {
    console.error('[SecurityLogs] Error:', e);
    return null;
  }
}

function showToast(message, type = 'info') {
  const el = document.createElement('div');
  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  el.className = 'toast toast-' + type;
  el.innerHTML = '<span class="toast-icon">' + (icons[type] || 'ℹ') + '</span><span class="toast-message">' + message + '</span>';
  document.body.appendChild(el);

  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

async function changePassword(oldPassword, newPassword) {
  try {
    await apiRequest('/admin/password', {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: { oldPassword, newPassword }
    });
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  }
}
