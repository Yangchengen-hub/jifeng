const API_BASE = '/api';

async function apiRequest(endpoint, options = {}) {
  const url = API_BASE + endpoint;
  const defaultOptions = {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  const finalOptions = { ...defaultOptions, ...options };
  if (options.body && typeof options.body !== 'string') {
    finalOptions.body = JSON.stringify(options.body);
  }
  
  const res = await fetch(url, finalOptions);
  const data = await res.json();
  
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  
  return data;
}

let loginCaptchaToken = '';

async function loadLoginCaptcha() {
  try {
    const data = await apiRequest('/captcha?purpose=login');
    loginCaptchaToken = data.token;
    const captchaContainer = document.getElementById('loginCaptcha');
    if (captchaContainer) {
      captchaContainer.innerHTML = data.svg;
      captchaContainer.style.cursor = 'pointer';
      captchaContainer.title = '点击刷新验证码';
      captchaContainer.onclick = loadLoginCaptcha;
    }
  } catch (e) {
    console.error('加载验证码失败:', e);
  }
}

async function doLogin() {
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginInput').value;
  const captchaAnswer = document.getElementById('loginCaptchaInput').value;
  const btn = document.getElementById('loginBtn');
  const error = document.getElementById('loginError');

  if (!username || !password) {
    error.textContent = '请输入用户名和密码';
    return;
  }
  if (!captchaAnswer) {
    error.textContent = '请输入验证码';
    return;
  }

  btn.disabled = true;
  btn.textContent = '登录中...';
  error.textContent = '';

  try {
    const result = await apiRequest('/login', {
      method: 'POST',
      body: {
        username,
        password,
        captcha_token: loginCaptchaToken,
        captcha_answer: captchaAnswer
      }
    });

    if (result.success) {
      localStorage.setItem('admin_logged_in', 'true');
      localStorage.setItem('admin_user', JSON.stringify(result.admin));
      showDashboard();
      loadAllData();
      showToast('登录成功', 'success');
    }
  } catch (e) {
    error.textContent = e.message;
    loadLoginCaptcha();
    document.getElementById('loginCaptchaInput').value = '';
  } finally {
    btn.disabled = false;
    btn.textContent = '进入控制台';
  }
}

async function doLogout() {
  try {
    await apiRequest('/logout', { method: 'POST' });
  } catch (e) {}
  localStorage.removeItem('admin_logged_in');
  localStorage.removeItem('admin_user');
  location.reload();
}

function checkLogin() {
  return localStorage.getItem('admin_logged_in') === 'true';
}

async function loadStats(hours = 24) {
  try {
    const data = await apiRequest(`/admin/stats?hours=${hours}`);
    return data;
  } catch (e) {
    console.error('加载统计数据失败:', e);
    return null;
  }
}

async function loadAccessLogs(limit = 50, offset = 0) {
  try {
    const data = await apiRequest(`/admin/logs/access?limit=${limit}&offset=${offset}`);
    return data.logs;
  } catch (e) {
    console.error('加载访问日志失败:', e);
    return [];
  }
}

async function loadSecurityLogs(hours = 24) {
  try {
    const data = await apiRequest(`/admin/logs/security?hours=${hours}`);
    return data;
  } catch (e) {
    console.error('加载安全日志失败:', e);
    return null;
  }
}

async function changePassword(oldPass, newPass) {
  try {
    await apiRequest('/admin/change-password', {
      method: 'POST',
      body: { old_password: oldPass, new_password: newPass }
    });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type} show`;
  const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
  toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${message}</span>`;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}
