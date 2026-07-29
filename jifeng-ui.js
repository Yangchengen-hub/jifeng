/**
 * Jifeng UI - 极简兼容版本
 * 只保留基础功能：GitHub API 获取 release、toast 提示
 */

(function() {
  'use strict';

  // ---- Toast ----
  window.toast = function(msg, type) {
    type = type || 'info';
    var existing = document.getElementById('jifeng-toast');
    if (existing) existing.remove();

    var div = document.createElement('div');
    div.id = 'jifeng-toast';
    var colors = {
      info: 'rgba(0,245,255,0.2)',
      success: 'rgba(57,255,20,0.2)',
      warn: 'rgba(255,234,0,0.2)',
      error: 'rgba(255,42,109,0.2)'
    };
    div.style.cssText = 'position:fixed;top:20px;right:20px;padding:12px 18px;border-radius:8px;background:rgba(15,23,42,0.98);color:#e2e8f0;font-size:14px;z-index:99999;border:1px solid ' + (colors[type] || colors.info) + ';box-shadow:0 4px 20px rgba(0,0,0,0.5);max-width:300px;word-break:break-word;';
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(function() {
      if (div.parentNode) div.parentNode.removeChild(div);
    }, 3000);
  };

  // ---- 获取 GitHub Release ----
  window.fetchGitHubRelease = function(repo, onSuccess, onError) {
    var url = 'https://api.github.com/repos/' + repo + '/releases/latest';
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.setRequestHeader('Accept', 'application/vnd.github.v3+json');
    xhr.onreadystatechange = function() {
      if (xhr.readyState !== 4) return;
      if (xhr.status === 200) {
        try { onSuccess(JSON.parse(xhr.responseText)); }
        catch(e) { onError && onError(e); }
      } else if (xhr.status === 403 || xhr.status === 429) {
        onError && onError(new Error('API 频率限制，请稍后再试'));
      } else {
        onError && onError(new Error('获取失败 (HTTP ' + xhr.status + ')'));
      }
    };
    xhr.onerror = function() { onError && onError(new Error('网络请求失败')); };
    xhr.timeout = 15000;
    xhr.ontimeout = function() { onError && onError(new Error('请求超时')); };
    xhr.send();
  };

  // ---- 获取 GitHub Releases 列表 ----
  window.fetchGitHubReleases = function(repo, onSuccess, onError) {
    var url = 'https://api.github.com/repos/' + repo + '/releases?per_page=5';
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.setRequestHeader('Accept', 'application/vnd.github.v3+json');
    xhr.onreadystatechange = function() {
      if (xhr.readyState !== 4) return;
      if (xhr.status === 200) {
        try { onSuccess(JSON.parse(xhr.responseText)); }
        catch(e) { onError && onError(e); }
      } else {
        onError && onError(new Error('获取失败'));
      }
    };
    xhr.onerror = function() { onError && onError(new Error('网络请求失败')); };
    xhr.timeout = 15000;
    xhr.send();
  };

  // ---- 安全下载弹窗 ----
  window.openSecureDownload = function(url, filename) {
    var dm = document.getElementById('dm');
    if (!dm) return window.open(url, '_blank');
    dm.style.display = 'flex';
    var yesBtn = document.getElementById('dmYes');
    var noBtn = document.getElementById('dmNo');
    if (yesBtn) {
      yesBtn.onclick = function() {
        dm.style.display = 'none';
        var a = document.createElement('a');
        a.href = url;
        a.download = filename || '';
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        document.body.appendChild(a);
        a.click();
        setTimeout(function() { a.remove(); }, 100);
      };
    }
    if (noBtn) noBtn.onclick = function() { dm.style.display = 'none'; };
  };

  // ---- 北京时间 ----
  function updateBeijingTime() {
    var el = document.getElementById('ftt');
    if (!el) return;
    var now = new Date();
    var str = now.toLocaleString('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    el.textContent = str;
  }
  updateBeijingTime();
  setInterval(updateBeijingTime, 1000);

  // ---- 导航滚动效果 ----
  window.addEventListener('scroll', function() {
    var nav = document.querySelector('nav');
    if (!nav) return;
    if (window.scrollY > 50) {
      nav.style.background = 'rgba(10,10,15,0.98)';
      nav.style.boxShadow = '0 2px 20px rgba(0,0,0,0.3)';
    } else {
      nav.style.background = 'rgba(10,10,15,0.95)';
      nav.style.boxShadow = 'none';
    }
  });

})();
