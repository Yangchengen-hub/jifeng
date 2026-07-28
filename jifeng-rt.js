/* ============================================================
   极风工作室 · 实时同步引擎 v2.0
   Real-time Sync Engine
   —— 官网访客/攻击/Bug 即时推送至管理端
   ============================================================ */
(function (global) {
  'use strict';

  const CHANNEL = 'jifeng_rt_v2';
  const bc = (function () {
    try { return new BroadcastChannel(CHANNEL); } catch (e) { return null; }
  })();

  // 推送一条实时事件（官网调用）
  function emit(type, payload) {
    const msg = { type: type, payload: payload, ts: Date.now(), id: Math.random().toString(36).slice(2) };
    if (bc) bc.postMessage(msg);
    // 同标签页兜底
    global.dispatchEvent(new CustomEvent('jifeng:rt', { detail: msg }));
  }

  // 订阅实时事件（管理端调用）
  function on(handler) {
    if (bc) bc.addEventListener('message', function (e) { handler(e.data); });
    global.addEventListener('jifeng:rt', function (e) { handler(e.detail); });
  }

  global.JifengRT = { emit: emit, on: on, channel: bc };
})(window);
