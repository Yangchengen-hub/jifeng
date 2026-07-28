const path = require('path');
const fs = require('fs');

// Vercel Serverless 入口 - 加载 Express 应用
// 注意：此文件不能被深度混淆，否则会导致 Vercel 无法正确加载应用

try {
  // 确保 /tmp 目录存在（Vercel 临时文件系统）
  if (process.env.VERCEL) {
    if (!fs.existsSync('/tmp')) {
      fs.mkdirSync('/tmp', { recursive: true });
    }
  }

  // 加载 Express 应用（src/app.js 导出的 app 实例）
  const app = require('../src/app.js');

  // Vercel Serverless 要求导出 app
  module.exports = app;
  
} catch (error) {
  console.error('[Vercel] 应用加载失败:', error.message);
  console.error('[Vercel] 错误堆栈:', error.stack);
  
  // 返回一个基本的错误响应处理器，防止函数完全崩溃
  module.exports = (req, res) => {
    res.status(500).json({
      error: 'INTERNAL_SERVER_ERROR',
      message: '应用加载失败',
      detail: process.env.NODE_ENV === 'development' ? error.message : '请联系管理员',
      requestId: req.headers['x-vercel-id'] || 'unknown'
    });
  };
}
