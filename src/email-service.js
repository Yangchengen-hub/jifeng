/**
 * 极风工作室 - 邮件通知系统
 * 使用 nodemailer 发送邮件
 */

const nodemailer = require('nodemailer');
const db = require('./db');

// 邮件配置
const EMAIL_CONFIG = {
  // SMTP 配置（需要配置真实的 SMTP 服务）
  service: process.env.EMAIL_SERVICE || 'QQ',
  host: process.env.EMAIL_HOST || 'smtp.qq.com',
  port: parseInt(process.env.EMAIL_PORT) || 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER || '', // 发件邮箱
    pass: process.env.EMAIL_PASS || ''  // 授权码
  }
};

// 管理员邮箱（仅从环境变量读取，绝不硬编码 fallback）
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';

// 创建传输器
let transporter = null;

function initTransporter() {
  if (!EMAIL_CONFIG.auth.user || !EMAIL_CONFIG.auth.pass || !ADMIN_EMAIL) {
    console.log('[Email] 邮件服务未配置，请设置 EMAIL_USER / EMAIL_PASS / ADMIN_EMAIL 环境变量');
    return false;
  }
  
  try {
    transporter = nodemailer.createTransport(EMAIL_CONFIG);
    console.log('[Email] 邮件服务初始化成功');
    return true;
  } catch (e) {
    console.error('[Email] 邮件服务初始化失败:', e.message);
    return false;
  }
}

// 发送邮件
async function sendMail(to, subject, html, text = null) {
  if (!transporter) {
    const initialized = initTransporter();
    if (!initialized) {
      console.log('[Email] 邮件服务未配置，跳过发送');
      return { success: false, reason: 'not_configured' };
    }
  }
  
  try {
    const info = await transporter.sendMail({
      from: `"极风工作室安全中心" <${EMAIL_CONFIG.auth.user}>`,
      to,
      subject,
      text: text || subject,
      html
    });
    
    console.log('[Email] 邮件发送成功:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (e) {
    console.error('[Email] 邮件发送失败:', e.message);
    return { success: false, error: e.message };
  }
}

// 发送申诉通知邮件（发送给管理员）
async function sendAppealNotification(appeal) {
  const typeNames = {
    ip: 'IP封禁',
    device: '设备封禁',
    account: '账号封禁'
  };
  const typeName = typeNames[appeal.type] || appeal.type;

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1a1a28; border-radius: 12px; overflow: hidden; }
        .header { background: linear-gradient(135deg, #00f5ff, #7b2ff7); padding: 24px; text-align: center; }
        .header h1 { margin: 0; color: #fff; font-size: 24px; }
        .content { padding: 24px; }
        .badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 14px; font-weight: bold; color: #fff; background: #00f5ff; margin-bottom: 16px; }
        .info-box { background: rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; margin: 16px 0; border-left: 4px solid #00f5ff; }
        .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #888; }
        .info-value { color: #fff; font-family: monospace; }
        .message-box { background: rgba(255,152,0,0.1); border-radius: 8px; padding: 16px; margin: 16px 0; border: 1px solid rgba(255,152,0,0.3); }
        .btn { display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #00f5ff, #7b2ff7); color: #fff; text-decoration: none; border-radius: 8px; margin-top: 16px; }
        .footer { background: #12121a; padding: 16px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>📢 申诉通知</h1>
        </div>
        <div class="content">
          <div class="badge">${typeName}申诉</div>
          <p>有用户提交了解封申诉，请及时处理：</p>

          <div class="info-box">
            <div class="info-row">
              <span class="info-label">申诉ID</span>
              <span class="info-value">#${appeal.id}</span>
            </div>
            <div class="info-row">
              <span class="info-label">封禁类型</span>
              <span class="info-value">${typeName}</span>
            </div>
            <div class="info-row">
              <span class="info-label">IP地址</span>
              <span class="info-value">${appeal.ip || '未知'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">设备指纹</span>
              <span class="info-value">${appeal.fingerprint_hash ? appeal.fingerprint_hash.slice(0,16) + '...' : '未知'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">联系邮箱</span>
              <span class="info-value">${appeal.contact_email || '未提供'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">提交时间</span>
              <span class="info-value">${new Date(appeal.created_at).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</span>
            </div>
          </div>

          <div class="message-box">
            <strong style="color: #ff9800;">申诉理由:</strong>
            <p style="margin: 8px 0; color: #e8e8f0;">${appeal.reason}</p>
          </div>

          ${appeal.appeal_message ? `
          <div class="message-box">
            <strong style="color: #00f5ff;">附加说明:</strong>
            <p style="margin: 8px 0; color: #e8e8f0;">${appeal.appeal_message}</p>
          </div>
          ` : ''}

          <p style="color: #888; font-size: 14px; margin-top: 24px;">
            请登录管理后台查看完整详情并处理此申诉。
          </p>
        </div>
        <div class="footer">
          极风工作室安全防护系统 // 此邮件由系统自动发送，请勿回复
        </div>
      </div>
    </body>
    </html>
  `;

  return sendMail(ADMIN_EMAIL, `[极风申诉] 新的${typeName}申诉 #${appeal.id}`, html);
}

// 发送申诉处理结果邮件（发送给申诉者）
async function sendAppealResult(appeal, adminReply) {
  if (!appeal.contact_email) return { success: false, reason: 'no_contact_email' };

  const statusNames = {
    approved: '已通过 - 已解封',
    rejected: '已驳回',
    pending: '处理中'
  };
  const statusName = statusNames[appeal.status] || appeal.status;

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
        .container { max-width: 500px; margin: 0 auto; background: #1a1a28; border-radius: 12px; overflow: hidden; }
        .header { background: linear-gradient(135deg, ${appeal.status === 'approved' ? '#00ff88, #00f5ff' : '#ff3b5c, #7b2ff7'}); padding: 24px; text-align: center; }
        .header h1 { margin: 0; color: #fff; }
        .content { padding: 32px; }
        .status-box { text-align: center; padding: 20px; border-radius: 12px; margin: 16px 0; font-size: 20px; font-weight: bold; background: ${appeal.status === 'approved' ? 'rgba(0,255,136,0.1)' : 'rgba(255,59,92,0.1)'}; color: ${appeal.status === 'approved' ? '#00ff88' : '#ff3b5c'}; }
        .reply-box { background: rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; margin: 16px 0; }
        .footer { background: #12121a; padding: 16px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>${appeal.status === 'approved' ? '✅ 申诉已通过' : '❌ 申诉已驳回'}</h1>
        </div>
        <div class="content">
          <div class="status-box">${statusName}</div>
          <p>您的申诉已由管理员处理。</p>
          ${adminReply ? `
          <div class="reply-box">
            <strong style="color: #00f5ff;">管理员回复:</strong>
            <p style="margin: 8px 0;">${adminReply}</p>
          </div>
          ` : ''}
          ${appeal.status === 'approved' ? '<p style="color: #00ff88;">您的IP/设备已被解封，现在可以正常访问网站了。</p>' : '<p style="color: #ff9800;">如果您认为处理有误，可以再次提交申诉。</p>'}
        </div>
        <div class="footer">
          极风工作室 // 此邮件由系统自动发送，请勿回复
        </div>
      </div>
    </body>
    </html>
  `;

  return sendMail(appeal.contact_email, `[极风工作室] 申诉处理结果 - ${statusName}`, html);
}

// 发送安全警报邮件
async function sendSecurityAlert(alert) {
  const severityColors = {
    critical: '#ff3b5c',
    high: '#ff9800',
    medium: '#ffc107',
    low: '#00f5ff'
  };
  
  const severityNames = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危'
  };
  
  const color = severityColors[alert.severity] || '#666';
  const severityName = severityNames[alert.severity] || alert.severity;
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1a1a28; border-radius: 12px; overflow: hidden; }
        .header { background: linear-gradient(135deg, #ff3b5c, #7b2ff7); padding: 24px; text-align: center; }
        .header h1 { margin: 0; color: #fff; font-size: 24px; }
        .content { padding: 24px; }
        .alert-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 14px; font-weight: bold; color: #fff; background: ${color}; margin-bottom: 16px; }
        .info-box { background: rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; margin: 16px 0; border-left: 4px solid ${color}; }
        .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #888; }
        .info-value { color: #fff; font-family: monospace; }
        .message { font-size: 16px; line-height: 1.6; margin: 16px 0; }
        .footer { background: #12121a; padding: 16px; text-align: center; color: #666; font-size: 12px; }
        .btn { display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #00f5ff, #7b2ff7); color: #fff; text-decoration: none; border-radius: 8px; margin-top: 16px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🛡️ 极风工作室安全警报</h1>
        </div>
        <div class="content">
          <div class="alert-badge">${severityName} // ${alert.severity.toUpperCase()}</div>
          
          <div class="message">${alert.message}</div>
          
          <div class="info-box">
            <div class="info-row">
              <span class="info-label">警报类型</span>
              <span class="info-value">${alert.type}</span>
            </div>
            <div class="info-row">
              <span class="info-label">来源 IP</span>
              <span class="info-value">${alert.ip || '未知'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">发生时间</span>
              <span class="info-value">${new Date(alert.created_at).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</span>
            </div>
            <div class="info-row">
              <span class="info-label">警报 ID</span>
              <span class="info-value">#${alert.id}</span>
            </div>
          </div>
          
          ${alert.details ? `
          <div class="info-box">
            <div style="color: #888; font-size: 12px; margin-bottom: 8px;">详细信息:</div>
            <pre style="color: #00f5ff; font-size: 12px; margin: 0; white-space: pre-wrap;">${typeof alert.details === 'string' ? alert.details : JSON.stringify(alert.details, null, 2)}</pre>
          </div>
          ` : ''}
          
          <p style="color: #888; font-size: 14px; margin-top: 24px;">
            请及时登录管理后台查看详情并采取相应措施。
          </p>
        </div>
        <div class="footer">
          极风工作室安全防护系统 // JIFENG SECURITY CENTER<br>
          此邮件由系统自动发送，请勿回复
        </div>
      </div>
    </body>
    </html>
  `;
  
  const result = await sendMail(ADMIN_EMAIL, `[极风安全] ${severityName}警报: ${alert.type}`, html);
  
  if (result.success) {
    // 标记已发送
    db.prepare('UPDATE security_alerts SET email_sent = 1 WHERE id = ?').run(alert.id);
  }
  
  return result;
}

// 发送二次验证码邮件
async function send2FACode(code, ip, userAgent) {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
        .container { max-width: 500px; margin: 0 auto; background: #1a1a28; border-radius: 12px; overflow: hidden; }
        .header { background: linear-gradient(135deg, #00f5ff, #7b2ff7); padding: 24px; text-align: center; }
        .header h1 { margin: 0; color: #fff; }
        .content { padding: 32px; text-align: center; }
        .code { font-size: 48px; font-weight: bold; color: #00f5ff; letter-spacing: 12px; font-family: monospace; background: rgba(0,245,255,0.1); padding: 24px; border-radius: 12px; margin: 24px 0; }
        .info { color: #888; font-size: 14px; margin-top: 16px; }
        .warning { color: #ff9800; font-size: 12px; margin-top: 24px; }
        .footer { background: #12121a; padding: 16px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔐 极风工作室 - 二次验证</h1>
        </div>
        <div class="content">
          <p>您的验证码是:</p>
          <div class="code">${code}</div>
          <p class="info">验证码 5 分钟内有效</p>
          <p class="info">请求来源: ${ip}</p>
          <p class="warning">如果这不是您本人的操作，请立即修改密码</p>
        </div>
        <div class="footer">
          极风工作室 // 此验证码由系统自动发送
        </div>
      </div>
    </body>
    </html>
  `;
  
  return sendMail(ADMIN_EMAIL, '极风工作室 - 管理员二次验证码', html);
}

// 发送动态路径邮件
async function sendDynamicPath(path, ip) {
  const fullUrl = process.env.SITE_URL || 'https://your-site.vercel.app';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e8e8f0; padding: 20px; }
        .container { max-width: 500px; margin: 0 auto; background: #1a1a28; border-radius: 12px; overflow: hidden; }
        .header { background: linear-gradient(135deg, #7b2ff7, #ff00d4); padding: 24px; text-align: center; }
        .header h1 { margin: 0; color: #fff; }
        .content { padding: 32px; }
        .path-box { background: rgba(123,47,247,0.1); border: 1px solid rgba(123,47,247,0.3); padding: 20px; border-radius: 8px; margin: 16px 0; word-break: break-all; font-family: monospace; color: #00f5ff; }
        .info { color: #888; font-size: 14px; margin: 8px 0; }
        .warning { color: #ff9800; font-size: 12px; margin-top: 24px; padding: 12px; background: rgba(255,152,0,0.1); border-radius: 8px; }
        .footer { background: #12121a; padding: 16px; text-align: center; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔑 极风工作室 - 管理后台入口</h1>
        </div>
        <div class="content">
          <p>您请求的管理后台动态访问路径:</p>
          <div class="path-box">${fullUrl}${path}</div>
          <p class="info">请求 IP: ${ip}</p>
          <p class="info">有效期: 1 小时</p>
          <p class="info">此路径仅限当前 IP 使用，且只能使用一次</p>
          <div class="warning">
            ⚠️ 安全提示: 请勿将此链接分享给任何人。如果您没有请求此链接，请立即检查账户安全。
          </div>
        </div>
        <div class="footer">
          极风工作室安全系统 // 自动发送
        </div>
      </div>
    </body>
    </html>
  `;
  
  return sendMail(ADMIN_EMAIL, '极风工作室 - 管理后台动态入口', html);
}

// 批量发送未处理的安全警报
async function sendPendingAlerts() {
  const { getUnsentAlerts } = require('./security-advanced');
  const alerts = getUnsentAlerts();
  
  const results = [];
  for (const alert of alerts) {
    const result = await sendSecurityAlert(alert);
    results.push({ alertId: alert.id, ...result });
  }
  
  return results;
}

module.exports = {
  initTransporter,
  sendMail,
  sendSecurityAlert,
  send2FACode,
  sendDynamicPath,
  sendPendingAlerts,
  sendAppealNotification,
  sendAppealResult,
  ADMIN_EMAIL,
  EMAIL_CONFIG
};