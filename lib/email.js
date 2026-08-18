const FROM=process.env.MAIL_FROM||'onboarding@resend.dev';
const API_KEY=process.env.RESEND_API_KEY;
const ALERT_TO=process.env.ALERT_EMAIL||'3565583431@qq.com';

async function send(to,subject,html){
  if(!API_KEY){console.warn('RESEND_API_KEY not set');return{ok:false}}
  try{
    const r=await fetch('https://api.resend.com/emails',{
      method:'POST',
      headers:{Authorization:'Bearer '+API_KEY,'Content-Type':'application/json'},
      body:JSON.stringify({from:FROM,to:to||ALERT_TO,subject,html:html||subject.replace(/\n/g,'<br>')})
    });
    const d=await r.json();
    return{ok:r.ok,id:d.id,error:d.message};
  }catch(e){return{ok:false,error:e.message}}
}

function securityAlert(event){
  const html=`<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<h2 style="color:#ff453a">⚠️ 极风安全告警</h2>
<div style="background:#1c1c1e;color:#f5f5f7;padding:20px;border-radius:12px;margin:16px 0">
<p><strong>事件类型：</strong>${event.type}</p>
<p><strong>详细信息：</strong>${(event.message||'').replace(/\n/g,'<br>')}</p>
<p><strong>时间：</strong>${new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}</p>
${event.meta&&event.meta.ip?`<p><strong>IP地址：</strong>${event.meta.ip}</p>`:''}
${event.meta&&event.meta.fid?`<p><strong>设备指纹：</strong><code>${event.meta.fid}</code></p>`:''}
</div>
<p style="color:#86868b;font-size:12px">此邮件由极风工作室安全系统自动发送，请勿直接回复。</p>
</div>`;
  return send(ALERT_TO,'[极风安全告警] '+event.type+' - '+new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'}),html);
}

function verificationCode(code){
  const html=`<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<h2 style="color:#ff6900">极风工作室 · 邮箱验证</h2>
<p>您正在登录极风工作室管理控制台，验证码为：</p>
<div style="background:#1c1c1e;color:#ff6900;padding:24px;border-radius:12px;text-align:center;font-size:32px;font-weight:800;letter-spacing:8px;margin:20px 0">${code}</div>
<p style="color:#86868b">验证码10分钟内有效，请勿向他人泄露。</p>
<p style="color:#86868b;font-size:12px">如非本人操作，请立即检查账号安全。</p>
</div>`;
  return send(ALERT_TO,'极风工作室 - 登录验证码',html);
}

function appealNotice(appeal){
  const html=`<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<h2 style="color:#ff9f0a">📋 新申诉待审核</h2>
<div style="background:#1c1c1e;color:#f5f5f7;padding:20px;border-radius:12px;margin:16px 0">
<p><strong>IP：</strong>${appeal.ip}</p>
<p><strong>设备：</strong>${appeal.fid||'未知'}</p>
<p><strong>封禁原因：</strong>${appeal.banReason}</p>
<p><strong>申诉内容：</strong>${appeal.content}</p>
<p><strong>提交时间：</strong>${new Date(appeal.time).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}</p>
</div>
<p>请登录管理端审核。</p>
</div>`;
  return send(ALERT_TO,'[极风] 新申诉待审核 - '+appeal.ip,html);
}

function commitmentNotice(data){
  const html=`<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<h2 style="color:#30d158">📝 承诺书已签署</h2>
<div style="background:#1c1c1e;color:#f5f5f7;padding:20px;border-radius:12px;margin:16px 0">
<p><strong>IP：</strong>${data.ip}</p>
<p><strong>设备：</strong>${data.fid||'未知'}</p>
<p><strong>承诺内容：</strong>${(data.content||'').replace(/\n/g,'<br>')}</p>
<p><strong>签署时间：</strong>${new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}</p>
</div>
<p style="color:#86868b;font-size:12px">此承诺书已存档备查。如再次违规将永久封禁。</p>
</div>`;
  return send(ALERT_TO,'[极风] 承诺书已签署 - '+data.ip,html);
}

function dailyReport(report){
  const html=`<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<h2 style="color:#ff6900">极风工作室 · 每日运维报告</h2>
<div style="background:#1c1c1e;color:#f5f5f7;padding:20px;border-radius:12px;margin:16px 0;white-space:pre-wrap;font-size:13px;line-height:1.8">${report}</div>
<p style="color:#86868b;font-size:12px">此邮件由系统自动发送。</p>
</div>`;
  return send(ALERT_TO,'极风工作室 - 每日运维报告 '+new Date().toLocaleDateString('zh-CN'),html);
}

module.exports={send,securityAlert,verificationCode,dailyReport,appealNotice,commitmentNotice};
