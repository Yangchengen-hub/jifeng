const crypto = require('crypto');
const db = require('./db');

// 多重验证码类型
// 1. 图形验证码（SVG 文字识别）
// 2. 数学运算验证（需要计算结果）
// 3. 行为验证 token（检测鼠标移动/键盘输入节奏）

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 生成图形验证码
function generateGraphicCaptcha(width = 150, height = 50, length = 5) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghjkmnpqrstuvwxyz';
  let answer = '';
  for (let i = 0; i < length; i++) {
    answer += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  const lines = [];
  const dots = [];
  // 干扰线
  for (let i = 0; i < 8; i++) {
    lines.push({
      x1: Math.random() * width,
      y1: Math.random() * height,
      x2: Math.random() * width,
      y2: Math.random() * height,
      color: `rgba(${rand(100, 200)}, ${rand(100, 200)}, ${rand(100, 200)}, 0.5)`
    });
  }
  // 干扰点
  for (let i = 0; i < 60; i++) {
    dots.push({
      x: Math.random() * width,
      y: Math.random() * height,
      r: Math.random() * 2 + 0.5,
      color: `rgba(${rand(100, 255)}, ${rand(100, 255)}, ${rand(100, 255)}, 0.5)`
    });
  }

  const characters = [];
  const charWidth = width / length;
  for (let i = 0; i < answer.length; i++) {
    characters.push({
      char: answer[i],
      x: charWidth * i + charWidth / 2 + rand(-10, 10),
      y: height / 2 + rand(-8, 8),
      rotate: rand(-30, 30),
      color: `rgb(${rand(200, 255)}, ${rand(100, 180)}, ${rand(50, 150)})`,
      fontSize: rand(24, 34)
    });
  }

  return {
    answer,
    svg: generateSvg(width, height, characters, lines, dots),
    width,
    height
  };
}

// 生成数学验证码
function generateMathCaptcha() {
  const a = rand(1, 20);
  const b = rand(1, 20);
  const ops = ['+', '-', '×'];
  const op = ops[rand(0, ops.length - 1)];
  let answer;
  let displayOp = op;

  switch (op) {
    case '+': answer = a + b; break;
    case '-':
      if (a < b) { answer = b - a; displayOp = `${b} - ${a}`; }
      else { answer = a - b; displayOp = `${a} - ${b}`; }
      break;
    case '×': answer = a * b; break;
  }

  return {
    answer: String(answer),
    question: displayOp === '×' ? `${a} × ${b} = ?` : `${displayOp} = ?`,
    svg: generateMathSvg(displayOp === '×' ? `${a} × ${b} = ?` : displayOp + ' = ?')
  };
}

function generateSvg(width, height, characters, lines, dots) {
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<rect width="100%" height="100%" fill="#1a1a2e"/>`;

  // 背景渐变
  svg += `<defs><linearGradient id="bg${rand(1000,9999)}" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" style="stop-color:#1a1a2e;stop-opacity:1"/>
    <stop offset="100%" style="stop-color:#16213e;stop-opacity:1"/>
  </linearGradient></defs>`;
  svg += `<rect width="100%" height="100%" fill="url(#bg)" opacity="0.5"/>`;

  lines.forEach(line => {
    svg += `<line x1="${line.x1}" y1="${line.y1}" x2="${line.x2}" y2="${line.y2}" stroke="${line.color}" stroke-width="1.5"/>`;
  });

  dots.forEach(dot => {
    svg += `<circle cx="${dot.x}" cy="${dot.y}" r="${dot.r}" fill="${dot.color}"/>`;
  });

  characters.forEach(char => {
    svg += `<text x="${char.x}" y="${char.y}" fill="${char.color}" font-size="${char.fontSize}px" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle" dominant-baseline="middle" transform="rotate(${char.rotate} ${char.x} ${char.y})">${char.char}</text>`;
  });

  svg += `</svg>`;
  return svg;
}

function generateMathSvg(question) {
  const width = 150;
  const height = 50;
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<rect width="100%" height="100%" fill="#1a1a2e"/>`;
  // 干扰线
  for (let i = 0; i < 5; i++) {
    svg += `<line x1="${Math.random()*width}" y1="${Math.random()*height}" x2="${Math.random()*width}" y2="${Math.random()*height}" stroke="rgba(${rand(100,200)},${rand(100,200)},${rand(100,200)},0.4)" stroke-width="1"/>`;
  }
  svg += `<text x="${width/2}" y="${height/2+8}" fill="rgb(${rand(200,255)},${rand(150,200)},${rand(100,180)})" font-size="22px" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">${question}</text>`;
  svg += `</svg>`;
  return svg;
}

// 生成行为验证 token（前端需要收集鼠标轨迹和输入时间）
function generateBehaviorToken() {
  return crypto.randomBytes(16).toString('hex');
}

// 创建多重验证码
function createCaptcha(purpose = 'general') {
  // 随机选择验证码类型：50% 图形，50% 数学
  const useMath = Math.random() > 0.5;
  const captcha = useMath ? generateMathCaptcha() : generateGraphicCaptcha();

  const token = crypto.randomBytes(32).toString('hex');
  const behaviorToken = generateBehaviorToken();
  const expiresAt = new Date(Date.now() + 3 * 60 * 1000).toISOString(); // 3分钟过期

  db.prepare(`
    INSERT INTO captcha_tokens (token, answer, purpose, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(token, captcha.answer.toUpperCase(), purpose, expiresAt);

  return {
    token,
    svg: captcha.svg,
    type: useMath ? 'math' : 'graphic',
    behaviorToken,
    expiresAt
  };
}

// 验证码校验 - 多重检测
function verifyCaptcha(token, answer, purpose = 'general', behaviorData = null) {
  const record = db.prepare(`
    SELECT * FROM captcha_tokens
    WHERE token = ? AND purpose = ? AND used = 0 AND expires_at > datetime('now')
  `).get(token, purpose);

  if (!record) {
    return { valid: false, reason: 'invalid_or_expired' };
  }

  const isCorrect = record.answer === (answer || '').toUpperCase().trim();

  // 标记已使用
  db.prepare('UPDATE captcha_tokens SET used = 1 WHERE id = ?').run(record.id);

  if (!isCorrect) {
    return { valid: false, reason: 'wrong_answer' };
  }

  // 行为验证：检测是否有人类行为特征
  if (behaviorData) {
    const { inputTime, mouseMovements, keyPressCount } = behaviorData;
    // 如果输入时间小于 500ms，可能是机器人自动填充
    if (inputTime && inputTime < 500) {
      return { valid: false, reason: 'behavior_check_failed' };
    }
    // 如果没有鼠标移动且按键次数太少
    if (mouseMovements === 0 && keyPressCount < 3) {
      return { valid: false, reason: 'behavior_check_failed' };
    }
  }

  return { valid: true };
}

function cleanupExpired() {
  const result = db.prepare(`
    DELETE FROM captcha_tokens
    WHERE expires_at < datetime('now', '-1 hour')
  `).run();
  return result.changes;
}

setInterval(cleanupExpired, 60 * 60 * 1000);

module.exports = {
  createCaptcha,
  verifyCaptcha,
  generateGraphicCaptcha,
  generateMathCaptcha
};
