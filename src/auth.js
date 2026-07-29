const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('[Auth] JWT_SECRET 环境变量未设置');
}
const TOKEN_EXPIRES_IN = '24h';

function login(username, password, ip) {
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  
  if (!admin) {
    return { success: false, message: '用户名或密码错误' };
  }

  const valid = bcrypt.compareSync(password, admin.password_hash);
  
  if (!valid) {
    return { success: false, message: '用户名或密码错误' };
  }

  const token = jwt.sign(
    { 
      id: admin.id, 
      username: admin.username, 
      role: admin.role 
    },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRES_IN }
  );

  db.prepare(`
    UPDATE admins 
    SET last_login_at = datetime('now'), last_login_ip = ?
    WHERE id = ?
  `).run(ip, admin.id);

  return {
    success: true,
    token,
    admin: {
      id: admin.id,
      username: admin.username,
      role: admin.role,
      last_login_at: admin.last_login_at,
      last_login_ip: admin.last_login_ip
    }
  };
}

function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = db.prepare('SELECT id, username, role FROM admins WHERE id = ?').get(decoded.id);
    
    if (!admin) {
      return { valid: false };
    }
    
    return { valid: true, admin };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.admin_token || 
                req.headers['authorization']?.replace('Bearer ', '');

  if (!token) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: '未登录' });
    }
    return res.redirect('/dashboard.html');
  }

  const result = verifyToken(token);
  
  if (!result.valid) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: '登录已过期' });
    }
    return res.redirect('/dashboard.html');
  }

  req.admin = result.admin;
  next();
}

function changePassword(userId, oldPassword, newPassword) {
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(userId);
  
  if (!admin) {
    return { success: false, message: '用户不存在' };
  }

  const valid = bcrypt.compareSync(oldPassword, admin.password_hash);
  
  if (!valid) {
    return { success: false, message: '原密码错误' };
  }

  if (newPassword.length < 6) {
    return { success: false, message: '新密码至少6位' };
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(newHash, userId);

  return { success: true };
}

function getAdminList() {
  return db.prepare('SELECT id, username, role, last_login_at, last_login_ip, created_at FROM admins ORDER BY id').all();
}

module.exports = {
  login,
  verifyToken,
  authMiddleware,
  changePassword,
  getAdminList
};
