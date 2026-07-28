const crypto = require('crypto');

const REQUEST_SECRET = process.env.REQUEST_SECRET || crypto.scryptSync('jifeng_prod_2024_xk', 's4lt', 32).toString('hex');
const TOKEN_EXPIRY = 2 * 60 * 1000;
const SIGNATURE_TIMESTAMP_TOLERANCE = 5 * 60 * 1000;

const tokenStore = new Map();

function generateServerToken(req) {
  const ip = req.ip || '0.0.0.0';
  const ua = req.headers['user-agent'] || '';
  const now = Date.now();
  const salt = crypto.randomBytes(16).toString('hex');
  const raw = `${ip}:${ua}:${now}:${salt}`;
  const token = crypto.createHmac('sha256', REQUEST_SECRET).update(raw).digest('hex');
  const stamp = now.toString(36) + '.' + crypto.randomBytes(4).toString('hex');

  tokenStore.set(token, { ip, ua, created: now, stamp, salt });
  if (tokenStore.size > 10000) {
    const cutoff = now - TOKEN_EXPIRY * 2;
    for (const [k, v] of tokenStore) {
      if (v.created < cutoff) tokenStore.delete(k);
    }
  }

  return { t: token, s: stamp };
}

function verifyServerToken(token, stamp, req) {
  if (!token || !stamp) return false;
  const record = tokenStore.get(token);
  if (!record) return false;

  const now = Date.now();
  if (now - record.created > TOKEN_EXPIRY) {
    tokenStore.delete(token);
    return false;
  }

  const ip = req.ip || '0.0.0.0';
  const ua = req.headers['user-agent'] || '';
  if (record.ip !== ip || record.ua !== ua) return false;

  return true;
}

function generateSignature(url, timestamp, userAgent, secret) {
  const data = `${url}:${timestamp}:${userAgent}:${secret}`;
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function verifyRequestSignature(req, res, next) {
  const token = req.headers['x-request-token'];
  const stamp = req.headers['x-request-stamp'];

  if (!token || !stamp) {
    if (req.path && req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_REQUIRED' });
    }
    return next();
  }

  if (!verifyServerToken(token, stamp, req)) {
    return res.status(401).json({ error: 'Unauthorized', code: 'TOKEN_INVALID' });
  }

  req.requestVerified = true;
  next();
}

function applySignatureToResponse(req, res, next) {
  next();
}

const sensitivePaths = [
  '/api/admin/',
  '/api/user/',
  '/api/billing/',
  '/api/verification/',
  '/api/license/',
  '/api/security/'
];

function isSensitivePath(p) {
  return sensitivePaths.some(s => p && p.startsWith(s));
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of tokenStore) {
    if (now - v.created > TOKEN_EXPIRY) tokenStore.delete(k);
  }
}, 60 * 1000);

module.exports = {
  verifyRequestSignature,
  applySignatureToResponse,
  isSensitivePath,
  generateServerToken,
  verifyServerToken,
  generateSignature,
  REQUEST_SECRET
};
