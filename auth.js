const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const COOKIE_NAME = 'ga_session';

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 16) {
    // In dev we allow weak secret, but warn.
    console.warn('[WARN] JWT_SECRET missing/too short. Set a strong JWT_SECRET in .env for production.');
    return 'dev_unsafe_jwt_secret_change_me';
  }
  return s;
}

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

async function verifyPassword(password, passwordHash) {
  if (!passwordHash) return false;
  return bcrypt.compare(password, passwordHash);
}

function signSession(payload) {
  const secret = getJwtSecret();
  return jwt.sign(payload, secret, { expiresIn: '8h' });
}

function verifySession(token) {
  const secret = getJwtSecret();
  return jwt.verify(token, secret);
}

function setSessionCookie(res, token) {
  const secure = String(process.env.COOKIE_SECURE || '0') === '1';
  const domain = process.env.COOKIE_DOMAIN || undefined;
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    domain,
    path: '/',
    maxAge: 8 * 60 * 60 * 1000
  });
}

function clearSessionCookie(res) {
  const domain = process.env.COOKIE_DOMAIN || undefined;
  res.clearCookie(COOKIE_NAME, { path: '/', domain });
}

function authMiddleware() {
  return (req, res, next) => {
    try {
      const header = req.headers.authorization || '';
      const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
      const token = bearer || (req.cookies ? req.cookies[COOKIE_NAME] : null);
      if (!token) {
        req.auth = null;
        return next();
      }
      const payload = verifySession(token);
      req.auth = payload;
      return next();
    } catch (e) {
      req.auth = null;
      return next();
    }
  };
}

function requireAuth(req, res, next) {
  if (!req.auth) {
    return res.status(401).json({ error: 'AUTH_REQUIRED' });
  }
  return next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ error: 'AUTH_REQUIRED' });
    if (!roles.includes(req.auth.role)) return res.status(403).json({ error: 'FORBIDDEN' });
    return next();
  };
}

module.exports = {
  COOKIE_NAME,
  hashPassword,
  verifyPassword,
  signSession,
  setSessionCookie,
  clearSessionCookie,
  authMiddleware,
  requireAuth,
  requireRole
};
