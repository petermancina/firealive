// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — Security Hardening Middleware
// Addresses: injection, XSS, CSRF, SSRF, clickjacking, replay attacks,
// path traversal, header injection, rate limiting, input validation,
// output encoding, session management, anti-fingerprinting
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── Security Headers (anti-clickjacking, anti-XSS, anti-MIME-sniffing) ──────
const securityHeaders = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');                    // anti-clickjacking
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), usb=()');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  // Anti-fingerprinting
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
};

// ── Input Sanitization (anti-injection, anti-XSS, anti-path-traversal) ──────
const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      // Strip null bytes (anti-canonicalization)
      let s = obj.replace(/\0/g, '');
      // Strip HTML tags (anti-XSS). Repeat the pass until the string stops
      // changing so a tag reconstructed by an earlier removal (for example
      // "<scr<script>ipt>") cannot survive, then drop any leftover angle
      // bracket so an unclosed tag like "<script" with no '>' cannot remain.
      let prevHtml;
      do {
        prevHtml = s;
        s = s.replace(/<[^>]*>/g, '');
      } while (s !== prevHtml);
      s = s.replace(/[<>]/g, '');
      // Strip dangerous URL schemes (anti-XSS). Repeat until stable so a
      // scheme reconstructed by an earlier removal cannot survive.
      let prevScheme;
      do {
        prevScheme = s;
        s = s.replace(/(?:javascript|data|vbscript):/gi, '');
      } while (s !== prevScheme);
      // Strip CRLF injection
      s = s.replace(/[\r\n]/g, '');
      // Anti-path-traversal. Repeat until stable so a sequence reconstructed
      // by an earlier removal (for example "....//" collapsing to "../")
      // cannot survive a single pass.
      let prevPath;
      do {
        prevPath = s;
        s = s.replace(/\.\.[\/\\]/g, '');
      } while (s !== prevPath);
      // Anti-SQL injection (belt-and-suspenders with prepared statements)
      s = s.replace(/['";\\]/g, (c) => '\\' + c);
      // Anti-XML injection / XXE
      s = s.replace(/<!ENTITY/gi, '').replace(/<!DOCTYPE/gi, '');
      // Anti-LDAP injection
      s = s.replace(/[()\\*\x00]/g, '');
      // Max length enforcement
      return s.substring(0, 10000);
    }
    if (Array.isArray(obj)) return obj.map(sanitize);
    if (obj && typeof obj === 'object') {
      const cleaned = {};
      for (const [k, v] of Object.entries(obj)) {
        // Reject __proto__ and constructor (prototype pollution)
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        cleaned[sanitize(k)] = sanitize(v);
      }
      return cleaned;
    }
    return obj;
  };
  if (req.body) req.body = sanitize(req.body);
  if (req.query) req.query = sanitize(req.query);
  if (req.params) req.params = sanitize(req.params);
  next();
};

// ── CSRF Protection (double-submit cookie pattern) ──────────────────────────
const csrfProtection = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.headers['x-csrf-token'] || req.headers['x-xsrf-token'];
  const cookie = req.cookies?.csrfToken;
  if (!token || !cookie || token !== cookie) {
    // In production, enforce. In dev, log warning.
    if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ error: 'CSRF token mismatch' });
    }
  }
  next();
};

// ── Anti-Replay (nonce + timestamp window) ──────────────────────────────────
const usedNonces = new Set();
const NONCE_WINDOW_MS = 300000; // 5 minutes
const antiReplay = (req, res, next) => {
  const nonce = req.headers['x-request-nonce'];
  const timestamp = parseInt(req.headers['x-request-timestamp'] || '0');
  if (nonce) {
    if (usedNonces.has(nonce)) {
      return res.status(409).json({ error: 'Replay detected' });
    }
    if (Math.abs(Date.now() - timestamp) > NONCE_WINDOW_MS) {
      return res.status(408).json({ error: 'Request expired' });
    }
    usedNonces.add(nonce);
    setTimeout(() => usedNonces.delete(nonce), NONCE_WINDOW_MS);
  }
  next();
};

// ── Rate Limiting (per-IP) ──────────────────────────────────────────────────
const requestCounts = new Map();
const RATE_LIMIT = { window: 60000, max: 100, authMax: 10 };
const rateLimit = (req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const key = `${ip}:${req.path.includes('/auth') ? 'auth' : 'general'}`;
  const now = Date.now();
  const entry = requestCounts.get(key) || { count: 0, resetAt: now + RATE_LIMIT.window };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + RATE_LIMIT.window; }
  entry.count++;
  requestCounts.set(key, entry);
  const max = req.path.includes('/auth') ? RATE_LIMIT.authMax : RATE_LIMIT.max;
  if (entry.count > max) {
    res.setHeader('Retry-After', Math.ceil((entry.resetAt - now) / 1000));
    return res.status(429).json({ error: 'Rate limited' });
  }
  next();
};

// ── SSRF Prevention ─────────────────────────────────────────────────────────
const validateUrl = (url) => {
  if (!url) return true;
  try {
    const parsed = new URL(url);
    // Block internal/private IPs
    const blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '::1', '169.254.', '10.', '172.16.', '192.168.', 'metadata.google', '169.254.169.254'];
    if (blocked.some(b => parsed.hostname.includes(b))) return false;
    // Block file:// protocol
    if (parsed.protocol === 'file:') return false;
    return true;
  } catch { return false; }
};

// ── Anti-Downgrade (enforce minimum TLS version) ────────────────────────────
const enforceMinTls = (req, res, next) => {
  // In production with Node's TLS server: minVersion set in server config
  // This middleware logs if connection isn't secure
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.status(403).json({ error: 'HTTPS required' });
  }
  next();
};

// ── Request Size Limiting (anti-XML bomb, anti-DoS) ─────────────────────────
const maxBodySize = (limit = '1mb') => (req, res, next) => {
  const contentLength = parseInt(req.headers['content-length'] || '0');
  const maxBytes = limit === '1mb' ? 1048576 : limit === '5mb' ? 5242880 : 1048576;
  if (contentLength > maxBytes) {
    return res.status(413).json({ error: 'Request too large' });
  }
  next();
};

// ── Session Binding (anti-session-hijacking) ────────────────────────────────
const sessionBinding = (req, res, next) => {
  if (req.user) {
    const fingerprint = crypto.createHash('sha256')
      .update(`${req.ip}${req.headers['user-agent']}`)
      .digest('hex').substring(0, 16);
    if (req.user.fingerprint && req.user.fingerprint !== fingerprint) {
      return res.status(401).json({ error: 'Session binding mismatch — possible hijack' });
    }
  }
  next();
};

module.exports = {
  securityHeaders, sanitizeInput, csrfProtection, antiReplay,
  rateLimit, validateUrl, enforceMinTls, maxBodySize, sessionBinding
};
