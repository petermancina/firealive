// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — CORS Policy (Zero Trust)
// Only allows connections from known FireAlive components
// ═══════════════════════════════════════════════════════════════════════════════

const ALLOWED_ORIGINS = new Set([
  // In production, these are set via environment variables
  process.env.FIREALIVE_MC_ORIGIN || 'app://firealive-mc',
  process.env.FIREALIVE_AC_ORIGIN || 'app://firealive-ac',
  process.env.FIREALIVE_GD_ORIGIN || 'app://firealive-gd',
]);

const corsPolicy = (req, res, next) => {
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Request-Nonce, X-Request-Timestamp');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '600');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
};

module.exports = { corsPolicy, ALLOWED_ORIGINS };
