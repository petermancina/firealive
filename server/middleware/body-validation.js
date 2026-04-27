// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Request Body Shape Validation
// Defends against type confusion attacks (CWE-843) where attackers send
// req.body as the wrong shape (e.g. array instead of object, or vice versa)
// to bypass sanitizers or poison stored config.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Reject requests whose body is not a plain object or array.
 * Strings, numbers, booleans, null, and undefined are all rejected for
 * routes that expect structured input (config writes, etc.).
 *
 * Apply selectively to mutating routes that persist req.body. GET requests
 * and routes that don't read req.body are unaffected.
 */
function requireStructuredBody(req, res, next) {
  // Only enforce on methods that carry a body
  if (!['POST', 'PUT', 'PATCH'].includes(req.method)) return next();

  const body = req.body;

  // Reject null, undefined, and primitives
  if (body === null || body === undefined) {
    return res.status(400).json({ error: 'Request body required' });
  }
  if (typeof body !== 'object') {
    return res.status(400).json({ error: 'Request body must be an object or array' });
  }

  next();
}

/**
 * Reject requests whose body is not an array. Use on routes that specifically
 * expect an array payload (e.g. PUT /backup-schedules expects [schedule, ...]).
 */
function requireArrayBody(req, res, next) {
  if (!Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Request body must be an array' });
  }
  next();
}

/**
 * Reject requests whose body is not a plain (non-array) object. Use on routes
 * that expect a config object (e.g. PUT /ha-config expects { mode, ... }).
 */
function requireObjectBody(req, res, next) {
  if (req.body === null || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Request body must be an object' });
  }
  next();
}

module.exports = {
  requireStructuredBody,
  requireArrayBody,
  requireObjectBody,
};
