// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — URL Sanitization & Validation
// Validates all URLs entering the system (custom resources, integration endpoints).
// Blocks: punycode homograph attacks, percent-encoding tricks, javascript: URIs,
//         data: URIs, file: URIs, and known-malicious patterns.
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('./logger');

// Allowed schemes
const ALLOWED_SCHEMES = ['https:', 'http:'];

// Blocked TLD patterns (common in phishing)
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz', '.zip', '.mov'];

// Max URL length
const MAX_URL_LENGTH = 2048;

/**
 * Validate and sanitize a URL.
 * Returns { valid: boolean, sanitized: string|null, reason: string|null }
 */
function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, sanitized: null, reason: 'URL is empty or not a string' };
  }

  // Length check
  if (rawUrl.length > MAX_URL_LENGTH) {
    return { valid: false, sanitized: null, reason: `URL exceeds maximum length (${MAX_URL_LENGTH})` };
  }

  // Strip whitespace and control characters
  let url = rawUrl.trim().replace(/[\x00-\x1f\x7f]/g, '');

  // Block javascript:, data:, vbscript:, file: schemes
  const schemeLower = url.toLowerCase().replace(/\s+/g, '');
  if (/^(javascript|data|vbscript|file|ftp|telnet|ssh|ldap):/i.test(schemeLower)) {
    return { valid: false, sanitized: null, reason: `Blocked scheme: ${schemeLower.split(':')[0]}` };
  }

  // Detect percent-encoding tricks (double-encoding, null bytes)
  if (/%00|%0[aAdD]|%25[0-9a-fA-F]{2}/i.test(url)) {
    return { valid: false, sanitized: null, reason: 'Suspicious percent-encoding detected (null bytes or double-encoding)' };
  }

  // Parse URL
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return { valid: false, sanitized: null, reason: 'Invalid URL format' };
  }

  // Scheme check
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    return { valid: false, sanitized: null, reason: `Scheme not allowed: ${parsed.protocol}` };
  }

  // Detect punycode/homograph attacks
  // IDN hostnames starting with xn-- are punycode-encoded
  if (parsed.hostname.includes('xn--')) {
    logger.warn('Punycode hostname detected', { url: rawUrl, hostname: parsed.hostname });
    return { valid: false, sanitized: null, reason: 'Internationalized domain name (punycode) detected — potential homograph attack' };
  }

  // Check for IP address URLs (often used in phishing)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
    logger.warn('IP address URL', { url: rawUrl });
    // Allow but flag — internal IPs are legitimate for SOAR/SIEM endpoints
    // Don't block, just log
  }

  // Check for suspicious TLDs
  const hostLower = parsed.hostname.toLowerCase();
  const suspiciousTld = SUSPICIOUS_TLDS.find(tld => hostLower.endsWith(tld));
  if (suspiciousTld) {
    logger.warn('Suspicious TLD', { url: rawUrl, tld: suspiciousTld });
    // Don't block — some legitimate services use these, but log it
  }

  // Check for username:password in URL (often used in phishing)
  if (parsed.username || parsed.password) {
    return { valid: false, sanitized: null, reason: 'URLs with embedded credentials are not allowed' };
  }

  // Check for excessive path depth (directory traversal attempts)
  if ((parsed.pathname.match(/\.\./g) || []).length > 0) {
    return { valid: false, sanitized: null, reason: 'Directory traversal pattern detected' };
  }

  // Reconstruct sanitized URL (strips any injected fragments/tricks)
  const sanitized = parsed.toString();

  return { valid: true, sanitized, reason: null };
}

/**
 * Express middleware that validates URL fields in request body.
 * @param {string[]} fields - body fields to validate as URLs
 */
function validateUrlFields(...fields) {
  return (req, res, next) => {
    for (const field of fields) {
      const value = req.body[field];
      if (!value) continue; // skip if not provided

      const result = sanitizeUrl(value);
      if (!result.valid) {
        logger.warn('URL validation failed', { field, url: value, reason: result.reason, user: req.user?.id });
        return res.status(400).json({ error: `Invalid URL in field '${field}': ${result.reason}` });
      }
      // Replace with sanitized version
      req.body[field] = result.sanitized;
    }
    next();
  };
}

module.exports = { sanitizeUrl, validateUrlFields, ALLOWED_SCHEMES };
