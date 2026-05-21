// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Lead Notification Contacts Routes
// Mounted at /api/users/me/lead-contacts by server/index.js (mount lands in the
// inline edit immediately following this commit).
//
//   GET    /api/users/me/lead-contacts  — read current lead's notification contact info
//   PUT    /api/users/me/lead-contacts  — update current lead's notification contact info
//
// SECURITY MODEL (anonymity preservation, N1a C7 + C19):
//   - Both endpoints require an authenticated user (req.user from JWT middleware)
//   - Both endpoints check role: only lead/admin/developer can read or write
//   - Analyst-role users get HTTP 403 with code ANALYST_CONTACT_STORAGE_BLOCKED
//   - The underlying lead_notification_contacts table (N1a C6 schema) is
//     structurally restricted by design: analysts NEVER have rows there.
//     Storing analyst contact info would defeat the pseudonym architecture
//     by linking the pseudonymized user_id to identity-bearing PII.
//
// VALIDATION:
//   - email: RFC 5322 light regex — accepts well-formed addresses, rejects garbage
//   - phone: E.164 format (e.g., +15551234567) — international standard accepted
//     by Twilio and AWS SNS without re-formatting (matches notifications-sms.js
//     dispatcher expectation at N1a C8)
//   - Both fields are nullable. Sending both as null/empty deletes the row
//     (lead clearing all contact info as part of opt-out or offboarding self-service)
//
// PII HANDLING:
//   - email + phone values are stored PLAINTEXT in lead_notification_contacts.
//     This is consistent with the existing users.name + users.username plaintext
//     storage pattern. These columns are NOT credentials (unlike
//     notification_config.sms_auth_token_encrypted, which IS AES-256-GCM
//     encrypted via TIER1_ENCRYPTION_KEY because it's a Twilio/AWS auth secret).
//   - Audit log entries reference the lead by user_id only and use boolean
//     set/unset flags for the email/phone fields — never the actual values.
//     This avoids leaking PII into the audit table even if the audit log is
//     compromised.
//
// AUDIT EVENTS:
//   - MC_LEAD_CONTACT_INFO_UPDATED              — PUT successful update (email_set/phone_set booleans)
//   - MC_LEAD_CONTACT_INFO_CLEARED              — PUT with both fields null (row deleted)
//   - MC_ANALYST_CONTACT_STORAGE_ACCESS_DENIED  — GET or PUT attempted by analyst-role caller
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// N1a C19: Anonymity-preservation role policy. Duplicated from notifications.js
// (N1a C7) to avoid circular-import risk. Stable policy (lead/admin/developer
// are contact-safe; analyst + unknown roles are not).
function isContactSafeRole(role) {
  return role === 'lead' || role === 'admin' || role === 'developer';
}

// RFC 5322 light: rejects whitespace, requires single @, requires a TLD-ish
// suffix. Doesn't validate every edge case in RFC 5322 (which is notoriously
// permissive) — strikes a balance between false-rejects on legitimate addresses
// and false-accepts on garbage. Production deployments may want to layer on
// a verification email round-trip for true validation.
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// E.164 international format: + followed by 1-15 digits, first digit non-zero.
// Matches Twilio + AWS SNS expected input format. Examples: +15551234567,
// +442071234567, +817012345678.
const E164_REGEX = /^\+[1-9]\d{1,14}$/;

function validateBody(body) {
  const email = body && typeof body.email === 'string' ? body.email.trim() : null;
  const phone = body && typeof body.phone === 'string' ? body.phone.trim() : null;
  const errors = [];
  if (email && !EMAIL_REGEX.test(email)) {
    errors.push({
      field: 'email',
      code: 'INVALID_EMAIL_FORMAT',
      message: 'Email must be a valid RFC 5322 address (e.g., name@example.com)',
    });
  }
  if (phone && !E164_REGEX.test(phone)) {
    errors.push({
      field: 'phone',
      code: 'INVALID_PHONE_FORMAT',
      message: 'Phone must be in E.164 international format (e.g., +15551234567)',
    });
  }
  return { email: email || null, phone: phone || null, errors };
}

// ── GET /api/users/me/lead-contacts ──────────────────────────────────────────
// Read the current lead's registered notification contact info. Returns
// { email, phone, updated_at }; all fields may be null if the lead has not yet
// registered any contact info (no row in lead_notification_contacts).
router.get('/', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const role = req.user?.role;
    if (!isContactSafeRole(role)) {
      auditLog(userId, 'MC_ANALYST_CONTACT_STORAGE_ACCESS_DENIED',
        `role=${role || 'unknown'} action=read`, req.ip);
      return res.status(403).json({
        error: 'Lead contact storage is restricted to non-anonymous roles (lead, admin, developer). Analyst-role users do not have a lead_notification_contacts entry by design — this preserves the pseudonym architecture.',
        code: 'ANALYST_CONTACT_STORAGE_BLOCKED',
      });
    }

    const db = getDb();
    try {
      const row = db.prepare(
        "SELECT email, phone, updated_at FROM lead_notification_contacts WHERE user_id = ?"
      ).get(userId);
      res.json(row || { email: null, phone: null, updated_at: null });
    } finally {
      db.close();
    }
  } catch (err) {
    logger.error('Lead contact GET error', { error: err.message });
    res.status(500).json({ error: 'Failed to read lead contact info' });
  }
});

// ── PUT /api/users/me/lead-contacts ──────────────────────────────────────────
// Update the current lead's notification contact info. Body: { email, phone }.
// Either field may be null/empty/missing. Sending both null/empty deletes the
// row (lead clearing all contact info — useful for opt-out or offboarding).
//
// Validates email + phone formats; returns HTTP 422 with field-level errors
// on validation failure. Returns HTTP 403 ANALYST_CONTACT_STORAGE_BLOCKED if
// the caller is not a contact-safe role.
router.put('/', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const role = req.user?.role;
    if (!isContactSafeRole(role)) {
      auditLog(userId, 'MC_ANALYST_CONTACT_STORAGE_ACCESS_DENIED',
        `role=${role || 'unknown'} action=write`, req.ip);
      return res.status(403).json({
        error: 'Lead contact storage is restricted to non-anonymous roles (lead, admin, developer). Analyst-role users cannot register notification contact info — this preserves the pseudonym architecture.',
        code: 'ANALYST_CONTACT_STORAGE_BLOCKED',
      });
    }

    const { email, phone, errors } = validateBody(req.body);
    if (errors.length > 0) {
      return res.status(422).json({
        error: 'Invalid contact info — see field-level errors',
        code: 'VALIDATION_FAILED',
        fields: errors,
      });
    }

    const db = getDb();
    try {
      // Both null/empty → delete the row entirely. Lead is opting out of
      // email + sms channels by removing their contact info. Subsequent
      // notification dispatches will skip these channels with audit reason
      // 'no_lead_phone_registered' / 'no_lead_email_registered'.
      if (!email && !phone) {
        const result = db.prepare(
          "DELETE FROM lead_notification_contacts WHERE user_id = ?"
        ).run(userId);
        auditLog(userId, 'MC_LEAD_CONTACT_INFO_CLEARED',
          `rows_deleted=${result.changes}`, req.ip);
        return res.json({
          success: true,
          email: null,
          phone: null,
          updated_at: null,
          cleared: true,
        });
      }

      // UPSERT: insert new row or update existing. user_id is the PRIMARY KEY
      // (N1a C6 schema), so the ON CONFLICT clause hits when the lead already
      // has a row.
      db.prepare(`
        INSERT INTO lead_notification_contacts (user_id, email, phone, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(user_id) DO UPDATE
          SET email = excluded.email,
              phone = excluded.phone,
              updated_at = datetime('now')
      `).run(userId, email, phone);

      const row = db.prepare(
        "SELECT email, phone, updated_at FROM lead_notification_contacts WHERE user_id = ?"
      ).get(userId);

      // Audit: log boolean set/unset flags only — never the actual email/phone
      // values. This avoids leaking PII into the audit table even if the
      // audit log is compromised.
      auditLog(userId, 'MC_LEAD_CONTACT_INFO_UPDATED',
        `email_set=${!!email} phone_set=${!!phone}`, req.ip);

      res.json({ success: true, ...row });
    } finally {
      db.close();
    }
  } catch (err) {
    logger.error('Lead contact PUT error', { error: err.message });
    res.status(500).json({ error: 'Failed to update lead contact info' });
  }
});

module.exports = router;
