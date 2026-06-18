'use strict';

/*
 * data-subject.js -- data-subject access export (gather + seal).
 *
 * Gathers every personal record FireAlive holds about one subject into a single
 * bundle for a data-subject access request and, for the organization-initiated
 * analyst path, seals that bundle to the analyst's own X25519 public key so the
 * admin who runs the export holds only opaque ciphertext and only the analyst can
 * open it on their device.
 *
 * The seal reuses sealToPublicKey from analyst-crypto.js -- the same server-side
 * analyst-seal scheme that already protects analyst_private_data -- so the
 * Analyst Client opens an org-initiated export with the decrypt path it already
 * has, with no new recipient key and no second scheme. By design there is no
 * analyst private key anywhere on the server: the server can gather and seal but
 * never read analyst_private_data. The self-service path (handled by the route)
 * returns the bundle directly to the authenticated subject's own session.
 *
 * Functions take the db handle as a parameter; the route supplies it and writes
 * the audit entry.
 */

const { sealToPublicKey } = require('./analyst-crypto');

const EXPORT_SCHEMA = 'firealive.data-subject-export';
const EXPORT_VERSION = 1;

// Allow-list of users columns included in an access export: profile, status, and
// non-secret auth metadata. Credential and second-factor secrets are never
// exported (password_hash, totp_secret, totp_last_used_step,
// totp_recovery_codes_hashed are intentionally absent). Allow-list, not a
// blocklist: a column is exported only by being named here, so a column added to
// users in the future is excluded until it is deliberately added to this list.
const USER_EXPORT_COLUMNS = [
  'id',
  'username',
  'email',
  'role',
  'name',
  'pseudonym',
  'pseudonym_rotated_at',
  'tier',
  'shift',
  'available',
  'active',
  'capacity_score',
  'last_heartbeat',
  'last_iam_check',
  'offboarded_at',
  'auth_method',
  'external_id',
  'geo_country',
  'totp_enrolled_at',
  'mfa_enrollment_required',
  'totp_recovery_codes_remaining',
  'leaderboard_opt_in',
  'created_at',
  'updated_at',
  'last_login',
];

/*
 * gatherSubjectData(db, subjectId) -> bundle object
 *
 * Reads every personal record FireAlive holds about one subject of ANY role.
 * Shared sources (the users row, audit_log, notification_preferences) are
 * gathered for everyone. Analyst-only sources (analyst_private_data,
 * analyst_baselines, analyst_impacts, analyst_consent_log, analyst_availability,
 * analyst_keys) come back empty for a non-analyst because their analyst_id /
 * user_id matches nothing. Lead-oriented sources (lead_notification_contacts,
 * e2ee_identity_keys, abuse_review_keys registered by the subject) likewise come
 * back empty when they do not apply, so a single code path serves every role.
 *
 * analyst_private_data ciphertext stays sealed to the analyst's key (the server
 * cannot read it) and is returned base64-encoded; the e2ee identity public keys
 * and the abuse-review public keys are returned base64-encoded as well. Most
 * analyst tables key on analyst_id; analyst_availability, audit_log,
 * notification_preferences, lead_notification_contacts and e2ee_identity_keys
 * key on user_id (the same users.id value); abuse_review_keys keys on
 * registered_by. analyst_metrics_deidentified is deliberately not gathered: it
 * carries no subject identity and is outside the subject's personal-data scope.
 */
function gatherSubjectData(db, subjectId) {
  const user =
    db
      .prepare('SELECT ' + USER_EXPORT_COLUMNS.join(', ') + ' FROM users WHERE id = ?')
      .get(subjectId) || null;

  const privateData = db
    .prepare(
      "SELECT id, kind, ciphertext, key_version, recorded_at FROM analyst_private_data WHERE analyst_id = ? ORDER BY id"
    )
    .all(subjectId)
    .map(function mapReading(row) {
      return {
        id: row.id,
        kind: row.kind,
        key_version: row.key_version,
        recorded_at: row.recorded_at,
        ciphertext_b64: row.ciphertext == null ? null : Buffer.from(row.ciphertext).toString('base64'),
      };
    });

  const baselines =
    db
      .prepare(
        'SELECT analyst_id, cognitive_load, task_switching, queue_pressure, response_latency, break_compliance, shift_overtime, established_at, sample_count FROM analyst_baselines WHERE analyst_id = ?'
      )
      .get(subjectId) || null;

  const impacts = db
    .prepare('SELECT id, type, description, recorded_at FROM analyst_impacts WHERE analyst_id = ? ORDER BY id')
    .all(subjectId);

  const consentLog = db
    .prepare(
      'SELECT id, action, detail, created_at FROM analyst_consent_log WHERE analyst_id = ? ORDER BY created_at, id'
    )
    .all(subjectId);

  const availability = db
    .prepare(
      'SELECT id, week_start, slots_json, source_platform, last_synced_at, created_at, updated_at FROM analyst_availability WHERE user_id = ? ORDER BY week_start, id'
    )
    .all(subjectId);

  const auditLog = db
    .prepare('SELECT id, timestamp, event_type, detail, ip_address FROM audit_log WHERE user_id = ? ORDER BY id')
    .all(subjectId);

  const analystKey =
    db
      .prepare(
        'SELECT analyst_id, public_key, algo, key_version, status, created_at, updated_at FROM analyst_keys WHERE analyst_id = ?'
      )
      .get(subjectId) || null;

  const notificationPreferences = db
    .prepare(
      'SELECT user_id, event_type, in_app, email, updated_at FROM notification_preferences WHERE user_id = ? ORDER BY event_type'
    )
    .all(subjectId);

  const leadContact =
    db
      .prepare('SELECT user_id, email, phone, updated_at FROM lead_notification_contacts WHERE user_id = ?')
      .get(subjectId) || null;

  const e2eeIdentityKeys = db
    .prepare(
      'SELECT user_id, domain, identity_pubkey, registration_id, created_at FROM e2ee_identity_keys WHERE user_id = ? ORDER BY domain'
    )
    .all(subjectId)
    .map(function mapIdentityKey(row) {
      return {
        user_id: row.user_id,
        domain: row.domain,
        registration_id: row.registration_id,
        created_at: row.created_at,
        identity_pubkey_b64: row.identity_pubkey == null ? null : Buffer.from(row.identity_pubkey).toString('base64'),
      };
    });

  const abuseReviewKeys = db
    .prepare(
      'SELECT id, public_key, algo, label, fingerprint, registered_by, created_at, active FROM abuse_review_keys WHERE registered_by = ? ORDER BY created_at, id'
    )
    .all(subjectId)
    .map(function mapReviewKey(row) {
      return {
        id: row.id,
        algo: row.algo,
        label: row.label,
        fingerprint: row.fingerprint,
        registered_by: row.registered_by,
        created_at: row.created_at,
        active: row.active,
        public_key_b64: row.public_key == null ? null : Buffer.from(row.public_key).toString('base64'),
      };
    });

  return {
    schema: EXPORT_SCHEMA,
    version: EXPORT_VERSION,
    generated_at: new Date().toISOString(),
    subject_id: subjectId,
    user: user,
    analyst_key: analystKey,
    private_data: privateData,
    baselines: baselines,
    impacts: impacts,
    consent_log: consentLog,
    availability: availability,
    audit_log: auditLog,
    notification_preferences: notificationPreferences,
    lead_contact: leadContact,
    e2ee_identity_keys: e2eeIdentityKeys,
    abuse_review_keys: abuseReviewKeys,
  };
}

/*
 * sealBundleToAnalyst(db, analystId, bundle) -> sealed descriptor
 *
 * Organization-initiated path: seals the whole bundle to the analyst's active
 * X25519 public key with the analyst-seal scheme, so the admin who triggered the
 * export cannot read it and only the analyst can open it on their device. Throws
 * an error with code NO_ACTIVE_ANALYST_KEY when the analyst has no active key
 * (never enrolled, or crypto-erased).
 */
function sealBundleToAnalyst(db, analystId, bundle) {
  const key = db
    .prepare("SELECT public_key FROM analyst_keys WHERE analyst_id = ? AND status = 'active'")
    .get(analystId);
  if (!key || !key.public_key) {
    const err = new Error('subject has no active analyst key to seal an export to');
    err.code = 'NO_ACTIVE_ANALYST_KEY';
    throw err;
  }
  const sealed = sealToPublicKey(JSON.stringify(bundle), key.public_key);
  return {
    schema: EXPORT_SCHEMA + '.sealed',
    version: EXPORT_VERSION,
    subject_id: analystId,
    algo: 'x25519-hkdf-sha256-aes256gcm',
    sealed_b64: sealed,
  };
}

module.exports = {
  EXPORT_SCHEMA: EXPORT_SCHEMA,
  EXPORT_VERSION: EXPORT_VERSION,
  USER_EXPORT_COLUMNS: USER_EXPORT_COLUMNS,
  gatherSubjectData: gatherSubjectData,
  sealBundleToAnalyst: sealBundleToAnalyst,
};
