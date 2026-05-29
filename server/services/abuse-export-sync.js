// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-Export Sync (dumb relay, regional side, U4 PR 5-C)
//
// Moves the two-person legal-hold export across the regional <-> GD boundary
// WITHOUT being trusted: it carries only opaque signed blobs. It cannot forge a
// CISO decision (no CISO private key) and cannot usefully alter one (tampering
// breaks the signature). Two phases per tick:
//
//   PUSH  — relay pending requests to the GD ingest endpoint (api_key transport
//           auth, reusing gd_push_config like the metrics push). Idempotent on
//           the GD via (mc_id, request_id); mark gd_request_ref locally so a row
//           is pushed once.
//
//   POLL  — for pushed-but-undecided requests, pull the GD's status. When a
//           signed decision arrives, VERIFY it against the pinned CISO key
//           (defense in depth — the reviewer's device re-verifies authoritatively
//           before producing) and confirm the signed payload binds THIS request
//           and flag, THEN persist the token and chain LEGAL_HOLD_APPROVED/DENIED.
//           A decision that fails verification or binding is refused, not stored.
//
// No Management Console surface, no MC config of its own. The GD endpoint + api
// key are the existing gd_push_config transport; the channel's authenticity rests
// on the CISO key (inbound) and is independent of that transport.
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('./logger');
const { decrypt } = require('./encryption');
const { validateAllowedHost } = require('./gd-allow-list');
const avChain = require('./abuse-vault-chain');
const cisoTrust = require('./abuse-export-ciso-trust');

const PUSH_TIMEOUT_MS = 10000;
const POLL_TIMEOUT_MS = 10000;

function decryptApiKey(encryptedBase64) {
  return decrypt(Buffer.from(encryptedBase64, 'base64'), 'TIER1_ENCRYPTION_KEY');
}

function loadGdConfig(db) {
  return db.prepare('SELECT * FROM gd_push_config WHERE id = 1').get();
}

async function postJson(url, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      redirect: 'error',
    });
    const text = await resp.text();
    let body;
    try { body = JSON.parse(text); } catch (e) { body = { error: text.slice(0, 200) }; }
    return { status: resp.status, body };
  } finally {
    clearTimeout(timer);
  }
}

// PUSH: relay pending requests not yet sent. Marks gd_request_ref on success.
async function pushPendingRequests(db, { endpointBase, apiKey }) {
  const rows = db.prepare(`
    SELECT id, flag_id, requested_by_user_id, request_reason,
           request_payload_canonical, request_signature, request_key_fingerprint
    FROM abuse_vault_export_requests
    WHERE status = 'pending' AND gd_request_ref IS NULL
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY requested_at ASC
  `).all();
  let pushed = 0;
  for (const row of rows) {
    const url = endpointBase + '/api/mc/abuse-export/ingest';
    try {
      const { status, body } = await postJson(url, {
        apiKey,
        requestId: row.id,
        flagId: row.flag_id,
        requestedBy: row.requested_by_user_id,
        requestReason: row.request_reason,
        requestPayloadCanonical: row.request_payload_canonical,
        requestSignature: row.request_signature,
        requestKeyFingerprint: row.request_key_fingerprint,
      }, PUSH_TIMEOUT_MS);
      if (status >= 200 && status < 300 && body && !body.error) {
        db.prepare('UPDATE abuse_vault_export_requests SET gd_request_ref = ? WHERE id = ?')
          .run(String(body.id != null ? body.id : 'pushed'), row.id);
        pushed++;
      } else {
        logger.warn('abuse-export-sync: push rejected', { requestId: row.id, status, error: body && body.error });
      }
    } catch (e) {
      logger.warn('abuse-export-sync: push network failure', { requestId: row.id, error: e.message });
    }
  }
  return { pushed, candidates: rows.length };
}

// POLL: pull decisions for pushed-but-undecided requests; verify + bind-check
// before persisting; chain the outcome.
async function pollDecisions(db, { endpointBase, apiKey }) {
  const rows = db.prepare(`
    SELECT id, flag_id FROM abuse_vault_export_requests
    WHERE status = 'pending' AND gd_request_ref IS NOT NULL
    ORDER BY requested_at ASC
  `).all();
  let decided = 0;
  for (const row of rows) {
    const url = endpointBase + '/api/mc/abuse-export/status';
    let status, body;
    try {
      ({ status, body } = await postJson(url, { apiKey, requestId: row.id }, POLL_TIMEOUT_MS));
    } catch (e) {
      logger.warn('abuse-export-sync: poll network failure', { requestId: row.id, error: e.message });
      continue;
    }
    if (status < 200 || status >= 300 || !body || body.error) continue;
    if (body.status !== 'approved' && body.status !== 'denied') continue; // still pending

    const d = body.decision;
    if (!d || !d.payloadCanonical || !d.signature || !d.keyFingerprint) {
      logger.warn('abuse-export-sync: decision missing signature fields', { requestId: row.id });
      continue;
    }
    // Defense in depth: verify the CISO signature against the pinned key. The
    // reviewer's device performs the authoritative verification at produce time.
    const sigOk = cisoTrust.verifyWithPinnedKey(db, {
      fingerprint: d.keyFingerprint,
      messageBytes: Buffer.from(d.payloadCanonical, 'utf8'),
      signatureHex: d.signature,
    });
    if (!sigOk) {
      logger.error('abuse-export-sync: decision signature did NOT verify against pinned CISO key; refusing to record', { requestId: row.id, keyFingerprint: d.keyFingerprint });
      continue;
    }
    // Confirm the signed payload binds THIS request, flag, and decision.
    let parsed;
    try { parsed = JSON.parse(d.payloadCanonical); } catch (e) { parsed = null; }
    if (!parsed || parsed.request_id !== String(row.id) || parsed.flag_id !== String(row.flag_id) || parsed.decision !== body.status) {
      logger.error('abuse-export-sync: decision payload does not bind this request; refusing', { requestId: row.id });
      continue;
    }

    const isApproved = body.status === 'approved';
    try {
      db.transaction(() => {
        if (isApproved) {
          db.prepare(`
            UPDATE abuse_vault_export_requests
            SET status = 'approved', approval_decision = 'approved',
                approval_payload_canonical = ?, approval_signature = ?,
                approval_key_fingerprint = ?, approval_nonce = ?,
                approved_by = 'ciso(gd)', approved_at = ?
            WHERE id = ? AND status = 'pending'
          `).run(d.payloadCanonical, d.signature, d.keyFingerprint, d.nonce || null, d.decidedAt || null, row.id);
        } else {
          db.prepare(`
            UPDATE abuse_vault_export_requests
            SET status = 'denied', approval_decision = 'denied',
                approval_payload_canonical = ?, approval_signature = ?,
                approval_key_fingerprint = ?, approval_nonce = ?,
                denied_at = ?, denial_reason = ?
            WHERE id = ? AND status = 'pending'
          `).run(d.payloadCanonical, d.signature, d.keyFingerprint, d.nonce || null, d.decidedAt || null, d.denialReason || null, row.id);
        }
        try {
          avChain.appendEntry(db, {
            eventType: isApproved ? 'LEGAL_HOLD_APPROVED' : 'LEGAL_HOLD_DENIED',
            flagId: row.flag_id,
            requestRef: String(row.id),
            actorUserId: 'ciso(gd):' + d.keyFingerprint.slice(0, 16),
          });
        } catch (avErr) {
          logger.warn('abuse-export-sync: chain append failed', { requestId: row.id, error: avErr.message });
        }
      })();
      decided++;
    } catch (e) {
      logger.error('abuse-export-sync: failed to record decision', { requestId: row.id, error: e.message });
    }
  }
  return { decided, candidates: rows.length };
}

// One tick: load config, SSRF-guard the endpoint, decrypt the key, push + poll.
async function runSyncTick(db) {
  const config = loadGdConfig(db);
  if (!config || config.enabled !== 1 || !config.endpoint_url || !config.api_key_encrypted) {
    return { skipped: 'gd push not configured' };
  }
  let host;
  try { host = new URL(config.endpoint_url).hostname; } catch (e) { return { skipped: 'bad endpoint_url' }; }
  const allowed = validateAllowedHost(host);
  if (!allowed.ok) {
    logger.warn('abuse-export-sync: endpoint host not allowed', { host, error: allowed.error });
    return { skipped: 'host not allowed' };
  }
  let apiKey;
  try { apiKey = decryptApiKey(config.api_key_encrypted); } catch (e) {
    logger.error('abuse-export-sync: api_key decrypt failed', { error: e.message });
    return { skipped: 'key decrypt failed' };
  }
  const endpointBase = config.endpoint_url.replace(/\/+$/, '');
  const push = await pushPendingRequests(db, { endpointBase, apiKey });
  const poll = await pollDecisions(db, { endpointBase, apiKey });
  return { push, poll };
}

module.exports = { decryptApiKey, loadGdConfig, pushPendingRequests, pollDecisions, runSyncTick };
