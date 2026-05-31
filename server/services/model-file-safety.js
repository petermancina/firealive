// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Model-File Integrity & Safety Gate (orchestrator)
//
// Runs the layered gate over a model's files BEFORE the loader is allowed to read
// them, fail-closed, and records every layer's verdict to model_file_scan_log.
//
//   Layer 1  hash-pin       (verifyModel — pinned SHA-256; primary control)
//   Layer 2  signature      (optional; verifyModelSignature over the pinned digest)
//   Layer 3  GGUF format     (validateGguf — defang the in-process loader)
//   Layer 4  malware scan    (scanModelFileLocal — by-path local engine)
//
// Per file the layers run in order and SHORT-CIRCUIT on the first failure (so the
// expensive malware scan only runs once hash/sig/format pass). The model is
// allowed to load only if every file reaches 'loaded'. A byte-stable file already
// gated clean is cached by SHA-256 so repeated loads skip layers 2–4.
//
// verifyModelFileSafety(modelId, opts?) -> Promise<{
//   ok, overall, blockedReason, hashStatus, modelId, perFile[]
// }>
// overall / per-file: 'loaded' | 'blocked_hash' | 'blocked_signature'
//                   | 'blocked_format' | 'blocked_malware' | 'blocked_no_scanner' | 'error'
//
// All collaborators are injectable via opts.deps for testing.
// ═══════════════════════════════════════════════════════════════════════════════

const cache = new Map(); // sha256 -> { ok:true, at, summary }

function resolveDeps(opts) {
  const d = (opts && opts.deps) || {};
  return {
    verifyModel: d.verifyModel || ((id) => require('../../scripts/download-model').verifyModel(id)),
    verifyModelSignature: d.verifyModelSignature || require('./model-signature').verifyModelSignature,
    validateGguf: d.validateGguf || require('./gguf-validate').validateGguf,
    scanModelFileLocal: d.scanModelFileLocal || require('./model-malware-scan').scanModelFileLocal,
    getDb: d.getDb || (() => require('../db/init').getDb()),
  };
}

const b01 = (v) => (v ? 1 : 0);
const nb01 = (v) => (v === null || v === undefined ? null : (v ? 1 : 0));
const short = (h) => (h ? String(h).slice(0, 12) : 'none');

async function verifyModelFileSafety(modelId, opts) {
  opts = opts || {};
  const D = resolveDeps(opts);
  const actor = opts.actor || 'system';

  let v;
  try { v = await D.verifyModel(modelId); }
  catch (e) {
    return { ok: false, overall: 'error', blockedReason: 'hash verification failed: ' + e.message, hashStatus: 'error', modelId, perFile: [] };
  }
  if (!v || !Array.isArray(v.files)) {
    return { ok: false, overall: 'error', blockedReason: 'verifyModel returned no file list (status ' + (v && v.status) + ')', hashStatus: (v && v.status) || 'error', modelId, perFile: [] };
  }

  const perFile = [];
  let overall = 'loaded';
  let blockedReason = null;

  for (const f of v.files) {
    const fr = await evaluateFile(modelId, f, D, opts);
    perFile.push(fr);
    logRow(D, modelId, fr, actor);
    if (fr.overall !== 'loaded' && overall === 'loaded') {
      overall = fr.overall;
      blockedReason = fr.reason;
    }
  }

  return { ok: overall === 'loaded', overall, blockedReason, hashStatus: v.status, modelId, perFile };
}

async function evaluateFile(modelId, f, D, opts) {
  const fr = {
    filename: f.filename, path: f.path, sha256: f.actual || null,
    hashPinOk: !!f.match, signatureChecked: false, signatureOk: null, signer: null,
    formatOk: null, malwareScanner: null, malwareOutcome: null, threats: [],
    overall: 'loaded', reason: null, cached: false,
  };

  // Layer 1 — hash-pin (verdict already computed by verifyModel)
  if (!f.present) { fr.overall = 'blocked_hash'; fr.reason = 'model file missing: ' + f.filename; return fr; }
  if (!f.match) { fr.overall = 'blocked_hash'; fr.reason = `sha256 mismatch (pinned ${short(f.expected)}, got ${short(f.actual)})`; return fr; }

  // Cache — byte-stable file already passed all layers this process lifetime.
  if (!opts.noCache && f.actual && cache.has(f.actual) && cache.get(f.actual).ok) {
    const s = cache.get(f.actual).summary;
    return Object.assign(fr, s, { overall: 'loaded', reason: 'cached clean', cached: true });
  }

  // Layer 2 — signature / provenance (optional)
  const sig = D.verifyModelSignature({ filePath: f.path, sha256: f.actual, modelId }, opts.signatureOpts);
  fr.signatureChecked = !!sig.checked;
  fr.signatureOk = sig.checked ? !!sig.ok : null;
  fr.signer = sig.signer || null;
  if (sig.checked && !sig.ok) { fr.overall = 'blocked_signature'; fr.reason = 'signature: ' + sig.reason; return fr; }

  // Layer 3 — GGUF format validation (GGUF files only)
  if (/\.gguf$/i.test(f.filename)) {
    const fmt = D.validateGguf(f.path, opts.formatOpts);
    fr.formatOk = !!fmt.ok;
    if (!fmt.ok) { fr.overall = 'blocked_format'; fr.reason = `gguf format: ${fmt.reason} (${fmt.code})`; return fr; }
  }

  // Layer 4 — malware scan (by-path local engine)
  const mal = await D.scanModelFileLocal(f.path, opts.malwareOpts);
  fr.malwareScanner = mal.scanner || null;
  fr.threats = mal.threats || [];
  if (mal.noScanner) { fr.malwareOutcome = 'skipped'; fr.overall = 'blocked_no_scanner'; fr.reason = 'no local malware scanner available'; return fr; }
  if (mal.error) { fr.malwareOutcome = 'error'; fr.overall = 'blocked_malware'; fr.reason = 'scan error: ' + mal.reason; return fr; }
  if (!mal.clean) { fr.malwareOutcome = 'threat'; fr.overall = 'blocked_malware'; fr.reason = 'malware detected: ' + (mal.threats || []).join('; '); return fr; }
  fr.malwareOutcome = 'clean';

  // All layers passed.
  fr.overall = 'loaded'; fr.reason = null;
  if (f.actual) {
    cache.set(f.actual, {
      ok: true, at: Date.now(),
      summary: { signatureChecked: fr.signatureChecked, signatureOk: fr.signatureOk, signer: fr.signer, formatOk: fr.formatOk, malwareScanner: fr.malwareScanner, malwareOutcome: fr.malwareOutcome },
    });
  }
  return fr;
}

function logRow(D, modelId, fr, actor) {
  let db;
  try {
    db = D.getDb();
    db.prepare(
      `INSERT INTO model_file_scan_log
        (model_id, file_name, sha256, hash_pin_ok, signature_checked, signature_ok,
         format_ok, malware_scanner, malware_outcome, threats, overall_outcome, detail, actor)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      modelId, fr.filename, fr.sha256,
      b01(fr.hashPinOk), b01(fr.signatureChecked), nb01(fr.signatureOk),
      nb01(fr.formatOk), fr.malwareScanner, fr.malwareOutcome,
      JSON.stringify(fr.threats || []), fr.overall, fr.reason, actor
    );
  } catch (_) {
    // Best-effort audit; a logging failure must not break the gate.
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
}

function _clearCache() { cache.clear(); }

module.exports = { verifyModelFileSafety, _clearCache };
