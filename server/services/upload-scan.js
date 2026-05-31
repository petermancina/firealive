// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Upload Scan Pipeline (shared service)
//
// Extracted verbatim from server/routes/ooda.js so the two-layer upload scan can
// be reused outside the OODA routes. Behavior is UNCHANGED from the in-route
// version — ooda.js now imports runUploadScans + scanAuditFragment from here.
//
//   Layer 1 — content-sanitizer (sync, deterministic, network-free; text-domain
//             threats). Runs first; a layer-1 rejection short-circuits.
//   Layer 2 — anti-malware/EDR inspection via IntegrationManager.inspectFile
//             (the F4c priority-ordered dispatch over the configured malware
//             scanners). Runs only if layer 1 cleared.
//
// Note: this pipeline is content/Buffer-based and oriented at the OODA text
// uploads (policies/AARs). Binary AI model files are NOT scanned here — they are
// multi-GB and the configured cloud/sandbox scanners are size-limited; the
// model-file integrity & safety gate scans those by path with a local engine
// (see the model-file-safety path) rather than buffering them through layer 2.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { sanitize } = require('./content-sanitizer');
const { IntegrationManager } = require('./integration-manager');

async function runUploadScans(content, fileName, fileType) {
  // Layer 1 — sanitizer (sync, deterministic, network-free)
  const layer1 = sanitize(content, { fileName, fileType });
  if (!layer1.clean) {
    return { ok: false, layer1, layer2: null, rejectedBy: 'layer1' };
  }

  // Layer 2 — EDR (async; only runs if layer 1 cleared). The IntegrationManager
  // is instantiated per upload because it caches a db handle in this.db; we
  // open one, run the inspection, close it.
  const db = getDb();
  let layer2;
  try {
    const mgr = new IntegrationManager(db);
    layer2 = await mgr.inspectFile(content, fileName, fileType);
  } finally {
    db.close();
  }
  if (!layer2.clean) {
    return { ok: false, layer1, layer2, rejectedBy: 'layer2' };
  }
  return { ok: true, layer1, layer2, rejectedBy: null };
}

// Build the per-upload audit-log fragment that records both scan layers.
// Used in the OODA_POLICY_UPLOADED and OODA_AAR_UPLOADED detail strings.
function scanAuditFragment(scans) {
  const parts = [
    `sanitizer=${scans.layer1.sanitizerVersion}/${scans.layer1.scanId}`,
  ];
  if (scans.layer2 && scans.layer2.skipped) {
    parts.push('edr=skipped');
  } else if (scans.layer2) {
    parts.push(
      `edr=${scans.layer2.provider}/${scans.layer2.scanId || 'no-id'}`
        + ` (${scans.layer2.latencyMs}ms)`
    );
  }
  return parts.join(' ');
}

module.exports = { runUploadScans, scanAuditFragment };
