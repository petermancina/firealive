// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Upload Scan Pipeline (shared service)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// The two-layer upload security pipeline for the GD, the GD twin of the Regional
// Server's upload-scan. Used by the config-baseline import to scan an uploaded
// bundle before it is parsed and applied; both layers must pass (fail-closed).
//
//   Layer 1 -- content sanitizer (sync, deterministic, network-free; text-domain
//             threats). Runs first; a layer-1 rejection short-circuits.
//   Layer 2 -- anti-malware / EDR inspection via IntegrationManager.inspectFile
//             (the priority-ordered dispatch over the configured malware
//             scanners). Runs only if layer 1 cleared.
//
// This pipeline is content/Buffer-based. Restore scans of raw SQLite database
// bytes go through IntegrationManager.inspectFile directly (layer 2 only -- a
// database file is not text), not through this text-oriented wrapper.
// -----------------------------------------------------------------------------

const { getDb } = require('../db-init');
const { sanitize } = require('./gd-content-sanitizer');
const { IntegrationManager } = require('./gd-integration-manager');

// opts (optional): { scanMode } - forwarded to layer 2 (inspectFile) to override
// the deployment's malware scan mode for this upload. The config-baseline import
// passes { scanMode: 'all_configured' } so every configured scanner must clear
// it; omit opts for the default behavior.
async function runUploadScans(content, fileName, fileType, opts = {}) {
  // Layer 1 -- sanitizer (sync, deterministic, network-free)
  const layer1 = sanitize(content, { fileName, fileType });
  if (!layer1.clean) {
    return { ok: false, layer1, layer2: null, rejectedBy: 'layer1' };
  }

  // Layer 2 -- EDR (async; only runs if layer 1 cleared). The IntegrationManager
  // is instantiated per upload because it caches a db handle; open one, run the
  // inspection, close it.
  const db = getDb();
  let layer2;
  try {
    const mgr = new IntegrationManager(db);
    layer2 = await mgr.inspectFile(content, fileName, fileType, opts);
  } finally {
    db.close();
  }
  if (!layer2.clean) {
    return { ok: false, layer1, layer2, rejectedBy: 'layer2' };
  }
  return { ok: true, layer1, layer2, rejectedBy: null };
}

// Build the per-upload audit-log fragment that records both scan layers.
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
