// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Local Deployment Mode (D9)
//
// Per-installation record of the operator's deployment-mode selection, made
// at first run before enrollment (so it cannot yet come from the server).
// This is advisory and client-side: it lets the app apply the right
// virtualization tolerances locally. The authoritative, tamper-evident mode
// lives server-side (services/deployment-mode) and remains the security
// boundary; a later check can reconcile the local selection against it.
//
// Stored as a small plain JSON file under the app's userData (the selection
// is not a secret), mirroring the CA-pin storage pattern. Shared by all four
// desktop apps; each passes its own userData path.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');

const BARE_METAL = 'bare-metal';
const VIRTUALIZED = 'virtualized';
const MODES = [BARE_METAL, VIRTUALIZED];

function makeLocalMode(filePath) {
  function read() {
    try {
      const obj = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (obj && MODES.indexOf(obj.mode) !== -1) return obj;
      return null;
    } catch (_e) {
      return null;
    }
  }
  return {
    // The selected mode, or null if first-run selection has not happened.
    getMode() { const o = read(); return o ? o.mode : null; },
    isConfigured() { return read() !== null; },
    isVirtualized() { const o = read(); return !!o && o.mode === VIRTUALIZED; },
    // Record the first-run selection. The local record is advisory, so
    // re-selection overwrites.
    setMode(mode) {
      if (MODES.indexOf(mode) === -1) throw new Error('invalid deployment mode: ' + mode);
      const rec = { mode: mode, selectedAt: new Date().toISOString() };
      fs.writeFileSync(filePath, JSON.stringify(rec), { mode: 0o600 });
      return rec;
    },
    filePath: filePath,
    MODES: MODES
  };
}

module.exports = { makeLocalMode, MODES, BARE_METAL, VIRTUALIZED };
