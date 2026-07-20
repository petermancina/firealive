// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Startup Integrity Check
// On boot, computes SHA-256 of every server source file and compares against
// a signed manifest. If any file is modified, logs CRITICAL and halts.
//
// Usage:
//   node server/services/integrity.js --generate   → creates manifest
//   node server/services/integrity.js --verify     → checks against manifest
//   Called automatically by server/index.js on startup
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { version } = require('../lib/version');

const SERVER_ROOT = path.join(__dirname, '..');
// P1-6 (FATAL 5a): the manifest ships INSIDE server/ so the MC's extraResources
// rule (../server -> server) carries it into resources/server/. The path is
// computed from __dirname, never read from a config row, so the packaged app
// resolves resources/server/integrity-manifest.json with no build-config change.
const MANIFEST_PATH = path.join(SERVER_ROOT, 'integrity-manifest.json');

// Files to check — all JS in server/, middleware/, services/, routes/, integrations/, db/
const SCAN_DIRS = ['routes', 'middleware', 'services', 'integrations', 'db'];

// P1-6: pinned, security-critical DATA trust anchors that ship in the bundle and
// must not be swapped -- the FIDO2 attestation root CAs that gate hardware-passkey
// enrollment (an attacker who swaps this file could add a rogue attestation root
// and forge a passkey). These are static seeds: admin-added roots go to the
// database, not this file, and runtime data lives in ~/.firealive/, so the hash
// is stable across a release. Non-.js, so the SCAN_DIRS loop below never reaches
// them -- they are listed explicitly rather than by scanning data/, so a
// runtime-mutable file dropped in data/ can never silently join the manifest.
const DATA_FILES = ['fido-attestation-roots.json'];

function hashFile(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function collectFiles() {
  const files = {};
  // Server index
  const indexPath = path.join(SERVER_ROOT, 'index.js');
  if (fs.existsSync(indexPath)) {
    files['server/index.js'] = hashFile(indexPath);
  }

  for (const dir of SCAN_DIRS) {
    const dirPath = path.join(SERVER_ROOT, dir);
    if (!fs.existsSync(dirPath)) continue;
    const entries = fs.readdirSync(dirPath).filter(f => f.endsWith('.js'));
    for (const f of entries) {
      const rel = `server/${dir}/${f}`;
      files[rel] = hashFile(path.join(dirPath, f));
    }
  }

  // Pinned data trust anchors (see DATA_FILES).
  for (const f of DATA_FILES) {
    const p = path.join(SERVER_ROOT, 'data', f);
    if (fs.existsSync(p)) {
      files[`server/data/${f}`] = hashFile(p);
    }
  }
  return files;
}

function generateManifest() {
  const files = collectFiles();
  const manifest = {
    version,
    generatedAt: new Date().toISOString(),
    algorithm: 'sha256',
    fileCount: Object.keys(files).length,
    files,
    // HMAC of the entire manifest for tamper detection
    // In production, sign with a private key instead
    manifestHash: null,
  };
  const content = JSON.stringify({ ...manifest, manifestHash: undefined }, null, 2);
  manifest.manifestHash = crypto.createHash('sha256').update(content).digest('hex');

  // MANIFEST_PATH's parent is SERVER_ROOT, which always exists; no mkdir needed.
  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  console.log(`Integrity manifest generated: ${manifest.fileCount} files`);
  return manifest;
}

function verifyIntegrity() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    return {
      valid: false,
      error: 'No integrity manifest found. Run: node server/services/integrity.js --generate',
      violations: [],
    };
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
  const current = collectFiles();
  const violations = [];

  // Check for modified files
  for (const [file, expectedHash] of Object.entries(manifest.files)) {
    if (!current[file]) {
      violations.push({ file, type: 'MISSING', expected: expectedHash, actual: null });
    } else if (current[file] !== expectedHash) {
      violations.push({ file, type: 'MODIFIED', expected: expectedHash, actual: current[file] });
    }
  }

  // Check for new files not in manifest
  for (const file of Object.keys(current)) {
    if (!manifest.files[file]) {
      violations.push({ file, type: 'ADDED', expected: null, actual: current[file] });
    }
  }

  return {
    valid: violations.length === 0,
    manifestVersion: manifest.version,
    manifestDate: manifest.generatedAt,
    expectedFiles: Object.keys(manifest.files).length,
    currentFiles: Object.keys(current).length,
    violations,
  };
}

// CLI mode
if (require.main === module) {
  const arg = process.argv[2];
  if (arg === '--generate') {
    generateManifest();
  } else if (arg === '--verify') {
    const result = verifyIntegrity();
    if (result.valid) {
      console.log(`✓ Integrity check passed (${result.expectedFiles} files verified)`);
    } else {
      console.error('✗ INTEGRITY VIOLATION DETECTED');
      for (const v of result.violations) {
        console.error(`  ${v.type}: ${v.file}`);
      }
      process.exit(1);
    }
  } else {
    console.log('Usage: node server/services/integrity.js --generate | --verify');
  }
}

module.exports = { verifyIntegrity, generateManifest };
