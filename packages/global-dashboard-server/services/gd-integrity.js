// ===========================================================================
// FIREALIVE GD SERVER -- Startup Integrity Check
//
// Twin of server/services/integrity.js (the Regional Server's check), built to
// the fixed FATAL-5a standard from the start: the manifest ships INSIDE the GD
// server directory so the GD app's extraResources rule
// (../global-dashboard-server -> global-dashboard-server) carries it into
// resources/global-dashboard-server/. The path is computed from __dirname,
// never read from a config row, so the packaged app resolves it with no
// build-config change. A missing manifest is fail-closed at boot in production
// by the gate in index.js -- never a silent pass.
//
// On boot, computes SHA-256 of every GD server source file and compares against
// the manifest. Any modified/missing/added file is a violation.
//
// Usage:
//   node packages/global-dashboard-server/services/gd-integrity.js --generate
//   node packages/global-dashboard-server/services/gd-integrity.js --verify
//   Called automatically by index.js on startup.
// ===========================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { version } = require('../package.json');

const GD_ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(GD_ROOT, 'integrity-manifest.json');

// The GD server's own code directories. Unlike the Regional Server there is no
// middleware/ or integrations/ directory; the GD's shipped code lives in
// routes/, services/, lib/ and tools/. data/ holds runtime/data files
// (fido-attestation-roots.json), not code, and is deliberately not scanned --
// the same as the Regional check, which scans no data directory either.
const SCAN_DIRS = ['routes', 'services', 'lib', 'tools'];

// The two top-level code files that sit at the GD server root.
const ROOT_FILES = ['index.js', 'db-init.js'];

// P1-6: pinned, security-critical DATA trust anchors that ship in the bundle and
// must not be swapped -- the FIDO2 attestation root CAs that gate hardware-passkey
// enrollment. Static seeds (admin-added roots go to the database, not this file;
// runtime data lives in ~/.firealive/), so the hash is stable across a release.
// Non-.js, so the SCAN_DIRS loop never reaches them; listed explicitly rather
// than by scanning data/, so a runtime-mutable file dropped in data/ can never
// silently join the manifest. Twin of the Regional check's DATA_FILES.
const DATA_FILES = ['fido-attestation-roots.json'];

function hashFile(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function collectFiles() {
  const files = {};

  for (const f of ROOT_FILES) {
    const p = path.join(GD_ROOT, f);
    if (fs.existsSync(p)) {
      files[`global-dashboard-server/${f}`] = hashFile(p);
    }
  }

  for (const dir of SCAN_DIRS) {
    const dirPath = path.join(GD_ROOT, dir);
    if (!fs.existsSync(dirPath)) continue;
    const entries = fs.readdirSync(dirPath).filter(f => f.endsWith('.js'));
    for (const f of entries) {
      const rel = `global-dashboard-server/${dir}/${f}`;
      files[rel] = hashFile(path.join(dirPath, f));
    }
  }

  // Pinned data trust anchors (see DATA_FILES).
  for (const f of DATA_FILES) {
    const p = path.join(GD_ROOT, 'data', f);
    if (fs.existsSync(p)) {
      files[`global-dashboard-server/data/${f}`] = hashFile(p);
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
    manifestHash: null,
  };
  const content = JSON.stringify({ ...manifest, manifestHash: undefined }, null, 2);
  manifest.manifestHash = crypto.createHash('sha256').update(content).digest('hex');

  // MANIFEST_PATH's parent is GD_ROOT, which always exists; no mkdir needed.
  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  console.log(`GD integrity manifest generated: ${manifest.fileCount} files`);
  return manifest;
}

function verifyIntegrity() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    return {
      valid: false,
      error: 'No GD integrity manifest found. Run: node packages/global-dashboard-server/services/gd-integrity.js --generate',
      violations: [],
    };
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
  const current = collectFiles();
  const violations = [];

  for (const [file, expectedHash] of Object.entries(manifest.files)) {
    if (!current[file]) {
      violations.push({ file, type: 'MISSING', expected: expectedHash, actual: null });
    } else if (current[file] !== expectedHash) {
      violations.push({ file, type: 'MODIFIED', expected: expectedHash, actual: current[file] });
    }
  }

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
      console.log(`GD integrity check passed (${result.expectedFiles} files verified)`);
    } else {
      console.error('GD INTEGRITY VIOLATION DETECTED');
      if (result.error) console.error(`  ${result.error}`);
      for (const v of result.violations) {
        console.error(`  ${v.type}: ${v.file}`);
      }
      process.exit(1);
    }
  } else {
    console.log('Usage: node packages/global-dashboard-server/services/gd-integrity.js --generate | --verify');
  }
}

module.exports = { verifyIntegrity, generateManifest };
