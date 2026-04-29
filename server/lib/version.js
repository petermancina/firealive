// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Canonical Version Module
//
// Single source of truth for application version, anti-rollback fuse counter,
// and build identifier. All server-side code that needs to report version
// information MUST require this module rather than hardcoding strings.
//
// The values are read from package.json at startup. The version module is
// the only place in the codebase that reads package.json for version data.
// ═══════════════════════════════════════════════════════════════════════════════

const path = require('path');

const pkg = require(path.join(__dirname, '..', '..', 'package.json'));

if (typeof pkg.version !== 'string' || !pkg.version) {
  throw new Error('package.json is missing a "version" field');
}

if (typeof pkg.fuseCounter !== 'number') {
  throw new Error('package.json is missing a numeric "fuseCounter" field — required for anti-rollback');
}

const version = pkg.version;
const fuseCounter = pkg.fuseCounter;
const buildId = typeof pkg.buildId === 'string' ? pkg.buildId : null;

// Convenience labels for log lines and CEF fields
const versionLabel = `v${version}`;
const cefDeviceVersion = version;

module.exports = {
  version,
  versionLabel,
  fuseCounter,
  buildId,
  cefDeviceVersion,
};
