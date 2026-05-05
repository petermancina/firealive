#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Sub-package version sync script
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Reads the version field from the root package.json and writes it into each
// sub-package's package.json where the version differs. Preserves all other
// formatting in the target files by doing a targeted regex replacement on the
// version field rather than a JSON parse + re-stringify, which would lose
// hand-authored indentation, key order, or trailing newlines.
//
// Run by .github/workflows/sync-versions.yml on every branch push (except
// pushes to main and tag pushes). The workflow auto-commits any changes back
// to the same branch, so a contributor only needs to edit the root package.json
// when bumping a project version.
//
// Run manually: `node scripts/sync-versions.js`
//
// Exit codes:
//   0 — sync completed (with or without changes)
//   1 — root package.json missing or has no version field
//
// The packages/global-dashboard-server sub-package is intentionally NOT in
// the sync list. It is an independent component with its own version string
// and lifecycle.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ROOT_PKG = path.join(ROOT, 'package.json');

const SUB_PACKAGES = [
  'frontend/package.json',
  'packages/analyst-client/package.json',
  'packages/global-dashboard/package.json',
];

function getRootVersion() {
  if (!fs.existsSync(ROOT_PKG)) {
    console.error('Error: root package.json not found at ' + ROOT_PKG);
    process.exit(1);
  }
  const root = JSON.parse(fs.readFileSync(ROOT_PKG, 'utf8'));
  if (!root.version) {
    console.error('Error: root package.json has no version field');
    process.exit(1);
  }
  return root.version;
}

// Read just the version field from a package.json without parsing the full
// file. Used so other formatting differences (whitespace, key order, trailing
// newline) do not get reported as a version change.
function readVersionField(content) {
  const m = content.match(/"version"\s*:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

// Replace the first version field's value with the given version. Preserves
// the original spacing inside the field declaration and leaves all other
// content untouched.
function setVersionField(content, newVersion) {
  return content.replace(
    /("version"\s*:\s*")([^"]*)(")/,
    (match, p1, _oldVersion, p3) => p1 + newVersion + p3
  );
}

function main() {
  const rootVersion = getRootVersion();
  console.log('Root package.json version: ' + rootVersion);

  let changed = 0;
  for (const rel of SUB_PACKAGES) {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) {
      console.warn('[skip] ' + rel + ' not found');
      continue;
    }
    const oldContent = fs.readFileSync(abs, 'utf8');
    const oldVersion = readVersionField(oldContent);
    if (oldVersion === null) {
      console.warn('[skip] ' + rel + ' has no version field');
      continue;
    }
    if (oldVersion === rootVersion) {
      console.log('[ok]   ' + rel + ' already at ' + rootVersion);
      continue;
    }
    const newContent = setVersionField(oldContent, rootVersion);
    fs.writeFileSync(abs, newContent);
    console.log('[upd]  ' + rel + ': ' + oldVersion + ' -> ' + rootVersion);
    changed++;
  }

  console.log('');
  console.log('Done. ' + changed + ' file(s) updated.');
  process.exit(0);
}

main();
