#!/usr/bin/env node
//
// FIREALIVE -- Config-Lock Coverage Guard (CI)
//
// Fails the build if the config-write route registry has drifted from the
// codebase. The config lock is only as strong as the registry it gates from,
// so this guard enforces three invariants:
//
//   A. COVERAGE  -- every config-settings endpoint (a PUT whose path ends in
//      "config") declared in the mixed feature routers is in the registry.
//      Catches: a new config endpoint added without gating it.
//
//   B. NO STALE  -- every CONFIG_WRITE_PATHS entry corresponds to a real route.
//      Catches: a removed/renamed route or a typo'd registry path.
//
//   C. WIRING    -- every registered mount prefix and every feature router is
//      actually applied with configLockChokepoint() in server/index.js.
//      Catches: a registered route that is not behind the chokepoint.
//
// Run:  node scripts/check-config-lock-coverage.js
// Exits non-zero (failing CI) with a list of problems, or 0 when consistent.
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SERVER = path.join(ROOT, 'server');

const {
  CONFIG_WRITE_MOUNTS,
  CONFIG_WRITE_PATHS,
  isConfigWriteRequest,
} = require(path.join(SERVER, 'middleware', 'config-write-routes.js'));

const failures = [];
const fail = (m) => failures.push(m);

// Mixed routers (config writes interleaved with operational actions) whose
// config endpoints are represented in the registry at the endpoint level. Each
// is paired with the mount prefix it is applied at in server/index.js so a
// route's full /api path can be reconstructed. The v0NN feature routers mount
// at the bare /api; the dedicated HA router mounts at /api/ha and is a mixed
// router too -- its sole config write (PUT /api/ha/config) is gated by an
// endpoint entry, not by prefix, so the emergency manual-failover /
// test-failover / pair actions on the same router stay ungated.
const FEATURE_IDS = ['021', '022', '023', '024', '025', '027', '030'];
const MIXED_ROUTERS = [
  ...FEATURE_IDS.map((n) => ({
    file: path.join(SERVER, 'routes', `v${n}-features.js`),
    mount: '/api',
    label: `v${n}-features`,
  })),
  { file: path.join(SERVER, 'routes', 'ha.js'), mount: '/api/ha', label: 'ha' },
  { file: path.join(SERVER, 'routes', 'auto-update.js'), mount: '/api/auto-update', label: 'auto-update' },  // B5r: detect-and-notify update router (PUT /config gated; check-now/status pass through)
];

const ROUTE_RE = /router\.(put|post|patch|delete)\(\s*['"]([^'"]+)['"]/g;

function routesIn(file) {
  const src = fs.readFileSync(file, 'utf8');
  const out = [];
  let m;
  while ((m = ROUTE_RE.exec(src)) !== null) {
    out.push({ method: m[1].toUpperCase(), rel: m[2] });
  }
  return out;
}

// Gather every mutating route in the mixed routers as full /api paths.
const featureRoutes = [];
for (const r of MIXED_ROUTERS) {
  if (!fs.existsSync(r.file)) {
    fail(`mixed router missing: ${path.relative(ROOT, r.file)}`);
    continue;
  }
  for (const route of routesIn(r.file)) {
    featureRoutes.push({
      method: route.method,
      fullPath: r.mount + route.rel,
      file: r.file,
    });
  }
}

// CHECK A: config-settings endpoints (PUT .../config) must be in the registry.
// Operational POSTs that merely mention "config" (e.g. propagate-config) are
// excluded by the PUT requirement and must NOT be gated.
for (const r of featureRoutes) {
  const looksConfig = r.method === 'PUT' && /config$/i.test(r.fullPath);
  if (looksConfig && !isConfigWriteRequest(r.method, r.fullPath)) {
    fail(
      `config endpoint not gated: ${r.method} ${r.fullPath} ` +
        `(${path.relative(ROOT, r.file)}) -- add it to CONFIG_WRITE_PATHS`
    );
  }
}

// CHECK B: no stale registry entries.
const declared = new Set(featureRoutes.map((r) => r.method + ' ' + r.fullPath));
for (const e of CONFIG_WRITE_PATHS) {
  if (!declared.has(e.method + ' ' + e.path)) {
    fail(
      `stale registry entry (no matching route): ${e.method} ${e.path} ` +
        '-- remove it or fix the path'
    );
  }
}

// CHECK C: every registered mount + feature router is wired with the chokepoint.
const indexLines = fs
  .readFileSync(path.join(SERVER, 'index.js'), 'utf8')
  .split('\n');

for (const mount of CONFIG_WRITE_MOUNTS) {
  const line = indexLines.find(
    (l) => l.includes(`'${mount}'`) && l.includes('app.use(')
  );
  if (!line) {
    fail(`config mount not found in index.js: ${mount}`);
  } else if (!line.includes('configLockChokepoint()')) {
    fail(`config mount not gated by chokepoint in index.js: ${mount}`);
  }
}

for (const n of FEATURE_IDS) {
  const needle = `require('./routes/v${n}-features')`;
  const line = indexLines.find((l) => l.includes(needle));
  if (!line) {
    fail(`feature router mount not found in index.js: v${n}-features`);
  } else if (!line.includes('configLockChokepoint()')) {
    fail(`feature router not gated by chokepoint in index.js: v${n}-features`);
  }
}

// The HA mixed router is mounted by property (ha.configRouter) rather than by a
// require() expression, so it is checked explicitly: its config mount must sit
// behind the chokepoint, keeping PUT /api/ha/config gated.
const haMount = indexLines.find(
  (l) => l.includes('ha.configRouter') && l.includes('app.use(')
);
if (!haMount) {
  fail('HA config router mount not found in index.js: ha.configRouter');
} else if (!haMount.includes('configLockChokepoint()')) {
  fail('HA config router not gated by chokepoint in index.js: ha.configRouter');
}

if (failures.length > 0) {
  console.error('Config-lock coverage guard FAILED:');
  for (const f of failures) console.error('  - ' + f);
  console.error(
    `\n${failures.length} problem(s). The config lock must gate every config ` +
      'write; update server/middleware/config-write-routes.js and/or the wiring.'
  );
  process.exit(1);
}

console.log(
  'Config-lock coverage guard passed: ' +
    `${CONFIG_WRITE_MOUNTS.length} mount(s) + ${CONFIG_WRITE_PATHS.length} ` +
    'config path(s); coverage, registry, and wiring consistent.'
);
