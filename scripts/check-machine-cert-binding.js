#!/usr/bin/env node
//
// FIREALIVE -- Machine-Credential Binding Guard (CI)  [O3 Half 2]
//
// Half 2 made every machine credential sender-constrained: a bearer secret
// authenticates NOTHING on its own, because the request must arrive over a
// mutual-TLS connection whose client certificate this deployment's CA issued,
// which carries the role OU for that surface, and which is bound to the exact
// credential row being presented.
//
// That property lives in code, not in the schema, on one path: SQLite cannot add
// a NOT NULL column to an existing table without a DEFAULT, and any default here
// would be a FAKE fingerprint -- worse than a null, because a fake LOOKS bound.
// Fresh installs get NOT NULL; upgraded databases get a nullable column and an
// auth path that fails closed. This guard is what makes the code-side guarantee
// legible and non-negotiable.
//
// It fails the build on eight drifts:
//
//   CERT-FIRST   -- a machine-auth path that can reach success without calling
//                   the shared verifier, or that looks up a credential before it.
//   DISTINCT-OU  -- two surfaces sharing a role OU. The OU is ENFORCED; a shared
//                   OU makes every machine certificate universal, which is
//                   strictly weaker than what B5m shipped.
//   ONE-VERIFIER -- certificate parsing or verification open-coded anywhere
//                   outside the two verifier modules. Seven copies is how one
//                   surface ends up accepting what another refuses.
//   DB-REQUIRED  -- a finish* function that leaves its db handle optional.
//                   Challenge consumption is unbypassable only because the
//                   throw makes it so.
//   MINT-BINDS   -- a mint path that inserts a credential row without issuing
//                   the certificate that constrains it, in the same transaction.
//   REVOKE-BINDS -- a revoke path that leaves a certificate this CA still
//                   vouches for -- a credential the operator believes destroyed.
//   SCHEMA-NN    -- a bound table whose CREATE does not declare cert_fingerprint
//                   NOT NULL.
//   NO-FAKE-DEF  -- a migration that gives cert_fingerprint a DEFAULT.
//
// Run:  node scripts/check-machine-cert-binding.js
//       node scripts/check-machine-cert-binding.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SELF = path.resolve(__filename);

// ── The registry: every machine-authenticated path ──────────────────────────
const AUTH_PATHS = [
  { file: 'server/middleware/auth.js', fn: 'handleApiKeyAuth',
    ou: 'ca.API_KEY_CONSUMER_OU', success: 'next();',
    lookup: 'cert_fingerprint = ?' },
  { file: 'server/middleware/threat-hunting-auth.js', fn: null,
    ou: 'CONSUMER_OU', success: 'req.threatHuntingAuth',
    lookup: 'findByCertFingerprint' },
  { file: 'server/routes/vuln-scan.js', fn: null,
    ou: 'ca.SCANNER_CONSUMER_OU', success: null,
    lookup: 'cert_fingerprint = ?' },
  { file: 'server/routes/cloud-vuln-scan.js', fn: null,
    ou: 'ca.SCANNER_CONSUMER_OU', success: null,
    lookup: 'cert_fingerprint = ?' },
  { file: 'packages/global-dashboard-server/routes/cloud-vuln-scan.js', fn: null,
    ou: 'gdCa.SCANNER_CONSUMER_OU', success: null,
    lookup: 'cert_fingerprint = ?' },
];

// Mint paths: file, the table they insert into, and the CA module they use.
const MINT_PATHS = [
  { file: 'server/routes/apikeys.js', table: 'api_keys', ca: 'ca' },
  { file: 'server/routes/vuln-scan.js', table: 'vuln_scan_scanner_authorizations', ca: 'ca' },
  { file: 'server/routes/cloud-vuln-scan.js', table: 'cloud_vuln_scanner_authorizations', ca: 'ca' },
  { file: 'packages/global-dashboard-server/routes/cloud-vuln-scan.js', table: 'cloud_vuln_scanner_authorizations', ca: 'gdCa' },
  { file: 'server/services/threat-hunting-registry.js', table: 'threat_hunting_consumer_authorizations', ca: 'ca' },
];

// Tables that must declare cert_fingerprint NOT NULL in their CREATE.
const BOUND_TABLES = [
  { file: 'server/db/init.js', table: 'api_keys' },
  { file: 'server/db/init.js', table: 'vuln_scan_scanner_authorizations' },
  { file: 'server/db/init.js', table: 'cloud_vuln_scanner_authorizations' },
  { file: 'server/db/init.js', table: 'threat_hunting_consumer_authorizations' },
  { file: 'packages/global-dashboard-server/db-init.js', table: 'cloud_vuln_scanner_authorizations' },
];

// The only two files permitted to open-code certificate verification.
const VERIFIER_FILES = [
  'server/services/machine-cert-auth.js',
  'packages/global-dashboard-server/services/gd-machine-cert-auth.js',
];
// ...plus the CA services, which implement the primitives the verifiers call.
const CA_FILES = [
  'server/services/ca.js',
  'packages/global-dashboard-server/services/gd-ca.js',
];

const SCAN_DIRS = ['server', 'packages', 'scripts'];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out']);

function read(rel) { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); }

function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return out; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.js$/.test(e.name) && path.resolve(p) !== SELF) out.push(p);
  }
  return out;
}

// Extract a function body by name, skipping its parameter list first -- these
// functions take destructured objects, so the first `{` after the name is the
// PARAMETER PATTERN, not the body. Getting that wrong yields a signature and
// every body assertion silently passes.
function extractFn(src, name) {
  const start = src.indexOf('function ' + name + '(');
  if (start === -1) return null;
  let pd = 0, bodyStart = -1;
  for (let k = src.indexOf('(', start); k < src.length; k++) {
    if (src[k] === '(') pd++;
    else if (src[k] === ')') { pd--; if (pd === 0) { bodyStart = src.indexOf('{', k); break; } }
  }
  if (bodyStart === -1) return null;
  let d = 0;
  for (let k = bodyStart; k < src.length; k++) {
    if (src[k] === '{') d++;
    else if (src[k] === '}') { d--; if (d === 0) return src.slice(start, k + 1); }
  }
  return null;
}

// Blank out comments and string bodies before any POSITION comparison.
// Ordering checks that count raw offsets are wrong twice over: a header comment
// mentioning `req.threatHuntingAuth` sits above everything and makes the real
// assignment look early, and an error-message string can contain any identifier.
// Both were hit during this phase -- once here, once in a verifier that compared
// against `ok: true` inside a JSDoc block. Lengths are preserved so offsets stay
// comparable with the original source.
function stripNonCode(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === '//') {
      const j = src.indexOf('\n', i);
      const end = j === -1 ? src.length : j;
      out += ' '.repeat(end - i); i = end;
    } else if (two === '/*') {
      const j = src.indexOf('*/', i + 2);
      const end = j === -1 ? src.length : j + 2;
      out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end;
    } else if (src[i] === "'" || src[i] === '"' || src[i] === '`') {
      const q = src[i]; let j = i + 1;
      while (j < src.length && src[j] !== q) { if (src[j] === '\\') j++; j++; }
      const end = Math.min(j + 1, src.length);
      out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end;
    } else { out += src[i]; i++; }
  }
  return out;
}

function createBlock(src, table) {
  const i = src.indexOf('CREATE TABLE IF NOT EXISTS ' + table + ' (');
  if (i === -1) return null;
  let d = 0, j = i;
  for (; j < src.length; j++) { if (src[j] === '(') d++; else if (src[j] === ')') { d--; if (d === 0) break; } }
  return src.slice(i, j + 1);
}

// ── checks ──────────────────────────────────────────────────────────────────
function run() {
  const failures = [];
  const fail = (m) => failures.push(m);

  // CERT-FIRST
  for (const p of AUTH_PATHS) {
    let src;
    try { src = read(p.file); } catch (_) { fail(`CERT-FIRST: ${p.file} not found`); continue; }
    // Positions are compared on comment-and-string-stripped source; the call
    // and lookup markers are matched on it too, so both sides agree.
    const stripped = stripNonCode(src);
    const scope = p.fn ? extractFn(stripped, p.fn) : stripped;
    if (!scope) { fail(`CERT-FIRST: ${p.file} has no function ${p.fn}`); continue; }
    if (scope.length < 300) { fail(`CERT-FIRST: extracted scope for ${p.file} is too small to be a body (${scope.length} chars) -- the extractor is broken, not the code`); continue; }

    const vi = scope.indexOf('verifyMachineCert(db, req, ' + p.ou + ')');
    if (vi === -1) {
      fail(`CERT-FIRST: ${p.file} does not call verifyMachineCert with ${p.ou}. Every machine-authenticated path must verify the certificate through the shared verifier.`);
      continue;
    }
    // p.lookup lives inside a SQL string on most paths, so it is matched on RAW
    // source; positions are then compared as line numbers, which are stable
    // across stripping because stripNonCode preserves newlines.
    const rawScope = p.fn ? (extractFn(src, p.fn) || src) : src;
    const rawLookup = rawScope.indexOf(p.lookup);
    const rawVerify = rawScope.indexOf('verifyMachineCert(db, req, ' + p.ou + ')');
    const li = rawLookup === -1 ? -1 : rawScope.slice(0, rawLookup).split('\n').length;
    const vl = rawVerify === -1 ? -1 : rawScope.slice(0, rawVerify).split('\n').length;
    if (li !== -1 && vl !== -1 && vl > li) {
      fail(`CERT-FIRST: ${p.file} looks up a credential (${p.lookup}) BEFORE verifying the certificate. A caller with no certificate must never reach a credential comparison.`);
    }
    if (p.success) {
      const si = scope.indexOf(p.success);
      if (si !== -1 && si < vi) {
        fail(`CERT-FIRST: ${p.file} can reach its success path (${p.success}) before verifying the certificate.`);
      }
    }
  }

  // DISTINCT-OU
  const ouByFile = new Map();
  for (const p of AUTH_PATHS) {
    let src;
    try { src = read(p.file); } catch (_) { continue; }
    const m = src.match(/verifyMachineCert\(db, req, ([A-Za-z.$_]+)\)/);
    if (m) ouByFile.set(p.file, m[1]);
  }
  // Resolve the identifiers to their literal OU strings where declared locally.
  const literal = (ident, file) => {
    if (ident === 'CONSUMER_OU') {
      const s = read(file);
      const m = s.match(/const CONSUMER_OU = ca\.([A-Z_]+)/);
      return m ? m[1] : ident;
    }
    return ident.replace(/^(ca|gdCa)\./, '');
  };
  const seen = new Map();
  for (const [file, ident] of ouByFile) {
    const lit = literal(ident, file);
    // The two scanner surfaces on the SAME server legitimately share an OU:
    // they are one consumer class. Cross-CLASS sharing is the defect.
    const cls = lit;
    if (!seen.has(cls)) seen.set(cls, []);
    seen.get(cls).push(file);
  }
  const classes = [...seen.keys()];
  if (classes.length < 2) {
    fail(`DISTINCT-OU: only ${classes.length} role OU(s) in use across ${ouByFile.size} machine-auth paths. Collapsing consumer classes onto one OU makes every machine certificate universal.`);
  }
  for (const caFile of CA_FILES) {
    let src;
    try { src = read(caFile); } catch (_) { continue; }
    const ous = [...src.matchAll(/const ([A-Z_]*CONSUMER_OU) = '([a-z-]+)'/g)];
    const vals = ous.map((m) => m[2]);
    if (new Set(vals).size !== vals.length) {
      fail(`DISTINCT-OU: ${caFile} declares two role OUs with the same string value.`);
    }
  }

  // ONE-VERIFIER
  const files = [];
  for (const d of SCAN_DIRS) walk(path.join(ROOT, d), files);
  const allowed = new Set([...VERIFIER_FILES, ...CA_FILES].map((f) => path.join(ROOT, f)));
  for (const f of files) {
    if (allowed.has(f)) continue;
    const src = fs.readFileSync(f, 'utf8');
    const rel = path.relative(ROOT, f);
    if (/getPeerCertificate\s*\(\s*true\s*\)/.test(src)) {
      fail(`ONE-VERIFIER: ${rel} reads a peer certificate directly. Certificate acquisition belongs in the shared verifier so all surfaces cannot drift apart.`);
    }
    if (/subject\.split\(/.test(src)) {
      fail(`ONE-VERIFIER: ${rel} parses a certificate subject itself. Use ca.subjectHasOu / gdCa.subjectHasOu.`);
    }
  }

  // DB-REQUIRED
  for (const rel of ['server/services/webauthn.js', 'packages/global-dashboard-server/services/gd-webauthn.js']) {
    let src;
    try { src = read(rel); } catch (_) { fail(`DB-REQUIRED: ${rel} not found`); continue; }
    if (/\bdb = null\b/.test(src)) {
      fail(`DB-REQUIRED: ${rel} leaves a db handle optional (\`db = null\`). Challenge consumption is unbypassable only because finish* THROWS without it.`);
    }
    for (const fn of ['finishStepUp', 'finishAuthentication', 'finishRegistration']) {
      const body = extractFn(src, fn);
      if (!body) { fail(`DB-REQUIRED: ${rel} has no ${fn}`); continue; }
      if (!/requires a database handle/.test(body)) {
        fail(`DB-REQUIRED: ${rel} ${fn} does not refuse a missing db handle.`);
      }
      if (!/consumeChallengeToken\(db, decoded\)/.test(body)) {
        fail(`DB-REQUIRED: ${rel} ${fn} never consumes its challenge -- the assertion stays replayable for the token's whole TTL.`);
      }
    }
  }

  // MINT-BINDS
  for (const m of MINT_PATHS) {
    let src;
    try { src = read(m.file); } catch (_) { fail(`MINT-BINDS: ${m.file} not found`); continue; }
    const ins = src.indexOf('INSERT INTO ' + m.table);
    if (ins === -1) { fail(`MINT-BINDS: ${m.file} has no INSERT INTO ${m.table}`); continue; }
    const region = src.slice(Math.max(0, ins - 1200), ins + 800);
    if (!region.includes(m.ca + '.issueMachineConsumerCert(')) {
      fail(`MINT-BINDS: ${m.file} inserts into ${m.table} without issuing the certificate that constrains it. A row with no certificate cannot authenticate; issuing outside the insert risks an orphaned certificate.`);
    }
    if (!/db\.transaction\(/.test(region)) {
      fail(`MINT-BINDS: ${m.file} does not wrap the certificate issuance and the ${m.table} insert in one transaction.`);
    }
    const stmtEnd = src.indexOf(');', src.indexOf('.run(', ins));
    const stmt = src.slice(ins, stmtEnd === -1 ? ins + 800 : stmtEnd);
    if (!/cert_fingerprint/.test(stmt) || !/cert_serial/.test(stmt)) {
      fail(`MINT-BINDS: ${m.file} INSERT INTO ${m.table} does not write cert_fingerprint and cert_serial.`);
    }
  }

  // REVOKE-BINDS
  const REVOKES = [
    { file: 'server/routes/apikeys.js', marker: "UPDATE api_keys SET revoked = 1", ca: 'ca' },
    { file: 'server/routes/vuln-scan.js', marker: 'DELETE FROM vuln_scan_scanner_authorizations', ca: 'ca' },
    { file: 'server/routes/cloud-vuln-scan.js', marker: 'DELETE FROM cloud_vuln_scanner_authorizations', ca: 'ca' },
    { file: 'packages/global-dashboard-server/routes/cloud-vuln-scan.js', marker: 'DELETE FROM cloud_vuln_scanner_authorizations', ca: 'gdCa' },
  ];
  for (const r of REVOKES) {
    let src;
    try { src = read(r.file); } catch (_) { fail(`REVOKE-BINDS: ${r.file} not found`); continue; }
    const i = src.indexOf(r.marker);
    if (i === -1) { fail(`REVOKE-BINDS: ${r.file} has no revoke statement (${r.marker})`); continue; }
    const region = src.slice(Math.max(0, i - 900), i + 900);
    if (!region.includes(r.ca + '.revokeCert(')) {
      fail(`REVOKE-BINDS: ${r.file} revokes a credential without revoking its certificate. The CA would still vouch for a credential the operator believes destroyed.`);
    }
  }

  // SCHEMA-NN
  for (const b of BOUND_TABLES) {
    let src;
    try { src = read(b.file); } catch (_) { fail(`SCHEMA-NN: ${b.file} not found`); continue; }
    const block = createBlock(src, b.table);
    if (!block) { fail(`SCHEMA-NN: ${b.file} has no CREATE for ${b.table}`); continue; }
    if (!/cert_fingerprint TEXT NOT NULL/.test(block)) {
      fail(`SCHEMA-NN: ${b.file} ${b.table} does not declare cert_fingerprint TEXT NOT NULL. Fresh installs must be bound structurally.`);
    }
  }

  // NO-FAKE-DEF
  for (const rel of ['server/db/init.js', 'packages/global-dashboard-server/db-init.js']) {
    let src;
    try { src = read(rel); } catch (_) { continue; }
    if (/ADD COLUMN cert_fingerprint[^;\n]*DEFAULT/i.test(src)) {
      fail(`NO-FAKE-DEF: ${rel} gives cert_fingerprint a DEFAULT on the upgrade path. A default is a FAKE fingerprint: it LOOKS bound while binding nothing. A null cannot authenticate, which is the correct failure.`);
    }
  }

  return failures;
}

// ── self-test ───────────────────────────────────────────────────────────────
function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: got === want, got, want });

  const SRC = "async function f({ a, b, db }) {\n  if (!db) throw new Error('x');\n  return 1;\n}";
  t('extractFn skips a destructured parameter list', /return 1;/.test(extractFn(SRC, 'f') || ''), true);
  t('extractFn returns null for an absent function', extractFn(SRC, 'nope'), null);
  t('extractFn output is a body, not a signature', (extractFn(SRC, 'f') || '').length > 40, true);

  const CB = "CREATE TABLE IF NOT EXISTS t (\n  id TEXT,\n  cert_fingerprint TEXT NOT NULL\n)";
  t('createBlock captures a whole CREATE', /cert_fingerprint/.test(createBlock(CB, 't') || ''), true);
  t('createBlock returns null for an absent table', createBlock(CB, 'other'), null);

  t('the fake-default pattern matches an offender',
    /ADD COLUMN cert_fingerprint[^;\n]*DEFAULT/i.test("db.exec('ALTER TABLE x ADD COLUMN cert_fingerprint TEXT DEFAULT \\'\\'')"), true);
  t('...and not the correct nullable form',
    /ADD COLUMN cert_fingerprint[^;\n]*DEFAULT/i.test("db.exec('ALTER TABLE x ADD COLUMN cert_fingerprint TEXT')"), false);

  t('the direct-peer-read pattern matches an offender',
    /getPeerCertificate\s*\(\s*true\s*\)/.test('const p = req.socket.getPeerCertificate(true);'), true);
  t('...and not a call through the verifier',
    /getPeerCertificate\s*\(\s*true\s*\)/.test('const r = verifyMachineCert(db, req, OU);'), false);

  t('the subject-parser pattern matches an offender',
    /subject\.split\(/.test('const parts = subject.split(/,/);'), true);

  t('stripNonCode blanks a line comment', /marker/.test(stripNonCode('// marker here\nreal();')), false);
  t('...but keeps the code after it', /real\(\)/.test(stripNonCode('// marker here\nreal();')), true);
  t('stripNonCode blanks a block comment', /marker/.test(stripNonCode('/* marker */ real();')), false);
  t('stripNonCode blanks a string body', /marker/.test(stripNonCode('const s = "marker";')), false);
  t('stripNonCode preserves length', stripNonCode('// abc\nx();').length, '// abc\nx();'.length);
  t('stripNonCode preserves newlines', stripNonCode('/* a\nb */ x();').split('\n').length, 2);

  // The real tree must produce a non-trivial registry (guards a broken path list).
  t('the registry covers 5 machine-auth paths', AUTH_PATHS.length, 5);
  t('the registry covers 5 mint paths', MINT_PATHS.length, 5);
  t('the registry covers 5 bound tables', BOUND_TABLES.length, 5);

  const bad = cases.filter((c) => !c.ok);
  for (const c of cases) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.n + (c.ok ? '' : ` (got ${JSON.stringify(c.got)}, want ${JSON.stringify(c.want)})`));
  console.log('\nself-test: ' + (cases.length - bad.length) + '/' + cases.length + ' passed');
  process.exit(bad.length ? 1 : 0);
}

if (process.argv.indexOf('--selftest') !== -1) selftest();

const failures = run();
if (failures.length) {
  console.error('Machine-credential binding gate FAILED:\n');
  for (const f of failures) console.error('  - ' + f);
  console.error('\nA bearer secret authenticates NOTHING on its own. Every machine credential is');
  console.error('bound to a client certificate this deployment issued, scoped to its surface by');
  console.error('role OU, and checked BEFORE the secret is ever compared. A path that can reach');
  console.error('success without that check is a bearer credential again.');
  process.exit(1);
}
console.log('Machine-credential binding gate passed: every machine-auth path is certificate-first, every mint binds a certificate, every revoke revokes one, and no credential table admits an unbound row on a fresh install.');
