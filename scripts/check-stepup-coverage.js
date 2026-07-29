#!/usr/bin/env node
//
// FIREALIVE -- Step-Up Coverage Guard (CI)  [O3]
//
// A step-up gate is worth exactly what its weakest reachable path is worth, so
// this guard fails the build on four distinct drifts:
//
//   * COVERAGE   -- every endpoint in STEPUP_REQUIRED must actually carry
//     mfaStepUp() (MC) / gdMfaStepUp() (GD) on its route line.
//
//   * NO-STALE   -- every STEPUP_REQUIRED and MINT_EXEMPT entry must correspond
//     to a real route. Catches a renamed endpoint silently leaving coverage.
//
//   * MINT-SHAPE -- every mutating endpoint reachable on a credential-minting
//     mount prefix must be registered or exempted WITH A WRITTEN REASON. A new
//     endpoint on apikeys/kms-providers/... fails the build until someone
//     decides, in writing, whether it mints.
//
//   * CALLER     -- every gated route must have a frontend caller that actually
//     sends an assertion. B6i-4 found two gated routes whose buttons sent
//     nothing, so the operation could not be performed from its own console at
//     all. A gate whose UI does not know about it is a broken feature, not a
//     hardened one.
//
// The enumerator is deliberately the same shape as check-config-lock-coverage.js
// (mount walking, .accessRouter attribution, alias resolution) so the two guards
// cannot disagree about what the route surface IS.
//
// Run:  node scripts/check-stepup-coverage.js
//       node scripts/check-stepup-coverage.js --enumerate   (inventory dump)
//       node scripts/check-stepup-coverage.js --selftest    (guard the guard)
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MUT = ['POST', 'PUT', 'PATCH', 'DELETE'];

// ── Enumeration machinery ────────────────────────────────────────────────────

function mainExportVar(src) {
  const m = src.match(/module\.exports\s*=\s*(\w+)\s*;/);
  return m ? m[1] : 'router';
}

function exportPropMap(src) {
  const map = {};
  const obj = src.match(/module\.exports\s*=\s*\{([\s\S]*?)\}/);
  if (obj) {
    const re = /(\w+)\s*:\s*(\w+)/g;
    let m;
    while ((m = re.exec(obj[1])) !== null) map[m[1]] = m[2];
  }
  const asg = /(?:module\.exports|\w+)\.(\w+)\s*=\s*(\w+)\s*;/g;
  let a;
  while ((a = asg.exec(src)) !== null) map[a[1]] = a[2];
  return map;
}

function aliasMap(indexSrc) {
  const map = {};
  const re = /const\s+(\w+)\s*=\s*require\(\s*'(\.\/routes\/[^']+)'\s*\)\s*;/g;
  let m;
  while ((m = re.exec(indexSrc)) !== null) map[m[1]] = m[2];
  return map;
}

function enumerateServer(cfg) {
  const indexSrc = fs.readFileSync(path.join(cfg.dir, 'index.js'), 'utf8');
  const indexLines = indexSrc.split('\n');
  const alias = aliasMap(indexSrc);
  const rows = [];

  const reReq = /app\.use\(\s*'(\/api[^']*)'\s*,[^\n]*require\(\s*'(\.\/routes\/[^']+)'\s*\)(?:\.(\w+))?/;
  const reAlias = /app\.use\(\s*'(\/api[^']*)'\s*,[^\n]*?(\w+)\.(\w+)\s*\)\s*;/;

  indexLines.forEach((line) => {
    let prefix, file, prop;
    let m = line.match(reReq);
    if (m) {
      prefix = m[1]; file = m[2]; prop = m[3] || null;
    } else {
      m = line.match(reAlias);
      if (!m) return;
      if (!alias[m[2]]) return;
      prefix = m[1]; file = alias[m[2]]; prop = m[3];
    }
    const fp = path.join(cfg.dir, file + (file.endsWith('.js') ? '' : '.js'));
    if (!fs.existsSync(fp)) return;
    const src = fs.readFileSync(fp, 'utf8');
    const routerVar = prop ? (exportPropMap(src)[prop] || prop) : mainExportVar(src);
    const mountGated = cfg.stepUpRe.test(line);
    src.split('\n').forEach((rl, ri) => {
      const rm = rl.match(/(\w+)\.(get|post|put|patch|delete)\(\s*'([^']*)'/);
      if (!rm || rm[1] !== routerVar) return;
      const method = rm[2].toUpperCase();
      if (!MUT.includes(method)) return;
      const sub = rm[3] === '/' ? '' : rm[3];
      rows.push({
        method, full: prefix + sub, file, routeLine: ri + 1,
        gated: cfg.stepUpRe.test(rl) || mountGated,
      });
    });
  });

  indexLines.forEach((line, i) => {
    const im = line.match(/\bapp\.(get|post|put|patch|delete)\(\s*'(\/api[^']*)'/);
    if (!im) return;
    const method = im[1].toUpperCase();
    if (!MUT.includes(method)) return;
    rows.push({
      method, full: im[2], file: 'index.js', routeLine: i + 1,
      gated: cfg.stepUpRe.test(line),
    });
  });

  return [...new Map(rows.map((r) => [r.method + ' ' + r.full, r])).values()];
}

// ── The registry ─────────────────────────────────────────────────────────────
//
// Every endpoint that creates, replaces, activates, or destroys a credential --
// or redirects the key material a credential protects. Revocation is included
// deliberately: destroying a credential is how an intruder causes an outage or
// covers a track, and the config lock bounds that at one ceremony per unlock
// window rather than one per operation. GitHub requires sudo-mode for both
// creating and deleting a PAT; AWS conditions both on MFA.

const STEPUP_REQUIRED = {
  MC: [
    'POST /api/apikeys',
    'DELETE /api/apikeys/:id',

    'POST /api/kms-providers',
    'PATCH /api/kms-providers/:id',
    'POST /api/kms-providers/:id/enable',
    'POST /api/kms-providers/:id/disable',
    'POST /api/kms-providers/:id/set-default',
    'DELETE /api/kms-providers/:id',

    'PUT /api/integrations/:type',
    'DELETE /api/integrations/:type',

    'POST /api/storage-destinations',
    'PATCH /api/storage-destinations/:id',
    'DELETE /api/storage-destinations/:id',

    'POST /api/v1/malware-scanners',
    'POST /api/v1/malware-scanners/:id',
    'DELETE /api/v1/malware-scanners/:id',
    'POST /api/v1/malware-scanners/scan-mode',

    'PUT /api/vuln-scan/config',
  // B6e: the cloud surface gained the policy layer it never had. Writing
  // policy is a configuration change on a security control -- disabling the
  // permitted-scanner list is as consequential as issuing an authorization,
  // and an intruder who can silently widen it can then mint freely inside the
  // same unlock window. Same treatment as its on-prem twin above.
  'PUT /api/cloud-vuln/config',
    'POST /api/vuln-scan/authorizations',
    'PUT /api/vuln-scan/authorizations/:id',
    'DELETE /api/vuln-scan/authorizations/:id',

    'POST /api/cloud-vuln/authorizations',
    'PUT /api/cloud-vuln/authorizations/:id',
    'DELETE /api/cloud-vuln/authorizations/:id',

    // Enrollment. Without these the rest of this registry is decorative: a
    // hijacked session that can enroll its own passwordless passkey then
    // satisfies every gate above, and can delete the operator's real credential
    // afterwards -- the lockout guard counts the attacker's new key as a
    // remaining login method.
    'POST /api/mfa/passkey/register-verify',
    'DELETE /api/mfa/passkeys/:id',
  ],
  GD: [
    // B6e: the GD's two scan surfaces gained a policy layer. Writing policy is a
    // configuration change on a security control -- silently widening the
    // permitted-scanner list re-opens a surface an operator believes is closed.
    'PUT /api/cloud-vuln/config',
    'PUT /api/vuln-scan/config',
    // B6e: the GD's on-prem scan surface. The same three mint paths its cloud
    // twin carries -- a scanner authorization IS a credential, and revoking one
    // is how an intruder blinds a scan or covers a track.
    'POST /api/vuln-scan/authorizations',
    'PUT /api/vuln-scan/authorizations/:id',
    'DELETE /api/vuln-scan/authorizations/:id',
    'POST /api/storage-destinations',
    'PATCH /api/storage-destinations/:id',
    'DELETE /api/storage-destinations/:id',

    'POST /api/cloud-vuln/authorizations',
    'PUT /api/cloud-vuln/authorizations/:id',
    'DELETE /api/cloud-vuln/authorizations/:id',

    'POST /api/mfa/passkey/register-verify',
    'DELETE /api/mfa/passkeys/:id',
  ],
};

// Mutating endpoints on a mint prefix deliberately NOT step-up gated. Each
// carries the reason, verified by reading the handler and anything it delegates
// to -- not inferred from the endpoint name.

const MINT_EXEMPT = {
  MC: {
    'POST /api/kms-providers/probe-config':
      'stateless validation; probeConfig() in services/kms-providers.js performs zero writes, verified by reading the function body rather than the section header. Mints nothing.',
    'POST /api/kms-providers/:id/probe':
      'round-trips an EXISTING row and writes last_probe_* metadata only; no credential, activation, or default change.',
    'POST /api/storage-destinations/:id/probe':
      'probes an existing destination; the handler performs no writes at all.',
    'POST /api/integrations/:type/test':
      'writes last_test_at / last_test_result / status metadata only; no credential or config change.',
    'POST /api/v1/malware-scanners/:id/test':
      'delegates to IntegrationManager.testScanner(), which writes last_test_at / last_test_status / last_test_error only, best-effort wrapped.',
    'POST /api/mfa/passkey/register-options':
      'issues a registration challenge and persists nothing; the credential is written at register-verify, which is gated. Gating this too would cost a third WebAuthn prompt (existing key, new key, existing key again -- the step-up token is consumed) and buy no additional property: the claim is that no credential is PERSISTED without fresh proof.',
    'POST /api/integrations/ticketing/activity-events':
      'machine-only data-plane ingest: rejects human sessions outright (req.user.apiKey required) and demands the ticketing:events scope, so there is no session to step up. An O3 Half-2 cert-binding target, not a Half-1 step-up target.',
  },
  GD: {
    'POST /api/mfa/passkey/register-options':
      'issues a registration challenge and persists nothing; the credential is written at register-verify, which is gated. Gating this too would cost a third WebAuthn prompt (existing key, new key, existing key again -- the step-up token is consumed) and buy no additional property: the claim is that no credential is PERSISTED without fresh proof.',
    'POST /api/storage-destinations/:id/probe':
      'probes an existing destination; the handler performs no writes at all.',
  },
};

const MINT_PREFIXES = [
  '/api/apikeys', '/api/kms-providers', '/api/integrations',
  '/api/storage-destinations', '/api/v1/malware-scanners',
  '/api/vuln-scan', '/api/cloud-vuln',
  '/api/mfa/passkey', '/api/mfa/passkeys',
];

const SERVERS = [
  {
    name: 'MC',
    dir: path.join(ROOT, 'server'),
    stepUpRe: /\bmfaStepUp\s*\(\s*\)/,
    frontend: path.join(ROOT, 'frontend', 'firealive-mc.jsx'),
    // MC idiom: const stepup = await getStepUp(); api.post(path, { ..., stepup })
    sharedHelperRe: null,
    mwName: 'mfaStepUp()',
  },
  {
    name: 'GD',
    dir: path.join(ROOT, 'packages', 'global-dashboard-server'),
    stepUpRe: /\bgdMfaStepUp\s*\(\s*\)/,
    frontend: path.join(ROOT, 'packages', 'global-dashboard', 'global-dashboard.jsx'),
    // GD idiom: await stepUp(path, body) -- the helper does the round trip.
    sharedHelperRe: /\bstepUp\s*\(/,
    mwName: 'gdMfaStepUp()',
  },
];

// ── Caller detection ─────────────────────────────────────────────────────────

const VERB_FOR = { POST: ['post'], PUT: ['put'], PATCH: ['patch'], DELETE: ['del', 'delete'] };

// The literal prefix of a route path: everything before the first :param.
// Used only as a cheap pre-filter before the real matcher runs.
function literalPrefix(routePath) {
  const i = routePath.indexOf('/:');
  return i === -1 ? routePath : routePath.slice(0, i);
}

// The text of a call expression starting at line i: from that line until the
// nesting opened on it closes, capped so a malformed file cannot run away.
// Needed because a multi-line api.post(path, { ... stepup, }) carries the path
// and the assertion on DIFFERENT lines -- inspecting one line at a time is a
// false red, found on live code during the O3 pre-flight.
function callExpression(jsxLines, i) {
  const MAX = 40;
  let depth = 0, started = false, out = [];
  for (let k = i; k < jsxLines.length && k < i + MAX; k++) {
    const L = jsxLines[k];
    out.push(L);
    for (const ch of L) {
      if (ch === '(' || ch === '{' || ch === '[') { depth++; started = true; }
      else if (ch === ')' || ch === '}' || ch === ']') depth--;
    }
    if (started && depth <= 0) break;
  }
  return out.join('\n');
}

// Rebuild a path from a call's FIRST ARGUMENT, which may be a concatenation:
//   "/api/kms-providers/" + k.id + "/enable"
// Capturing only up to the first closing quote yields "/api/kms-providers/" and
// silently drops the "/enable" suffix, so the call is attributed to .../:id
// instead of .../:id/enable -- the same defect class as truncating at ${...},
// but for + concatenation. Found on live code during O3 sub-phase 3B.
//
// Every string literal in the argument is joined with a dynamic marker between,
// so "/api/x/" + id + "/y" becomes /api/x/<dyn>/y.
function pathLiteralOf(argText) {
  // Stop at the first top-level comma: everything after it is the body.
  let depth = 0, end = argText.length;
  for (let i = 0; i < argText.length; i++) {
    const c = argText[i];
    if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') { if (depth === 0) { end = i; break; } depth--; }
    else if (c === ',' && depth === 0) { end = i; break; }
  }
  const head = argText.slice(0, end);
  const lits = head.match(/["'`][^"'`]*["'`]/g) || [];
  if (!lits.length) return head;
  return lits.map((x) => x.slice(1, -1)).join('\u0001');
}

// Parse the path literal captured from a call site into comparable segments.
// A trailing '/' or a '${' interpolation means one dynamic segment follows:
//   "/api/apikeys"                  -> { segs:[api,apikeys],           tail:false }
//   "/api/apikeys/" + k.id          -> { segs:[api,apikeys],           tail:true  }
//   `/api/x/authorizations/${a.id}` -> { segs:[api,x,authorizations],  tail:true  }
function callPathInfo(literal) {
  // Each ${...} becomes a DYNAMIC segment marker rather than truncating the
  // path. Truncating loses any static suffix after the interpolation, so
  //   `/api/v1/malware-scanners/${s.id}/test`
  // collapsed to `/api/v1/malware-scanners/` and was attributed to
  // POST .../:id (step-up required) instead of POST .../:id/test (exempt).
  // Found on live code: wiring that call would have made the Test button
  // demand a hardware key it does not need.
  let lit = literal.replace(/\$\{[^}]*\}/g, '\u0001');
  let tail = false;
  if (lit.length > 1 && lit.charAt(lit.length - 1) === '/') { tail = true; lit = lit.slice(0, -1); }
  const segs = lit.split('/').filter((x) => x.length > 0)
    .map((x) => (x.indexOf('\u0001') !== -1 ? null : x));   // null = dynamic
  return { segs, tail };
}

// Express-like specificity score for a route against a call, or -1 for no
// match. A STATIC segment match scores far higher than a :param match, so
// POST /api/v1/malware-scanners/scan-mode wins over
// POST /api/v1/malware-scanners/:id for a call to .../scan-mode. Without this,
// any longer path matched any :param route and the gate attributed callers to
// the wrong endpoint -- right verdict by luck, wrong reason.
function routeMatchScore(routePath, call) {
  const rsegs = routePath.split('/').filter((x) => x.length > 0);
  const effectiveLen = call.tail ? call.segs.length + 1 : call.segs.length;
  if (rsegs.length !== effectiveLen) return -1;
  let score = 0;
  for (let i = 0; i < call.segs.length; i++) {
    const r = rsegs[i];
    const c = call.segs[i];
    if (c === null) {
      // A dynamic call segment can only line up with a route :param.
      if (r.charAt(0) !== ':') return -1;
      score += 1;
    } else if (r.charAt(0) === ':') {
      score += 1;
    } else if (r === c) {
      score += 10;
    } else return -1;
  }
  if (call.tail) {
    const last = rsegs[rsegs.length - 1];
    if (last.charAt(0) !== ':') return -1;
    score += 1;
  }
  return score;
}

// Find EVERY frontend call attributed to this route -- not to a sibling -- and
// report which of them carry an assertion.
//
// It reports every caller rather than short-circuiting on the first good one,
// because "at least one caller sends an assertion" is a much weaker claim than
// it looks: a route with two callers where only one was wired would read green
// while the other button 401s. That exact shape appeared during the O3
// pre-flight -- PATCH /api/storage-destinations/:id has both a save ternary and
// an enable/disable toggle -- so the guard requires ALL of them.
//
// The assertion must appear IN the call expression. An assignment a few lines
// earlier (payload.stepup = ...) does not count, deliberately: scanning
// backwards for a nearby binding would trade a false red for a possible false
// green, and it makes the codebase auditable by eye -- a reviewer reading
// api.post(path, payload) cannot tell whether an assertion is sent, and one
// reading api.post(path, { ...payload, stepup }) can.
//
// allRoutes is every mutating route on the server, so a call is attributed to
// the most specific route matching it rather than the first that does.
function findCaller(jsxLines, method, routePath, cfg, allRoutes) {
  const prefix = literalPrefix(routePath);
  const verbs = VERB_FOR[method];
  const sameMethod = (allRoutes || []).filter((r) => r.method === method).map((r) => r.full);
  const callers = [];

  const attributes = (literal) => {
    const call = callPathInfo(literal);
    const mine = routeMatchScore(routePath, call);
    if (mine < 0) return false;
    for (const other of sameMethod) {
      if (other === routePath) continue;
      if (routeMatchScore(other, call) > mine) return false;
    }
    return true;
  };

  for (let i = 0; i < jsxLines.length; i++) {
    const L = jsxLines[i];
    if (L.indexOf(prefix) === -1) continue;

    // GD shared helper: stepUp("<path>", body[, method]) performs the whole
    // round trip, so reaching it IS the assertion.
    if (cfg.sharedHelperRe && cfg.sharedHelperRe.test(L)) {
      const m = L.match(/stepUp\(\s*(["'`].*)/);
      if (m && attributes(pathLiteralOf(m[1]))) { callers.push({ line: i + 1, withStepUp: true, via: 'stepUp' }); continue; }
    }

    for (const v of verbs) {
      const re = new RegExp('api\\.' + v + '\\(\\s*(["\'`].*)');
      const m = L.match(re);
      if (!m) continue;
      if (!attributes(pathLiteralOf(m[1]))) continue;
      callers.push({
        line: i + 1,
        withStepUp: /\bstepup\b/.test(callExpression(jsxLines, i)),
        via: 'api.' + v,
      });
    }
  }

  const missing = callers.filter((c) => !c.withStepUp);
  return {
    called: callers.length > 0,
    callers,
    missing,
    // Retained for readability at call sites: true only when EVERY caller carries one.
    withStepUp: callers.length > 0 && missing.length === 0,
    line: callers.length ? callers[0].line : null,
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────

function run(opts) {
  opts = opts || {};
  const failures = [];
  const fail = (m) => failures.push(m);

  for (const cfg of SERVERS) {
    const rows = enumerateServer(cfg);
    const byKey = new Map(rows.map((r) => [r.method + ' ' + r.full, r]));
    const required = STEPUP_REQUIRED[cfg.name] || [];
    const exempt = MINT_EXEMPT[cfg.name] || {};
    const reqSet = new Set(required);

    for (const key of required) {
      const row = byKey.get(key);
      if (!row) { fail(`[${cfg.name}] NO-STALE: STEPUP_REQUIRED entry has no matching route: ${key}`); continue; }
      if (!row.gated) fail(`[${cfg.name}] COVERAGE: ${key} is registered as requiring step-up but its route line carries no ${cfg.mwName} (${row.file}:${row.routeLine})`);
    }

    for (const key of Object.keys(exempt)) {
      if (!byKey.get(key)) fail(`[${cfg.name}] NO-STALE: MINT_EXEMPT entry has no matching route: ${key}`);
      if (!exempt[key] || exempt[key].length < 40) fail(`[${cfg.name}] MINT_EXEMPT entry needs a substantive written reason: ${key}`);
    }

    for (const r of rows) {
      const onMint = MINT_PREFIXES.some((p) => r.full === p || r.full.indexOf(p + '/') === 0);
      if (!onMint) continue;
      const key = r.method + ' ' + r.full;
      if (reqSet.has(key) || Object.prototype.hasOwnProperty.call(exempt, key)) continue;
      fail(`[${cfg.name}] MINT-SHAPE: ${key} (${r.file}:${r.routeLine}) is a mutating endpoint on a credential-minting mount but is in neither STEPUP_REQUIRED nor MINT_EXEMPT. Decide in writing whether it mints.`);
    }

    for (const r of rows) {
      if (!r.gated) continue;
      const key = r.method + ' ' + r.full;
      const onMint = MINT_PREFIXES.some((p) => r.full === p || r.full.indexOf(p + '/') === 0);
      if (onMint && !reqSet.has(key)) fail(`[${cfg.name}] REGISTRY: ${key} carries step-up but is not in STEPUP_REQUIRED (${r.file}:${r.routeLine})`);
    }

    if (!opts.skipCaller) {
      if (!fs.existsSync(cfg.frontend)) { fail(`[${cfg.name}] CALLER: frontend not found at ${cfg.frontend}`); continue; }
      const jsxLines = fs.readFileSync(cfg.frontend, 'utf8').split('\n');
      for (const key of required) {
        const row = byKey.get(key);
        if (!row || !row.gated) continue;
        const sp = key.indexOf(' ');
        const res = findCaller(jsxLines, key.slice(0, sp), key.slice(sp + 1), cfg, rows);
        if (!res.called) {
          fail(`[${cfg.name}] CALLER: ${key} is step-up gated but ${path.basename(cfg.frontend)} never calls it. The operation cannot be performed from its own console.`);
        } else if (res.missing.length) {
          const where = res.missing.map((c) => path.basename(cfg.frontend) + ':' + c.line).join(', ');
          const many = res.missing.length > 1;
          const n = res.missing.length === res.callers.length
            ? 'its caller' + (many ? 's' : '')
            : res.missing.length + ' of its ' + res.callers.length + ' callers';
          fail(`[${cfg.name}] CALLER: ${key} is step-up gated but ${n} at ${where} ${many ? 'send' : 'sends'} no assertion. ${many ? 'Those requests' : 'That request'} will 401 MFA_STEPUP_REQUIRED.`);
        }
      }
    }
  }

  return { failures };
}

// ── Self-test ────────────────────────────────────────────────────────────────

function selftest() {
  const cases = [];
  const t = (name, got, want) => cases.push({ name, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

  t('literalPrefix strips :param', literalPrefix('/api/apikeys/:id'), '/api/apikeys');
  t('literalPrefix leaves plain path', literalPrefix('/api/apikeys'), '/api/apikeys');
  t('literalPrefix handles mid-path param', literalPrefix('/api/kms-providers/:id/enable'), '/api/kms-providers');

  const mc = { sharedHelperRe: null };
  const gd = { sharedHelperRe: /\bstepUp\s*\(/ };
  const call = (lines, m, p, c, routes) => findCaller(lines, m, p, c, routes || [{ method: m, full: p }]);

  let r = call(['const r = await api.post("/api/apikeys", { name, scopes, stepup });'], 'POST', '/api/apikeys', mc);
  t('MC caller sending an assertion is accepted', [r.called, r.withStepUp], [true, true]);

  r = call(['const r = await api.post("/api/apikeys", { name, scopes });'], 'POST', '/api/apikeys', mc);
  t('MC caller sending no assertion is flagged (the B6i-4 defect)', [r.called, r.withStepUp], [true, false]);

  r = call(['const r = await api.get("/api/apikeys");'], 'POST', '/api/apikeys', mc);
  t('absent caller detected', r.called, false);

  r = call(['await api.del("/api/apikeys/" + k.id, { stepup });'], 'DELETE', '/api/apikeys/:id', mc);
  t('DELETE via api.del is recognised', [r.called, r.withStepUp], [true, true]);

  r = call(['await api.delete("/api/apikeys/" + k.id, { stepup });'], 'DELETE', '/api/apikeys/:id', mc);
  t('DELETE via api.delete is recognised', [r.called, r.withStepUp], [true, true]);

  r = call(['await api.put(`/api/vuln-scan/authorizations/${a.id}`, { enabled, stepup });'], 'PUT', '/api/vuln-scan/authorizations/:id', mc);
  t('template-literal path is recognised', [r.called, r.withStepUp], [true, true]);

  r = call(['const r = await stepUp("/api/storage-destinations", payload);'], 'POST', '/api/storage-destinations', gd);
  t('GD stepUp() helper counts as an assertion', [r.called, r.withStepUp], [true, true]);

  r = call(['await api.post("/api/apikeys/rotate", {});'], 'POST', '/api/apikeys', mc);
  t('a longer sibling path does not satisfy an exact route', r.called, false);

  // STRENGTHENED: one wired caller no longer excuses an unwired sibling. This
  // shape is live -- PATCH /api/storage-destinations/:id has a save ternary AND
  // an enable/disable toggle -- and wiring only one would have read green while
  // the other button 401'd.
  r = call(['await api.post("/api/apikeys", { stepup });', 'await api.post("/api/apikeys", {});'], 'POST', '/api/apikeys', mc);
  t('one wired caller does NOT excuse an unwired sibling', [r.called, r.withStepUp, r.missing.length], [true, false, 1]);
  t('...and it names the unwired line', r.missing[0].line, 2);

  r = call(['await api.post("/api/apikeys", { stepup });', 'await api.post("/api/apikeys", { a, stepup });'], 'POST', '/api/apikeys', mc);
  t('two wired callers pass', [r.called, r.withStepUp, r.missing.length], [true, true, 0]);

  r = call(['const r = await api.post("/api/apikeys", payload);'], 'POST', '/api/apikeys', mc);
  t('assertion assigned elsewhere and passed via a bare object does NOT count', [r.called, r.withStepUp], [true, false]);

  // A multi-line call carries the path and the assertion on DIFFERENT lines.
  // Inspecting one line at a time reports a false red; this was found on live
  // code during the O3 pre-flight, not hypothesised.
  r = call([
    'const r = await api.post("/api/apikeys", {',
    '  name: n,',
    '  scopes: s,',
    '  stepup,',
    '});',
  ], 'POST', '/api/apikeys', mc);
  t('multi-line call with the assertion on a later line is accepted', [r.called, r.withStepUp], [true, true]);

  // ...but a multi-line call that genuinely omits it must still go red.
  r = call([
    'const r = await api.post("/api/apikeys", {',
    '  name: n,',
    '  scopes: s,',
    '});',
  ], 'POST', '/api/apikeys', mc);
  t('multi-line call genuinely missing the assertion still flagged', [r.called, r.withStepUp], [true, false]);

  // ── Attribution: a static sibling must win over a :param route ────────────
  // Found on live code: POST /api/v1/malware-scanners/:id and
  // POST /api/v1/malware-scanners/scan-mode both claimed the SAME caller line,
  // because any longer path matched the :param route's literal prefix.
  const MS = [
    { method: 'POST', full: '/api/v1/malware-scanners' },
    { method: 'POST', full: '/api/v1/malware-scanners/:id' },
    { method: 'POST', full: '/api/v1/malware-scanners/scan-mode' },
  ];
  const scanModeCall = ['await api.post("/api/v1/malware-scanners/scan-mode", { mode });'];
  const byIdCall = ['await api.post(`/api/v1/malware-scanners/${s.id}`, { enabled });'];

  r = call(scanModeCall, 'POST', '/api/v1/malware-scanners/scan-mode', mc, MS);
  t('scan-mode call attributed to the scan-mode route', r.called, true);

  r = call(scanModeCall, 'POST', '/api/v1/malware-scanners/:id', mc, MS);
  t('scan-mode call NOT attributed to the :id route', r.called, false);

  r = call(byIdCall, 'POST', '/api/v1/malware-scanners/:id', mc, MS);
  t('interpolated :id call attributed to the :id route', r.called, true);

  r = call(byIdCall, 'POST', '/api/v1/malware-scanners/scan-mode', mc, MS);
  t('interpolated :id call NOT attributed to scan-mode', r.called, false);

  r = call(['await api.post("/api/v1/malware-scanners", { name });'], 'POST', '/api/v1/malware-scanners', mc, MS);
  t('collection-root call attributed to the collection route', r.called, true);

  r = call(['await api.post("/api/v1/malware-scanners", { name });'], 'POST', '/api/v1/malware-scanners/:id', mc, MS);
  t('collection-root call NOT attributed to the :id route', r.called, false);

  // ── A static suffix AFTER an interpolation must survive parsing ───────────
  const MS2 = [
    { method: 'POST', full: '/api/v1/malware-scanners/:id' },
    { method: 'POST', full: '/api/v1/malware-scanners/:id/test' },
  ];
  const testCall = ['await api.post(`/api/v1/malware-scanners/${s.id}/test`, {});'];
  r = call(testCall, 'POST', '/api/v1/malware-scanners/:id/test', mc, MS2);
  t('interpolated call with /test suffix attributed to the /test route', r.called, true);
  r = call(testCall, 'POST', '/api/v1/malware-scanners/:id', mc, MS2);
  t('interpolated call with /test suffix NOT attributed to the bare :id route', r.called, false);
  t('callPathInfo keeps a suffix after an interpolation',
    callPathInfo('/api/x/${a.id}/test'), { segs: ['api', 'x', null, 'test'], tail: false });
  t('callPathInfo marks a bare interpolation as a dynamic segment',
    callPathInfo('/api/x/${a.id}'), { segs: ['api', 'x', null], tail: false });
  t('routeMatchScore refuses a dynamic segment against a static route segment',
    routeMatchScore('/api/v1/malware-scanners/scan-mode', callPathInfo('/api/v1/malware-scanners/${s.id}')), -1);

  // Segment-count discipline.
  t('routeMatchScore rejects a length mismatch',
    routeMatchScore('/api/apikeys/:id', callPathInfo('/api/apikeys')), -1);
  t('routeMatchScore requires a param under a dynamic tail',
    routeMatchScore('/api/v1/malware-scanners/scan-mode', callPathInfo('/api/v1/malware-scanners/')), -1);
  t('callPathInfo represents a trailing interpolation as a dynamic segment',
    callPathInfo('/api/x/authorizations/${a.id}'), { segs: ['api', 'x', 'authorizations', null], tail: false });

  const mcRows = enumerateServer(SERVERS[0]);
  const gdRows = enumerateServer(SERVERS[1]);
  t('MC enumerates a non-trivial surface', mcRows.length > 200, true);
  t('GD enumerates a non-trivial surface', gdRows.length > 50, true);
  t('enumerator finds the apikeys mint path', mcRows.some((x) => x.method === 'POST' && x.full === '/api/apikeys'), true);
  t('enumerator finds the GD enrollment path', gdRows.some((x) => x.method === 'POST' && x.full === '/api/mfa/passkey/register-verify'), true);

  const bad = cases.filter((c) => !c.ok);
  for (const c of cases) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.name + (c.ok ? '' : `   (got ${JSON.stringify(c.got)}, want ${JSON.stringify(c.want)})`));
  console.log('\nself-test: ' + (cases.length - bad.length) + '/' + cases.length + ' passed');
  process.exit(bad.length ? 1 : 0);
}

// ── Entry ────────────────────────────────────────────────────────────────────

if (require.main === module) {
  if (process.argv.indexOf('--selftest') !== -1) selftest();

  if (process.argv.indexOf('--enumerate') !== -1) {
    for (const cfg of SERVERS) {
      const rows = enumerateServer(cfg);
      const mint = rows.filter((r) => MINT_PREFIXES.some((p) => r.full === p || r.full.indexOf(p + '/') === 0));
      console.log('\n=== ' + cfg.name + ' === mutating: ' + rows.length + '   on mint prefixes: ' + mint.length);
      for (const r of mint.sort((a, b) => a.full.localeCompare(b.full))) {
        console.log('  ' + (r.gated ? 'GATED ' : '  --  ') + r.method.padEnd(7) + r.full.padEnd(48) + r.file + ':' + r.routeLine);
      }
    }
    process.exit(0);
  }

  const { failures } = run({ skipCaller: process.argv.indexOf('--no-caller') !== -1 });
  if (failures.length) {
    console.error('Step-up coverage gate FAILED:\n');
    for (const f of failures) console.error('  - ' + f);
    console.error('\nA credential minted inside an unlock window outlives the session, survives key');
    console.error('rotation, and is how an intruder establishes a foothold. Minting is its own');
    console.error('ceremony: every mint path re-proves the hardware credential at the moment of');
    console.error('the action, and every gated path has a console that knows to send one.');
    process.exit(1);
  }
  console.log('Step-up coverage gate passed: every registered mint path carries a step-up, every exemption is reasoned, and every gated route has a caller that sends an assertion.');
}

module.exports = { enumerateServer, findCaller, callExpression, callPathInfo, pathLiteralOf, routeMatchScore, literalPrefix, STEPUP_REQUIRED, MINT_EXEMPT, MINT_PREFIXES, SERVERS, run };
