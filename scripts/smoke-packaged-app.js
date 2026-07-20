#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// smoke-packaged-app.js  --  launch a packaged app and assert the boot ladder
// ═══════════════════════════════════════════════════════════════════════════
//
// Usage:  node scripts/smoke-packaged-app.js <mc|gd|ac> <extracted-app-dir>
//
// Run under xvfb-run. Exits 0 when the app cleared every packaging layer and
// failed exactly where it should; non-zero, loudly, otherwise.
//
// ── WHY THIS EXISTS ──────────────────────────────────────────────────────
//
// CI has never executed FireAlive in any form. Not the packaged app, not the
// server, not once. Every gate in scripts/ is a source-level check driven by
// stubs and mock databases -- check-tier1-boot-gate.js says so in its own
// header. That is not laziness: no hosted runner has a TPM 2.0 or a Secure
// Enclave, and this platform fails closed without one. Six fatal packaging
// defects are the arithmetic result of four layers of verification being
// absent at once.
//
// ── WHY IT DOES NOT ASSERT LIVENESS ──────────────────────────────────────
//
// It cannot. `GET /api/system/health` will never answer on a runner: the boot
// halts at instance-identity establishment with "there is no software
// fallback", correctly. A software TPM (swtpm) would make it answer and is
// refused -- introducing a software root of trust into the one project whose
// anti-clone guarantee is that none exists, even for verification only, is the
// fallback-to-a-weaker-option the master principle forbids. It is also
// Linux-only, so the honest design would be needed anyway.
//
// So the green condition is: THE APP REACHES THE HARDWARE REFUSAL AND NOTHING
// EARLIER. That is strictly stronger than a 200. A 200 proves something
// answered. Reaching the hardware boundary proves every layer beneath it
// resolved -- the module graph (FATAL 6), the spawn target (FATAL 1), the Node
// runtime (FATAL 2), the writable data root (FATAL 3), and every data path
// landing outside the bundle (FATAL 4). Each of those fails EARLIER and
// DIFFERENTLY: MODULE_NOT_FOUND, ENOENT, EROFS, a path under resources/.
//
// ── WHY IT ASSERTS THE CAUSE AND NEVER THE ADVICE LINE ───────────────────
//
// Both servers print their hardware-root advice from a catch that fires for
// ANY establishment failure:
//
//   server/index.js:657-658          GD index.js:7165-7166
//
// So a GD broken by a missing schema (FATAL 7) emits "requires a hardware root
// of trust" too. A job grepping that string goes GREEN on a server that cannot
// start -- a guard reporting success on a broken product, which is the exact
// disease this phase exists to kill. This asserts the CAUSE: the anchor's real
// error is HardwareKeystoreUnavailableError, "Hardware root of trust (...) not
// detected on this <platform> host" (hardware-keystore.js:127-132).
// "no such table" is unmistakably different, and is asserted ABSENT.
//
// ── WHY THE THREE APPS ARE ASSERTED DIFFERENTLY ──────────────────────────
//
// Not for convenience. Each shape is forced by what the app actually does.
//
// MC   Its server writes NOTHING to stdout. server/services/logger.js adds the
//      Console transport only when NODE_ENV !== 'production', and
//      frontend/main.js:246 spawns the server with NODE_ENV: 'production'
//      explicitly set -- so every logger.error goes to files only, and
//      server/index.js contains zero console.* calls. The [Server] re-emit at
//      main.js:250-251 captures an empty stream. The refusal lands in
//      <dataRoot>/logs/error.log as winston.format.json().
//
//      That is BETTER than stdout, not worse: the file's existence AT THAT
//      PATH is itself the FATAL 3/4 assertion, and JSON lines are parsed
//      rather than pattern-matched.
//
// GD   Has no logger at all (zero winston requires) -- pure console.error, and
//      it CONCATENATES the cause into the message, so the line reaches stdout
//      through main.js:360-361's [GD-Server] re-emit. It also has no logsDir,
//      so there is no file to read. Asserted on stdout.
//
// AC   Spawns no server (zero spawn calls; it is a client of the MC's embedded
//      Regional Server). Its entire packaging exposure is whether main.js
//      loads -- which is precisely FATAL 6. Asserted on absence alone.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

// 90s default. Overridable so the FATAL-6 hang path is testable and a
// constrained runner can shorten it; the value never affects a passing run,
// which exits on its own well under the cap.
const LAUNCH_TIMEOUT_MS = Number(process.env.FIREALIVE_SMOKE_TIMEOUT_MS) || 90_000;

const APPS = {
  mc: { label: 'Management Console', server: true, via: 'logfile' },
  gd: { label: 'Global Dashboard', server: true, via: 'stdout' },
  ac: { label: 'Analyst Client', server: false, via: 'stdout' },
};

// Failures that mean a packaging layer did not resolve. Each is EARLIER than
// the hardware boundary and is what a fatal defect actually looks like.
const PACKAGING_FAILURES = [
  ['MODULE_NOT_FOUND', 'FATAL 6 -- a require did not resolve in the bundle'],
  ['Cannot find module', 'FATAL 6 -- a require did not resolve in the bundle'],
  ['ENOENT', 'FATAL 1 or 2 -- the spawn target or the node runtime is absent'],
  ['EROFS', 'FATAL 3 -- something wrote inside the read-only AppImage mount'],
  ['no such table', 'FATAL 7 -- the schema was never created'],
  ['EACCES', 'a permission failure below the hardware boundary'],
];

const HARDWARE_CAUSE = /Hardware root of trust \(.*\) not detected on this .* host|no hardware root of trust \(.*\) available/;

const problems = [];
const fail = (m) => problems.push(m);
const ok = (m) => console.log('  ok  ' + m);

function usage() {
  console.error('usage: node scripts/smoke-packaged-app.js <mc|gd|ac> <extracted-app-dir>');
  process.exit(2);
}

// ── launch ────────────────────────────────────────────────────────────────
function findAppRun(dir) {
  const direct = path.join(dir, 'AppRun');
  if (fs.existsSync(direct)) return direct;
  fail('no AppRun in ' + dir + ' -- --appimage-extract did not produce squashfs-root');
  return null;
}

function snapshot(dir) {
  const out = new Set();
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (_e) { return; }
    for (const e of entries) {
      const f = path.join(d, e.name);
      out.add(f);
      if (e.isDirectory()) walk(f);
    }
  };
  walk(dir);
  return out;
}

function launch(appRun, appDir) {
  return new Promise((resolve) => {
    let out = '';
    // --no-sandbox: the runner has no user namespaces for Chromium's sandbox.
    // This weakens nothing in the product -- it is a property of the launch,
    // and every app sets sandbox: true in webPreferences regardless.
    const child = spawn(appRun, ['--no-sandbox'], {
      cwd: appDir,
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const grab = (d) => { out += d.toString(); };
    child.stdout.on('data', grab);
    child.stderr.on('data', grab);

    let done = false;
    const finish = (why) => {
      if (done) return;
      done = true;
      try { child.kill('SIGKILL'); } catch (_e) { /* already gone */ }
      resolve({ out, why });
    };
    child.on('error', (e) => { out += '\nSPAWN ERROR: ' + e.message; finish('spawn-error'); });
    child.on('exit', () => setTimeout(() => finish('exited'), 1500));
    setTimeout(() => finish('timeout'), LAUNCH_TIMEOUT_MS);
  });
}

// ── assertions ────────────────────────────────────────────────────────────
function assertNoPackagingFailure(out, label) {
  for (const [needle, why] of PACKAGING_FAILURES) {
    if (out.includes(needle)) {
      const line = out.split('\n').find((l) => l.includes(needle)) || needle;
      fail(label + ': "' + needle + '" appeared -- ' + why + '\n        ' + line.trim().slice(0, 200));
    }
  }
  if (!problems.length) ok(label + ': no packaging failure in the captured output');
}

function assertModes(p, want, label) {
  let st;
  try { st = fs.statSync(p); } catch (_e) { fail(label + ': ' + p + ' does not exist'); return false; }
  const m = st.mode & 0o777;
  if (m !== want) {
    fail(label + ': ' + p + ' is mode ' + m.toString(8) + ', expected ' + want.toString(8)
       + '. Liveness alone would pass a world-readable deployment.');
    return false;
  }
  ok(label + ': ' + p + ' is ' + want.toString(8));
  return true;
}

function assertOutsideBundle(p, appDir, label) {
  const rp = path.resolve(p);
  if (rp === path.resolve(appDir) || rp.startsWith(path.resolve(appDir) + path.sep)) {
    fail(label + ': ' + p + ' is INSIDE the application bundle -- FATAL 4. An installer replaces this directory.');
    return;
  }
  ok(label + ': resolves outside the bundle');
}

// The MC: parse the JSON log rather than grep a string.
function assertMcRefusal(logsDir) {
  const errLog = path.join(logsDir, 'error.log');
  if (!fs.existsSync(errLog)) {
    fail('MC: ' + errLog + ' does not exist. The server never reached instance-identity, '
       + 'or the logger never initialised -- meaning it died BELOW the hardware boundary.');
    return;
  }
  let lines;
  try {
    lines = fs.readFileSync(errLog, 'utf8').split('\n').filter(Boolean);
  } catch (e) { fail('MC: cannot read ' + errLog + ': ' + e.message); return; }

  const parsed = [];
  for (const l of lines) {
    try { parsed.push(JSON.parse(l)); } catch (_e) { /* winston writes one JSON object per line */ }
  }
  if (!parsed.length) { fail('MC: ' + errLog + ' holds no parseable JSON lines'); return; }

  const identity = parsed.find((r) => String(r.message || '').includes('Instance identity establishment failed'));
  if (!identity) {
    const last = parsed[parsed.length - 1];
    fail('MC: the boot never reached instance-identity establishment. Last error logged: '
       + JSON.stringify(last).slice(0, 240)
       + '\n        Something failed BELOW the hardware boundary -- that is a packaging defect.');
    return;
  }
  const cause = String(identity.error || '');
  if (!HARDWARE_CAUSE.test(cause)) {
    fail('MC: instance-identity failed for the WRONG reason: "' + cause.slice(0, 200) + '"'
       + '\n        Expected the hardware keystore to be absent. Note the catch prints the '
       + 'hardware-root ADVICE for any failure, so the advice line proves nothing -- this '
       + 'asserts the cause.');
    return;
  }
  ok('MC: reached the hardware refusal, and for the right reason');
  ok('MC: cause -> ' + cause.slice(0, 96));
}

// The GD: assert stdout, since it has no logger and concatenates the cause.
function assertGdRefusal(out) {
  const line = out.split('\n').find((l) => l.includes('GD instance identity establishment failed'));
  if (!line) {
    fail('GD: the boot never reached instance-identity establishment. Nothing below the '
       + 'hardware boundary may fail -- that would be a packaging defect.');
    return;
  }
  if (!HARDWARE_CAUSE.test(line)) {
    fail('GD: instance-identity failed for the WRONG reason:\n        ' + line.trim().slice(0, 240)
       + '\n        The catch concatenates the cause into this line and then prints the '
       + 'hardware advice regardless, so the advice proves nothing. "no such table" here '
       + 'means FATAL 7 regressed.');
    return;
  }
  ok('GD: reached the hardware refusal, and for the right reason');
}

// ── main ──────────────────────────────────────────────────────────────────
async function main() {
  const which = process.argv[2];
  const appDirArg = process.argv[3];
  if (!which || !appDirArg || !APPS[which]) usage();
  // Resolve ONCE, to absolute. The first version kept appDir relative, found
  // AppRun relative to the process cwd, then spawned it with cwd: appDir --
  // so spawn re-resolved the same relative path against a different base and
  // died with ENOENT. Two frames of reference for one path is the exact defect
  // class this phase exists to eliminate; it does not get to live in the
  // instrument that catches it.
  const appDir = path.resolve(appDirArg);
  const spec = APPS[which];
  if (!fs.existsSync(appDir)) { console.error('no such directory: ' + appDir); process.exit(2); }

  console.log('smoke: ' + spec.label + ' (' + which + ') at ' + appDir);

  const appRun = findAppRun(appDir);
  if (!appRun) { report(spec); return; }

  const before = snapshot(appDir);
  const { out, why } = await launch(appRun, appDir);
  console.log('  launch ended: ' + why + ' (' + out.length + ' bytes captured)');

  assertNoPackagingFailure(out, spec.label);

  // Any packaging failure is TERMINAL for this report, and it can arrive two
  // ways, neither leaving a process worth asserting against:
  //
  //   - a spawn error: the runtime or the AppRun could not be launched at all.
  //   - a require that failed INSIDE a launched app, which throws and then
  //     hangs until the timeout. The MC does exactly this on FATAL 6 -- it
  //     MODULE_NOT_FOUNDs on main.js line 42, never exits, and is killed at 90s
  //     having done nothing.
  //
  // In the second case an earlier version proceeded to the file-diff and
  // printed "ok: zero files created inside the application directory". True,
  // and measured against an app that crashed on line 42 and never ran -- a
  // guard claiming coverage it does not have, which is the disease this harness
  // exists to catch. assertNoPackagingFailure records into problems[], so a
  // non-empty problems[] here means packaging is broken and nothing downstream
  // may speak.
  if (why === 'spawn-error' || problems.length > 0) {
    if (why === 'spawn-error') {
      fail(spec.label + ': the app never launched, so nothing below this was asserted.');
    } else {
      fail(spec.label + ': packaging failed, so no assertion below the failure was made. '
         + 'Fix the packaging before reading any other line of this report.');
    }
    report(spec);
    return;
  }

  if (spec.server) {
    if (which === 'mc') {
      const dr = require(path.join(__dirname, '..', 'server', 'lib', 'data-root'));
      const root = dr.dataRoot();
      assertOutsideBundle(root, appDir, 'MC data root');
      assertModes(root, 0o700, 'MC data root');
      assertMcRefusal(dr.logsDir());
      // initDb() runs at boot step 3, BEFORE the hardware gate at step 4, so
      // the real database is on disk by the time the process exits.
      const db = dr.dbPath();
      if (assertModes(db, 0o600, 'MC database')) assertOutsideBundle(db, appDir, 'MC database');
    } else {
      const gdr = require(path.join(__dirname, '..', 'packages', 'global-dashboard-server', 'lib', 'gd-data-root'));
      const root = gdr.gdDataRoot();
      assertOutsideBundle(root, appDir, 'GD data root');
      assertModes(root, 0o700, 'GD data root');
      assertGdRefusal(out);
      const db = gdr.dbPath();
      if (assertModes(db, 0o600, 'GD database')) assertOutsideBundle(db, appDir, 'GD database');
    }
  } else {
    // The AC spawns no server. That its main loaded IS the assertion.
    ok('AC: main process loaded without a module-resolution failure (this is FATAL 6)');
  }

  // FATAL 4, asserted by execution rather than by grep: the app directory must
  // be byte-for-byte the same set of files it was before launch.
  const after = snapshot(appDir);
  const created = [...after].filter((f) => !before.has(f));
  if (created.length) {
    fail(spec.label + ': ' + created.length + ' file(s) were created INSIDE the application '
       + 'directory -- FATAL 4. An installer replaces this directory, so anything written here '
       + 'dies with the next update:\n        ' + created.slice(0, 8).map((f) => path.relative(appDir, f)).join('\n        '));
  } else {
    ok(spec.label + ': zero files created inside the application directory');
  }

  report(spec);
}

function report(spec) {
  if (problems.length) {
    console.error('\nsmoke FAILED (' + problems.length + '):\n');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    process.exit(1);
  }
  // Say what was actually verified, per app. The first version printed
  // "refused at the hardware root of trust" for the Analyst Client, which
  // spawns no server and never refuses at anything -- a report claiming a
  // verification it never made is the disease this harness exists to catch.
  if (spec && spec.server) {
    console.log('\nsmoke passed: the packaged ' + spec.label + ' cleared every packaging layer and '
      + 'refused at the hardware root of trust, which is the only correct outcome on a runner '
      + 'without one.');
  } else {
    console.log('\nsmoke passed: the packaged ' + (spec ? spec.label : 'app') + ' loaded its main '
      + 'process with every require resolved, and wrote nothing into its own bundle. It spawns no '
      + 'server, so there is no boot ladder to assert and none is claimed.');
  }
}

main().catch((e) => { console.error('smoke harness error: ' + (e && e.stack || e)); process.exit(3); });
