#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// check-baseliner-invariants.js  --  the 22nd gate  (N2)
// ═══════════════════════════════════════════════════════════════════════════
//
// Guards the on-device behavioral baseline + drift engine (B5d1 PR D), extracted
// to packages/analyst-client/baseliner.js so the exact math the Analyst Client
// renderer runs is executable here in CI. The engine is the heart of the
// wellbeing model: per analyst, from that analyst's own sealed history, it
// decides whether a behavioral signal has drifted from a FROZEN personal
// baseline. Getting it wrong toward a rolling/self-refitting mean would normalise
// persistent burnout -- the one UEBA behaviour (continuous re-fit) that is exactly
// wrong for a wellbeing metric, per the research this platform is built on. A
// CISO trusts the burnout posture only if this engine cannot silently regress.
//
// WHY A SOURCE GATE
//
// The engine lives inside a ~4,000-line renderer bundle. A well-meaning refactor
// that swaps the frozen base for a trailing mean, drops the "establishing" state,
// or scores an analyst's first-90-day window as if it were a personal baseline
// would compile, bundle, and ship green -- the failure is a slow, invisible drift
// in WHO gets flagged, not a crash, so no runtime smoke would catch it. This gate
// imports the real module and asserts its load-bearing invariants on synthetic
// series, so any such change fails the build. It is DEPENDENCY-FREE (the module +
// Node built-ins) and runs in the coverage job on every pull request.
//
// ── INVARIANTS ────────────────────────────────────────────────────────────
//
//  A. FIXED WINDOW. A history spanning less than FA_ESTABLISH_DAYS is
//     "establishing" and exposes NO personal base; at/after the window it is
//     "established" with a base. (A fixed time window, not an N-reading count.)
//  B. ESTABLISHING IS UNSCORED, NEVER HEALTHY. While establishing, a signal
//     contributes zero strain -- even carrying a drift value -- UNLESS its current
//     value breaches the normative healthy band, in which case it scores exactly
//     FA_BAND_BREACH_STRAIN. It is never drift-scored against a baseline it does
//     not yet have, and never laundered into a "healthy" reading.
//  C. FROZEN AGAINST UPWARD DRIFT. A sustained-high recent window can NEVER raise
//     the frozen base above the first-window median. Persistent strain is not
//     normalised into "normal".
//  D. DOWNWARD RE-ESTABLISH ONLY WHEN IN-BAND. The base re-establishes to a lower
//     recent window ONLY when that window is within the healthy band; a lower but
//     OUT-of-band recent window does NOT move the base.
//  E. DRIFT IS RELATIVE TO THE FROZEN BASE. Drift percent is
//     (current - base) / |base| * 100, measured against the frozen base.
//  F. NO DATA. An empty history is "no_data", not "establishing" or "healthy".
//
// Run with --self-test to drive the invariants against planted-defect mutants --
// a rolling mean, a dropped establishing state, a scored establishing window, an
// unconditional downward refit, an absolute (unnormalised) drift, and a mistyped
// empty series -- and prove EACH is caught. A guard that cannot go red is useless.
// ═══════════════════════════════════════════════════════════════════════════

const path = require('path');

const BASELINER_PATH = path.join(__dirname, '..', 'packages', 'analyst-client', 'baseliner.js');

// ── synthetic-series helpers (deterministic, dependency-free) ───────────────
function flat(v, n) { return Array.from({ length: n }, () => v); }
// Spread `values` evenly across `days`, ending "now", as {t (ms), v} readings.
function seriesSpanning(values, days, bl) {
  const now = Date.now();
  const n = values.length;
  const DAY = bl.FA_DAY_MS;
  return values.map((v, i) => ({ t: now - (days - (n <= 1 ? 0 : (i * days) / (n - 1))) * DAY, v }));
}
function round(x) { return Math.round(x * 1000) / 1000; }

// ── the invariant suite: returns a list of violation strings (empty == holds) ──
// Every assertion is tagged [A]..[F] so the self-test can prove a planted defect
// trips the specific guard it is meant to. Each defect below overrides a function
// that the catching invariant calls DIRECTLY -- baseliner's internal cross-calls
// use module-scope bindings, so an exports-object override would not reach them,
// and the invariants that catch these defects all call the overridden function
// directly (faComputeSignal for A/C/D/E/F, faSignalStrain for B).
function runInvariants(bl) {
  const problems = [];
  const check = (cond, msg) => { if (!cond) problems.push(msg); };

  const loBand = bl.BEHAVIORAL_META.investigationTime.band; // lower-is-better, healthy high 30
  const hiBand = bl.BEHAVIORAL_META.ticketQuality.band;     // higher-is-better, healthy low 65

  // (A) FIXED WINDOW
  const aEst = bl.faComputeSignal(seriesSpanning([20, 21, 19, 20, 22], 40, bl), loBand, false);
  check(aEst.status === 'establishing', '[A] a sub-window (40d) span must be establishing, got status=' + aEst.status);
  check(aEst.base == null, '[A] an establishing signal must not expose a personal base, got base=' + aEst.base);
  const aDone = bl.faComputeSignal(seriesSpanning(flat(20, 30).concat(flat(21, 30)), 180, bl), loBand, false);
  check(aDone.status === 'established', '[A] a full-window (180d) span must be established, got status=' + aDone.status);
  check(aDone.base != null, '[A] an established signal must expose a base, got base=' + aDone.base);

  // (B) ESTABLISHING IS UNSCORED, NEVER HEALTHY
  const bWithin = bl.faSignalStrain({ status: 'establishing', band: 'within', hib: false, driftPct: 60 });
  check(bWithin.strain === 0, '[B] an in-band establishing signal must contribute 0 strain even carrying a drift value, got strain=' + bWithin.strain);
  const bBreach = bl.faSignalStrain({ status: 'establishing', band: 'above', hib: false });
  check(bBreach.strain === bl.FA_BAND_BREACH_STRAIN, '[B] a band-breaching establishing signal must score FA_BAND_BREACH_STRAIN (' + bl.FA_BAND_BREACH_STRAIN + '), got strain=' + bBreach.strain);

  // (C) FROZEN AGAINST UPWARD DRIFT
  const cSig = bl.faComputeSignal(seriesSpanning(flat(20, 30).concat(flat(28, 30)), 180, bl), loBand, false);
  check(cSig.base != null && cSig.base <= 20 + 1e-9, '[C] a sustained-high recent window must NOT raise the frozen base above the first-window median (20), got base=' + cSig.base);

  // (D) DOWNWARD RE-ESTABLISH ONLY WHEN IN-BAND
  const dDown = bl.faComputeSignal(seriesSpanning(flat(24, 30).concat(flat(12, 30)), 180, bl), loBand, false);
  check(dDown.base != null && dDown.base < 24, '[D] a lower in-band recent window must re-establish the base downward (< 24), got base=' + dDown.base);
  const dHold = bl.faComputeSignal(seriesSpanning(flat(80, 30).concat(flat(50, 30)), 180, bl), hiBand, true);
  check(dHold.base != null && dHold.base >= 80 - 1e-9, '[D] a lower but OUT-OF-BAND recent window must NOT re-establish the base (stays 80), got base=' + dHold.base);

  // (E) DRIFT IS RELATIVE TO THE FROZEN BASE
  const eSig = bl.faComputeSignal(seriesSpanning(flat(20, 30).concat(flat(28, 30)), 180, bl), loBand, false);
  if (eSig.base != null && eSig.cur != null) {
    const want = ((eSig.cur - eSig.base) / Math.abs(eSig.base)) * 100;
    check(Math.abs(eSig.driftPct - want) < 1e-9, '[E] drift must be (cur-base)/|base|*100 = ' + round(want) + ', got driftPct=' + round(eSig.driftPct));
  } else {
    check(false, '[E] expected an established signal exposing base and cur to test the drift formula');
  }

  // (F) NO DATA
  const fSig = bl.faComputeSignal([], loBand, false);
  check(fSig.status === 'no_data', '[F] an empty history must be no_data, got status=' + fSig.status);

  return problems;
}

// ── planted-defect mutants: each a shallow override that violates one invariant ──
function mutants(bl) {
  const median = bl.faMedian, DAY = bl.FA_DAY_MS, W = bl.FA_ESTABLISH_DAYS;
  const asc = (series) => series.slice().sort((a, b) => a.t - b.t);
  const drift = (cur, base) => (base != null && base !== 0 && cur != null) ? ((cur - base) / Math.abs(base)) * 100 : 0;
  return {
    // (A) never enters the establishing state -- "established" immediately
    'no-establishing': Object.assign({}, bl, {
      faComputeSignal(series, band, hib) {
        const r = bl.faComputeSignal(series, band, hib);
        if (r.status === 'establishing') return Object.assign({}, r, { status: 'established', base: r.cur, driftPct: 0 });
        return r;
      },
    }),
    // (B) drift-scores establishing signals instead of leaving them unscored
    'scores-establishing': Object.assign({}, bl, {
      faSignalStrain(s) {
        if (!s || s.status === 'no_data') return { strain: 0, usable: false };
        const breach = (s.band === 'above') || (s.band === 'below');
        const badMag = s.hib ? Math.max(0, -(s.driftPct || 0)) : Math.max(0, (s.driftPct || 0));
        const driftStrain = Math.min(1, badMag / bl.FA_DRIFT_FULL);
        return { strain: Math.min(1, Math.max(driftStrain, breach ? bl.FA_BAND_BREACH_STRAIN : 0)), usable: true };
      },
    }),
    // (C) rolling mean: base follows the recent window (raises on sustained-high)
    'rolling-mean': Object.assign({}, bl, {
      faComputeSignal(series, band, hib) {
        const r = bl.faComputeSignal(series, band, hib);
        if (r.status !== 'established') return r;
        const s = asc(series); const tEnd = s[s.length - 1].t;
        const base = median(s.filter((p) => p.t >= tEnd - W * DAY).map((p) => p.v));
        return Object.assign({}, r, { base, driftPct: drift(r.cur, base) });
      },
    }),
    // (D) re-establishes downward with NO in-band check
    'reestablish-anyway': Object.assign({}, bl, {
      faComputeSignal(series, band, hib) {
        const r = bl.faComputeSignal(series, band, hib);
        if (r.status !== 'established') return r;
        const s = asc(series); const t0 = s[0].t, tEnd = s[s.length - 1].t;
        const estBase = median(s.filter((p) => p.t <= t0 + W * DAY).map((p) => p.v));
        const recentBase = median(s.filter((p) => p.t >= tEnd - W * DAY).map((p) => p.v));
        let base = estBase;
        if (recentBase != null && estBase != null && recentBase < estBase) base = recentBase; // dropped faInBand()
        return Object.assign({}, r, { base, driftPct: drift(r.cur, base) });
      },
    }),
    // (E) drift as an absolute delta, not normalised by |base|
    'wrong-drift': Object.assign({}, bl, {
      faComputeSignal(series, band, hib) {
        const r = bl.faComputeSignal(series, band, hib);
        if (r.status !== 'established' || r.base == null) return r;
        return Object.assign({}, r, { driftPct: (r.cur - r.base) });
      },
    }),
    // (F) empty history mistyped as establishing
    'empty-not-nodata': Object.assign({}, bl, {
      faComputeSignal(series, band, hib) {
        if (!series || series.length === 0) return { status: 'establishing', base: null, cur: null };
        return bl.faComputeSignal(series, band, hib);
      },
    }),
  };
}

// ── self-test: the real engine holds; each planted defect trips its guard ────
function selfTest() {
  const real = require(BASELINER_PATH);
  let bad = 0;

  const realProblems = runInvariants(real);
  if (realProblems.length) {
    bad++;
    console.error('  FAIL  the real engine must hold, but got:\n        - ' + realProblems.join('\n        - '));
  } else {
    console.log('  ok    real engine holds (invariants A-F)');
  }

  const muts = mutants(real);
  const expect = {
    'no-establishing': '[A]',
    'scores-establishing': '[B]',
    'rolling-mean': '[C]',
    'reestablish-anyway': '[D]',
    'wrong-drift': '[E]',
    'empty-not-nodata': '[F]',
  };
  for (const name of Object.keys(expect)) {
    const problems = runInvariants(muts[name]);
    const hit = problems.some((p) => p.indexOf(expect[name]) !== -1);
    if (!hit) {
      bad++;
      console.error('  FAIL  planted defect "' + name + '" must trip ' + expect[name] + ', but got:\n        - ' + (problems.join('\n        - ') || '(no problems -- the defect ESCAPED)'));
    } else {
      console.log('  ok    planted defect caught: ' + name + ' -> ' + expect[name]);
    }
  }

  if (bad) { console.error('\nbaseliner-invariants self-test FAILED: ' + bad + ' case(s).'); process.exit(1); }
  console.log('\nbaseliner-invariants self-test passed (real engine holds; 6 planted defects each caught: '
    + 'rolling mean, dropped establishing, scored establishing, unconditional refit, absolute drift, mistyped empty).');
}

// ── main ────────────────────────────────────────────────────────────────────
if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  let bl;
  try { bl = require(BASELINER_PATH); }
  catch (e) { console.error('check-baseliner-invariants FAILED: cannot load baseliner.js (' + (e && e.message ? e.message : e) + ')'); process.exit(1); }
  const problems = runInvariants(bl);
  if (problems.length) {
    console.error('check-baseliner-invariants FAILED (' + problems.length + '):\n');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    process.exit(1);
  }
  console.log('check-baseliner-invariants passed: fixed ' + bl.FA_ESTABLISH_DAYS + '-day window, establishing unscored '
    + '(never healthy), frozen against upward drift, downward re-establish only when in-band, drift vs the frozen base, '
    + 'empty is no_data.');
}
