// FIREALIVE — SOC Analyst Wellbeing Platform
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Analyst Client -- on-device behavioral baseline + drift engine (B5d1 PR D).
//
// Extracted verbatim from analyst-client.jsx so the exact math the renderer runs
// is also importable by a CI invariant gate (scripts/check-baseliner-invariants.js).
// esbuild bundles this module into the AC's app.js at build time (--bundle), so no
// separate file ships; Node loads it directly via require() for the gate. The
// display-only helpers that reference the color palette C (STAGE_COPY) and the
// interpretation-prompt word (faPressureWord) stay in the JSX; everything here is
// pure, dependency-free baseliner math.
//
// Invariants this module must preserve (asserted by the gate):
//   - Fixed FA_ESTABLISH_DAYS window; below it, status is "establishing".
//   - The frozen base is the median of the first window and can only re-establish
//     DOWNWARD when the analyst is genuinely in-band -- a sustained-high window can
//     NEVER raise it (persistent strain is never laundered into "normal").
//   - Establishing signals contribute no strain unless a hard band breach; they are
//     never scored as healthy.
//   - Drift is (cur - base) / |base| against the frozen base.

// ── B5d1 PR D: My Signals metadata + on-device baseline/drift engine ─────────
// Behavioral signals are sealed to the analyst's own X25519 key and decrypted
// ONLY on this device (burnout:decrypt). From each analyst's own decrypted
// history we compute two anchors, shown side by side:
//   1. A FROZEN personal baseline -- the median over the first FA_ESTABLISH_DAYS
//      of history, then frozen. Later data can RE-ESTABLISH IT DOWNWARD (a recent
//      in-band window that settles lower), but a sustained-high window can NEVER
//      raise it. A rolling/auto-raising baseline would silently normalise
//      persistent strain and hide a worsening analyst.
//   2. A normative HEALTHY-RANGE band per signal (FireAlive-set, configurable,
//      research-informed). It flags an analyst whose own "normal" already sits
//      outside the band even while their personal drift is flat.
// Until FA_ESTABLISH_DAYS of history exist the personal baseline is withheld
// (status 'establishing') and only the band comparison is shown.
const FA_ESTABLISH_DAYS = 90;   // history required before a personal baseline is trusted
const FA_CURRENT_DAYS = 14;     // recent window summarised as "current"
const FA_DAY_MS = 86400000;
const FA_DRIFT_NOTABLE = 15;    // |drift %| beyond which a worsening change is highlighted

// hib = "higher is better" (documentation quality, break compliance). band is the
// healthy range; for hib the concern is falling BELOW low, otherwise rising ABOVE high.
const BEHAVIORAL_META = {
  investigationTime: { label: "Avg time per alert",    u: "min", hib: false, band: { low: 0,  high: 30  } },
  dismissRate:       { label: "Closed without notes",  u: "%",   hib: false, band: { low: 0,  high: 30  } },
  ticketQuality:     { label: "Documentation quality", u: "%",   hib: true,  band: { low: 65, high: 100 } },
  escalationRate:    { label: "Escalation rate",       u: "%",   hib: false, band: { low: 0,  high: 25  } },
  break_compliance:  { label: "Break compliance",      u: "%",   hib: true,  band: { low: 60, high: 100 } },
};
const BEHAVIORAL_ORDER = ["investigationTime", "dismissRate", "ticketQuality", "escalationRate", "break_compliance"];

function faMedian(arr) {
  if (!arr || arr.length === 0) return null;
  const s = arr.slice().sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
// 'within' | 'above' | 'below' relative to the normative band (only the harmful side is named).
function faBandStatus(v, band, hib) {
  if (v == null || !band) return "within";
  if (hib) return v < band.low ? "below" : "within";
  return v > band.high ? "above" : "within";
}
function faInBand(v, band, hib) { return faBandStatus(v, band, hib) === "within"; }
// Per-signal view from a chronological series of {t (ms), v}.
// Returns { status:'no_data'|'establishing'|'established', n, cur, base, driftPct, band }.
function faComputeSignal(series, band, hib) {
  if (!series || series.length === 0) return { status: "no_data", n: 0 };
  const asc = series.slice().sort((a, b) => a.t - b.t);
  const t0 = asc[0].t, tEnd = asc[asc.length - 1].t;
  const spanDays = (tEnd - t0) / FA_DAY_MS;
  const cur = faMedian(asc.filter((p) => p.t >= tEnd - FA_CURRENT_DAYS * FA_DAY_MS).map((p) => p.v));
  const bandStatus = faBandStatus(cur, band, hib);
  if (spanDays < FA_ESTABLISH_DAYS) {
    return { status: "establishing", n: asc.length, cur, band: bandStatus, spanDays: Math.floor(spanDays) };
  }
  const estBase = faMedian(asc.filter((p) => p.t <= t0 + FA_ESTABLISH_DAYS * FA_DAY_MS).map((p) => p.v));
  const recentBase = faMedian(asc.filter((p) => p.t >= tEnd - FA_ESTABLISH_DAYS * FA_DAY_MS).map((p) => p.v));
  let base = estBase;
  if (recentBase != null && estBase != null && recentBase < estBase && faInBand(recentBase, band, hib)) base = recentBase;
  const driftPct = (base != null && base !== 0 && cur != null) ? ((cur - base) / Math.abs(base)) * 100 : 0;
  return { status: "established", n: asc.length, cur, base, driftPct, band: bandStatus };
}
// Display: round to a tidy number; em-dash placeholder when absent.
function faNum(x) { return x == null ? "\u2014" : (Math.round(x * 10) / 10); }

// ── B5d1 PR D: aggregate burnout-proximity (on-device, deterministic) ────────
// One overall read across ALL signals. Behavioral strain (the original
// computeRisk ratios, with break_compliance folded in) is blended with
// operational pressure; a single severe signal lifts the score (max blend) so a
// real problem is not diluted by calm signals. Establishing/no-data signals do
// not invent strain. Drives the My Signals overall card and the home status
// banner, and frames the holistic on-device interpretation.
const FA_BEHAVIORAL_WEIGHTS = { dismissRate: 0.30, ticketQuality: 0.26, investigationTime: 0.22, escalationRate: 0.09, break_compliance: 0.13 };
const FA_DRIFT_FULL = 50;             // a 50% bad-direction drift -> full per-signal drift strain
const FA_BAND_BREACH_STRAIN = 0.7;    // current value outside the healthy band, on the harmful side
const FA_AVG_VS_MAX = 0.55;           // behavioral = 0.55*weighted average + 0.45*worst signal
const FA_BEHAVIORAL_VS_PRESSURE = 0.6;// overall = 0.6*behavioral + 0.4*pressure (renormalized if one absent)
const FA_PRESSURE_THRESHOLDS = { cognitive_load: [60, 80], task_switching: [6, 10], queue_pressure: [8, 12], shift_overtime: [4, 8] };
const FA_STAGE_BANDS = [[0.25, "healthy"], [0.50, "watch"], [0.75, "strained"], [Infinity, "elevated"]];

function faSignalStrain(s) {
  if (!s || s.status === "no_data") return { strain: 0, usable: false };
  const breach = (s.band === "above") || (s.band === "below");
  if (s.status === "establishing") return { strain: breach ? FA_BAND_BREACH_STRAIN : 0, usable: true };
  const badMag = s.hib ? Math.max(0, -(s.driftPct || 0)) : Math.max(0, (s.driftPct || 0));
  const driftStrain = Math.min(1, badMag / FA_DRIFT_FULL);
  return { strain: Math.min(1, Math.max(driftStrain, breach ? FA_BAND_BREACH_STRAIN : 0)), usable: true };
}
function faBehavioralScore(signals) {
  let wsum = 0, acc = 0, worst = 0, any = false;
  for (const k of Object.keys(FA_BEHAVIORAL_WEIGHTS)) {
    const r = faSignalStrain(signals[k]); if (!r.usable) continue;
    any = true; wsum += FA_BEHAVIORAL_WEIGHTS[k]; acc += FA_BEHAVIORAL_WEIGHTS[k] * r.strain; if (r.strain > worst) worst = r.strain;
  }
  if (!any || wsum === 0) return { score: null, usable: false };
  return { score: FA_AVG_VS_MAX * (acc / wsum) + (1 - FA_AVG_VS_MAX) * worst, usable: true };
}
function faPressureScore(pressure) {
  if (!pressure) return { score: null, usable: false };
  let n = 0, acc = 0;
  for (const k of Object.keys(FA_PRESSURE_THRESHOLDS)) {
    const v = pressure[k]; if (typeof v !== "number" || !Number.isFinite(v)) continue;
    const r = FA_PRESSURE_THRESHOLDS[k]; acc += v >= r[1] ? 1 : v >= r[0] ? 0.5 : 0; n++;
  }
  if (n === 0) return { score: null, usable: false };
  return { score: acc / n, usable: true };
}
function faAggregate(signals, pressure) {
  const b = faBehavioralScore(signals || {});
  const p = faPressureScore(pressure);
  const parts = [];
  if (b.usable) parts.push([FA_BEHAVIORAL_VS_PRESSURE, b.score]);
  if (p.usable) parts.push([1 - FA_BEHAVIORAL_VS_PRESSURE, p.score]);
  let overall = 0;
  if (parts.length) { const ws = parts.reduce((a, x) => a + x[0], 0); overall = parts.reduce((a, x) => a + x[0] * x[1], 0) / ws; }
  const established = Object.keys(signals || {}).some((k) => signals[k] && signals[k].status === "established");
  let stage = "healthy";
  for (const sb of FA_STAGE_BANDS) { if (overall < sb[0]) { stage = sb[1]; break; } }
  return { score: overall, stage, behavioral: b.score, pressure: p.score, established, hasBehavioral: b.usable, hasPressure: p.usable };
}

module.exports = {
  FA_ESTABLISH_DAYS, FA_CURRENT_DAYS, FA_DAY_MS, FA_DRIFT_NOTABLE,
  BEHAVIORAL_META, BEHAVIORAL_ORDER,
  FA_BEHAVIORAL_WEIGHTS, FA_DRIFT_FULL, FA_BAND_BREACH_STRAIN, FA_AVG_VS_MAX,
  FA_BEHAVIORAL_VS_PRESSURE, FA_PRESSURE_THRESHOLDS, FA_STAGE_BANDS,
  faMedian, faBandStatus, faInBand, faComputeSignal, faNum,
  faSignalStrain, faBehavioralScore, faPressureScore, faAggregate,
};
