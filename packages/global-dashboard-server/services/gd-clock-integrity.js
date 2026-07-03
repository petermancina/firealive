// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Clock Integrity (D12)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Time-windowed security checks trust the wall clock: signed device actions and
// proof-of-possession assertions are honored only inside a tight iat window, and
// short-lived tokens rely on expiry. A virtual machine or cloud instance,
// however, jumps its wall clock -- snapshot restore, pause/resume, live
// migration, and host scheduling all step Date.now() forward or back. A jumped
// clock makes "now" untrustworthy: a restored snapshot could replay old signed
// assertions whose iat now reads as current, or revive tokens that should have
// expired.
//
// The monotonic clock (process.hrtime.bigint) advances steadily and is immune to
// wall-clock SETTING changes. By comparing how far the wall clock moved against
// how far monotonic time moved since a moving baseline, a wall-clock STEP shows
// up as divergence, while gradual NTP slew stays within tolerance.
//
// In virtualized or cloud mode a detected jump fails CLOSED: callers refuse the
// time-windowed operation rather than trust a clock that just moved. Bare-metal
// is never gated here -- its clock is host-NTP-managed and stable. A cloud
// checkpoint/restore steps the clock the same way a VM snapshot does, so cloud
// is gated like virtualized. This is the GD-server twin of the Regional Server's
// clock-integrity gate; it ADDS a control in the highest-risk environments and
// relaxes nothing.
//
// Scope: this defends against operational clock jumps (snapshot/pause/migrate),
// which sit inside the guest trust boundary. A malicious hypervisor that sets
// the guest clock arbitrarily is outside any in-guest defense and out of scope.
// -----------------------------------------------------------------------------

// A wall-clock step larger than this (ms) is treated as a jump, not slew. NTP
// discipline slews at well under 1 ms/s and steps only at 128 ms, so 2000 ms
// cleanly separates a real VM clock jump (seconds to hours) from benign slew and
// scheduler/GC jitter. Fixed, not env-tunable: loosening it would weaken the
// gate, and a conservative constant is the safe default.
const MAX_DRIFT_MS = 2000;

// Moving baseline: wall time and the steady monotonic clock, captured together.
let baselineWallMs = Date.now();
let baselineMonoNs = process.hrtime.bigint();

function monoDeltaToMs(deltaNs) {
  // Deltas here are small enough that Number() precision is not a concern.
  return Number(deltaNs) / 1e6;
}

// Current wall-vs-monotonic skew against the moving baseline, WITHOUT mutating
// it. Positive skew means the wall clock is ahead of where steady time says it
// should be (jumped forward); negative means it jumped back.
function measure(nowMs, monoNs) {
  const elapsedMonoMs = monoDeltaToMs(monoNs - baselineMonoNs);
  const expectedWallMs = baselineWallMs + elapsedMonoMs;
  return { skewMs: nowMs - expectedWallMs };
}

function rebaseline(nowMs, monoNs) {
  baselineWallMs = nowMs;
  baselineMonoNs = monoNs;
}

// Gate for time-windowed security operations. In virtualized or cloud mode a
// detected wall-clock jump returns ok:false and the caller MUST refuse the
// operation. Bare-metal always returns ok:true (the anomaly is logged, not
// gated).
//
//   opts.virtualized       boolean; pass gdDeploymentMode.summary().substrateVirtualized
//   opts.cloud             boolean; pass gdDeploymentMode.summary().substrateCloud
//   opts.nowMs, opts.monoNs optional injected clocks for deterministic tests
function checkClockIntegrity(opts) {
  const virtualized = !!(opts && opts.virtualized);
  const cloud = !!(opts && opts.cloud);
  // The time-windowed gate applies wherever the wall clock can be checkpoint-
  // jumped: a VM snapshot (virtualized) or a cloud checkpoint/restore (cloud).
  const gated = virtualized || cloud;
  const modeLabel = cloud ? 'cloud' : (virtualized ? 'virtualized' : 'bare-metal');
  const nowMs = (opts && typeof opts.nowMs === 'number') ? opts.nowMs : Date.now();
  const monoNs = (opts && typeof opts.monoNs === 'bigint') ? opts.monoNs : process.hrtime.bigint();

  // Monotonic time must never run backward. If it does, the platform clock
  // source is untrustworthy and we refuse to vouch for it in virtualized/cloud
  // mode.
  if (monoNs < baselineMonoNs) {
    rebaseline(nowMs, monoNs);
    if (gated) {
      console.error('[gd-clock-integrity] monotonic clock moved backward (mode ' + modeLabel + ')');
      return { ok: false, jumped: true, skewMs: null, reason: 'monotonic_regressed' };
    }
    return { ok: true, jumped: true, skewMs: null, reason: 'monotonic_regressed_bare_metal' };
  }

  const { skewMs } = measure(nowMs, monoNs);
  const absSkew = Math.abs(skewMs);

  if (absSkew <= MAX_DRIFT_MS) {
    // Consistent. Absorb gradual slew into the baseline so it never accumulates
    // into a false jump, then report healthy.
    rebaseline(nowMs, monoNs);
    return { ok: true, jumped: false, skewMs: Math.round(skewMs), reason: 'ok' };
  }

  // A jump occurred: the wall clock moved relative to steady time beyond
  // tolerance. Log it, then re-establish the baseline at the corrected wall time
  // so later checks measure fresh divergence instead of re-flagging the same
  // jump forever.
  console.warn('[gd-clock-integrity] wall-clock jump detected (skewMs ' + Math.round(skewMs) + ', thresholdMs ' + MAX_DRIFT_MS + ', mode ' + modeLabel + ')');
  rebaseline(nowMs, monoNs);

  if (gated) {
    return { ok: false, jumped: true, skewMs: Math.round(skewMs), reason: 'clock_jump_detected' };
  }
  return { ok: true, jumped: true, skewMs: Math.round(skewMs), reason: 'clock_jump_bare_metal_tolerated' };
}

// Diagnostic snapshot for health/status surfaces. Does not mutate the baseline.
function status() {
  const monoNs = process.hrtime.bigint();
  const nowMs = Date.now();
  const { skewMs } = measure(nowMs, monoNs);
  return { skewMs: Math.round(skewMs), thresholdMs: MAX_DRIFT_MS };
}

// Test-only: reset the moving baseline to injected (or current) clocks so a
// suite can simulate jumps deterministically.
function _resetForTest(nowMs, monoNs) {
  baselineWallMs = (typeof nowMs === 'number') ? nowMs : Date.now();
  baselineMonoNs = (typeof monoNs === 'bigint') ? monoNs : process.hrtime.bigint();
}

module.exports = { checkClockIntegrity, status, MAX_DRIFT_MS, _resetForTest };
