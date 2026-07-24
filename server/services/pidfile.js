// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Regional Server pidfile  (B6k)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS
//
// services/db-restore-swap.js atomically renames restored bytes over the live
// database path. Its contract is explicit: "the caller MUST close its own
// database handle before calling, so the rename does not write to an unlinked
// ghost inode." Every existing caller runs INSIDE the server, so closing the
// handle is something it can simply do.
//
// The B6k offline rollback tool is the first caller that runs in a DIFFERENT
// process. It cannot close a handle held by the server, so it must instead
// refuse to run while the server is alive. That makes this a CORRECTNESS
// control, not a convenience: without it a rollback against a running server
// leaves the server writing to an unlinked inode and silently discards every
// write it makes from that point on.
//
// WHAT THIS IS, AND WHAT IT IS NOT
//
// This is a liveness MARKER, not a mutual-exclusion lock. It answers one
// question -- "is a server process alive that owns this data root?" -- and it
// is deliberately not named "lock", because it does not serialize anything and
// nothing should be built on it as though it did. Enforcing single-instance
// startup is a separate concern with its own failure modes and is not bundled
// here.
//
// FAILING IN THE SAFE DIRECTION
//
// A PID can be reused by an unrelated process after the server exits without
// cleaning up (a kill -9, a power loss). This module therefore reports a
// reused PID as ALIVE, which makes the tool refuse a rollback it could in fact
// have performed. That is the correct direction to be wrong in: the cost of a
// false "running" is an operator clearing a stale file and retrying, while the
// cost of a false "stopped" is a corrupted database. Nothing here ever removes
// or overrides another live process's marker on its own initiative.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const path = require('path');

const dataRoot = require('../lib/data-root');

// Owner-only. The data root is already 0700; this is defense in depth so the
// marker does not become the one group-readable file in the tree.
const FILE_MODE = 0o600;

// Is a process with this pid currently alive? Signal 0 performs the permission
// and existence checks without delivering a signal.
//   no throw -> alive and ours
//   EPERM    -> alive, owned by another user (still alive: say so)
//   ESRCH    -> no such process
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    if (e && e.code === 'EPERM') return true;
    return false;
  }
}

// Read the marker. Returns null when absent or unreadable/unparseable -- an
// unreadable marker is treated as absent rather than fatal, because a
// corrupted marker must not permanently wedge the tool. Callers get `alive`
// so they can distinguish "stale file, safe to proceed" from "server running".
function read() {
  const file = dataRoot.runtimePidPath();
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (_e) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_e) {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const pid = Number(parsed.pid);
  if (!Number.isInteger(pid) || pid <= 0) return null;
  return {
    path: file,
    pid: pid,
    startedAt: typeof parsed.startedAt === 'string' ? parsed.startedAt : null,
    dataRoot: typeof parsed.dataRoot === 'string' ? parsed.dataRoot : null,
    alive: pidAlive(pid),
  };
}

// True iff a live server process owns this data root.
function isRunning() {
  const held = read();
  return !!(held && held.alive);
}

// Write this process's marker and arrange for it to be removed on exit.
// Never throws: a server must not fail to boot because a liveness marker could
// not be written. It returns what happened so the caller can log it, and the
// offline tool fails CLOSED on a missing marker anyway (absent marker plus a
// running server is indistinguishable from absent marker plus a stopped one,
// so the tool requires an affirmative "not running" it can trust -- see the
// tool's own gate).
function acquire() {
  const file = dataRoot.runtimePidPath();
  const prior = read();
  try {
    dataRoot.ensureDir(path.dirname(file));
    fs.writeFileSync(
      file,
      JSON.stringify({
        pid: process.pid,
        startedAt: new Date().toISOString(),
        dataRoot: dataRoot.dataRoot(),
      }),
      { mode: FILE_MODE },
    );
  } catch (e) {
    return { ok: false, error: e.message, priorHolder: prior };
  }
  registerCleanup();
  return { ok: true, path: file, pid: process.pid, priorHolder: prior };
}

// Remove the marker, but ONLY if it is still ours. A marker written by a
// process that replaced us belongs to that process, and removing it would tell
// the offline tool a live server is stopped.
function release() {
  const file = dataRoot.runtimePidPath();
  const held = read();
  if (!held || held.pid !== process.pid) return false;
  try {
    fs.unlinkSync(file);
    return true;
  } catch (_e) {
    return false;
  }
}

let cleanupRegistered = false;
function registerCleanup() {
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  // 'exit' covers normal termination and process.exit(); the signal handlers
  // cover an operator stopping the server or a supervisor shutting it down.
  // A SIGKILL or a power loss cannot be covered -- that is exactly the stale
  // marker `read()` reports with alive:false.
  process.on('exit', () => { try { release(); } catch (_e) { /* exiting */ } });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => {
      try { release(); } catch (_e) { /* exiting */ }
      process.exit(0);
    });
  }
}

module.exports = {
  FILE_MODE,
  pidAlive,
  read,
  isRunning,
  acquire,
  release,
};
