# Incremental and Differential Backups

FireAlive's R3l series introduced two new backup strategies — **incremental** and **differential** — that capture only the SQLite WAL frames written between a reference backup and the current moment. This document walks through why they exist, how they're shaped, how restore reconstructs the database from a chain of them, the six conditions under which they escalate back to a full backup, and the operational decisions an operator faces when choosing between strategies.

The architectural pieces live in `server/services/wal-extractor.js`, `wal-checkpoint.js`, `backup-incremental.js`, `backup-differential.js`, and `restore-chain.js`. The HTTP surface is in `server/routes/backup.js` (the new `?strategy=` parameter and `GET /:id/chain` endpoint) and `server/routes/restore.js` (`POST /execute-chain/:id`). The frontend integration is in `frontend/firealive-mc.jsx`.

## Why this exists

Three operator problems motivated the feature:

- **Full backups are expensive at high cadence.** An hourly full backup of a multi-gigabyte database wastes I/O and storage capturing pages that didn't change in the last hour. The marginal cost of frequent fulls is mostly redundancy. Incremental backups capture only what changed, dropping the marginal cost to roughly the size of the WAL frames written since the previous backup.

- **Restore complexity should be operator-tunable.** Two operators with the same data can have wildly different restore-time requirements. One wants the cheapest archive, accepts the consequence of walking a 100-link chain on restore. Another wants the simplest restore even if individual archives are larger. Forcing both into the same strategy doesn't work.

- **Long chains have linearly-growing fragility.** A 1000-link incremental chain has 1000x more single points of failure than a 1-link chain. Any one corruption, missing file, or signature failure renders the entire downstream chain unrecoverable. A configurable depth limit lets operators bound this exposure to a tolerable level for their data and SLA.

The feature solves all three by adding incremental, differential, and snapshot strategies alongside the existing full strategy, plus configurable depth limits, plus a chain-walking restore path that gives the same approval / IP-allowlist / audit treatment as single-backup restore.

## The chain abstraction

Every backup in the system has a `backup_strategy` from a 4-value enum:

- `full` — captures the entire database
- `snapshot` — captures the entire database at a point in time (self-contained, not part of any chain)
- `incremental` — captures WAL frames since the immediate predecessor (any strategy)
- `differential` — captures WAL frames since the anchor full

The chain shape depends on the leaf's strategy. For a full or snapshot leaf, the chain is just the leaf itself:

```
[full F1]
```

For a differential leaf, the chain has exactly two links — anchor and leaf:

```
[full F1] ──→ [differential D]
```

For an incremental leaf, the chain can be arbitrarily long, with each incremental's `parent_backup_id` pointing to its immediate predecessor:

```
[full F1] ──→ [incr I1] ──→ [incr I2] ──→ [incr I3] ──→ ... ──→ [incr IN]
```

The `parent_full_backup_id` column on every chain link points directly at the anchor full — an O(1) shortcut that lets queries identify the anchor without walking the chain.

Differentials are a star, incrementals are a list. This is what makes restoring from a differential always a 2-link operation regardless of how many differentials accumulate, while restoring from the Nth incremental requires walking N links back to the anchor.

## A 10-day workload walkthrough

Consider a schedule running once per day. Day 1 has the initial full backup; days 2-9 are runs of either incremental or differential; day 10 is a restore.

### Incremental strategy

| Day | Action | Result | Archive size | Restore needs |
|-----|--------|--------|--------------|---------------|
| 1 | Full | F1 | 2.4 GB | [F1] |
| 2 | Incremental | I1, parent=F1, anchor=F1 | 12 MB | [F1, I1] |
| 3 | Incremental | I2, parent=I1, anchor=F1 | 18 MB | [F1, I1, I2] |
| 4 | Incremental | I3, parent=I2, anchor=F1 | 8 MB | [F1, I1, I2, I3] |
| ... | ... | ... | ... | ... |
| 9 | Incremental | I8, parent=I7, anchor=F1 | 22 MB | [F1, I1, ..., I8] |
| 10 | Restore from I8 | Walk 9-link chain | n/a | 9 manifest verifications, 9 archive decrypts, 8 INCR bundle parses, 8 frame replays |

Total storage for the 9-day chain: ~2.4 GB + ~120 MB = ~2.5 GB. Restoring from day 10 needs every archive in the chain to be present and intact.

### Differential strategy

| Day | Action | Result | Archive size | Restore needs |
|-----|--------|--------|--------------|---------------|
| 1 | Full | F1 | 2.4 GB | [F1] |
| 2 | Differential | D1, parent=F1, anchor=F1 | 12 MB | [F1, D1] |
| 3 | Differential | D2, parent=F1, anchor=F1 | 30 MB | [F1, D2] |
| 4 | Differential | D3, parent=F1, anchor=F1 | 38 MB | [F1, D3] |
| ... | ... | ... | ... | ... |
| 9 | Differential | D8, parent=F1, anchor=F1 | 110 MB | [F1, D8] |
| 10 | Restore from D8 | Walk 2-link chain | n/a | 2 manifest verifications, 2 archive decrypts, 1 INCR bundle parse, 1 frame replay |

Total storage for the 9-day differentials: ~2.4 GB + (12 + 30 + 38 + ... + 110) MB ≈ 2.4 GB + 470 MB = 2.87 GB. Each differential is larger than the previous because it captures all changes since the anchor; the last one captures everything written across the 9-day window.

Restoring from day 10 needs only F1 + D8. Even if D1 through D7 are corrupted, missing, or lost, the restore proceeds.

### Trade-off summary

Incremental stores ~370 MB less but requires every link in the chain to be present at restore time. Differential stores more but tolerates any number of missing intermediate differentials.

## INCR-v1 archive payload format

Both incremental and differential archives wrap WAL frames in a custom binary format inside the standard v2 archive.bin (which is still zstd-compressed and AES-256-GCM-encrypted via the existing `backup-archive` pipeline). The INCR-v1 format is defined in `server/services/backup-incremental.js` and parsed in `server/services/restore-chain.js`.

### Header (16 bytes)

```
Offset  Size  Field
0       4     magic = 'INCR' (ASCII)
4       4     format_version (uint32 BE, currently 1)
8       4     frame_count (uint32 BE)
12      4     page_size (uint32 BE; SQLite WAL page size)
```

### Per frame (44 + page_size bytes)

```
Offset  Size       Field
0       4          frame_no (uint32 BE; 1-indexed within the WAL)
4       4          page_no (uint32 BE; DB page this frame modifies)
8       4          db_size_after_commit (uint32 BE; 0 for non-commit frames)
12      32         sha256 of page_data (raw bytes, not hex)
44      page_size  raw page bytes
```

Total bundle size: `16 + frame_count × (44 + page_size)`. For a 1024-frame bundle with 4 KB pages, that's `16 + 1024 × (44 + 4096)` = ~4.14 MB before zstd compression.

The per-frame SHA-256 hash lets restore verify each page's integrity independently. The manifest also carries a frames descriptor array with the same per-frame metadata; `validateChain` cross-checks both directions (bundle's declared sha256 matches the page bytes, AND bundle's frame metadata matches the manifest's frames descriptor) to catch tampering that would preserve one or the other.

### Why a custom format rather than tar

The frames bundle is a homogeneous list of fixed-shape records. Tar headers add ~512 bytes of overhead per entry; for 1024 frames that's 500 KB of structural waste. A flat binary layout with a fixed per-frame layout is faster to write, faster to parse, and gives the manifest a 1:1 position mapping with the on-disk frames for cross-check.

## Restore mechanics

`server/services/restore-chain.js` exports three core functions used together to restore from any inc/diff leaf.

### walkChain(db, leafBackupId)

Walks the parent pointers backwards from the leaf to the anchor, returning the ordered list `[anchor, ...intermediates_oldest_to_newest, leaf]`.

- Full and snapshot leaves: returns `[leaf]`.
- Differential leaves: returns `[anchor, leaf]` via `parent_backup_id` which points directly at the anchor.
- Incremental leaves: walks `parent_backup_id` backwards until reaching a full or snapshot. Maximum depth `MAX_CHAIN_DEPTH = 1000`. Cycle detection rejects malformed chains.

Throws on cycles, missing parent rows, chain depth above the cap, or unknown `backup_strategy` values.

### validateChain(db, chain)

For every link in the chain:
- manifest file SHA-256 matches `backups.sha256_hash`
- manifest signature verifies against the recorded signing key
- archive.bin SHA-256 matches the manifest's `files[0].sha256`
- wrapped-key.bin SHA-256 matches the manifest's `files[1].sha256`

For each incremental and differential link with `page_count > 0`, additionally:
- unwrap the data key via the Tier-1 KEK envelope
- decrypt and zstd-decompress the archive payload
- parse the INCR-v1 bundle
- verify each frame's declared SHA-256 against the recomputed SHA-256 of its page bytes
- cross-check the manifest's `frames[]` descriptor against the bundle's frame metadata

Returns a structured report `{ok, chainLength, resultsCount, results: [perBackupResult, ...]}`. Stops at the first failed link (a broken predecessor invalidates everything downstream).

### replayChain(db, chain, targetDbPath, options)

Apply the chain to a target database file:

1. Run `validateChain` end-to-end (unless `options.skipValidation`)
2. Extract the anchor full backup's archive payload to `targetDbPath`
3. For each subsequent link in chain order:
   - Unwrap key, decrypt+decompress, parse INCR-v1 bundle
   - For each frame: write `pageBuf` to `targetDbPath` at offset `(page_no - 1) × page_size`
   - If `db_size_after_commit > 0`, ftruncate target to `db_size_after_commit × page_size`

Returns `{ok, anchorBackupId, leafBackupId, chainLength, linksReplayed, framesApplied, validation, error?}`. On partial failure the target file is in an inconsistent state; the recovery path is to restore the pre-restore snapshot that `/execute-chain` writes before invoking replayChain.

## The six escalation reasons

Both `performIncrementalBackup` and `performDifferentialBackup` can escalate to a full backup when their preconditions aren't met. The escalation is transparent to the caller: the response carries `escalated: true` and a `reason` string; the audit log records both the requested strategy and the actual strategy produced. The C67 route surfaces all six in the response field `escalation_reason`.

### no-parent

`findIncrementalParent` returns null (no verified backup with `wal_end_position`). Happens the first time an incremental schedule fires on a fresh install, or after every backup has been deleted.

**Worked example:** Operator creates a schedule with `backup_strategy=incremental` on a fresh install. First run fires. There are zero rows in `backups` matching the eligibility query. The function escalates with `reason=no-parent`. The escalated full becomes the anchor for future runs.

### incompatible-parent

`findIncrementalParent` returned a row but its `wal_end_position` is NULL. Happens when the most recent backup is a pre-R3l format that didn't track WAL positions, or a v2 backup that was created in a non-WAL `journal_mode`.

**Worked example:** Operator upgrades from a pre-R3l version. The most recent backup is a v2 full from R3k that has no `wal_end_position`. First incremental run finds it as parent but can't compute a delta. Escalates.

### no-wal-file

The DB's `<dbpath>-wal` file doesn't exist on disk. Happens when `PRAGMA journal_mode` is not set to WAL, or when WAL was checkpointed and SQLite removed the WAL file.

**Worked example:** Operator changed `journal_mode=DELETE` for some reason. WAL file no longer exists. Incremental backup has nothing to capture.

### no-anchor

The parent's `parent_full_backup_id` couldn't be resolved. Happens when chain pointers are broken — a row references a parent that was deleted, or the parent's anchor was deleted.

**Worked example:** A retention policy deletes the anchor full backup but leaves an incremental whose `parent_full_backup_id` pointed at it. Next incremental finds this orphan as its parent but can't resolve the anchor. Escalates.

### salt-change

The WAL was checkpointed since the parent was taken, causing SQLite to re-salt the WAL header. The parent's recorded `wal_end_position` is no longer valid — the position references the old salt. Detected by the salt mismatch when reading frames in the new WAL.

**Worked example:** Operator manually ran `PRAGMA wal_checkpoint(TRUNCATE)` to shrink the WAL file. Next incremental tries to read frames from `parent.wal_end_position.frameNo + 1` but the salt at that position differs from the WAL header salt. Escalates.

### depth-limit

The chain has reached the configured maximum length; the next incremental would push past the limit. New in R3l C73.

**Worked example:** A schedule has `max_chain_depth = 50` (overriding the global default of 100). 50 incrementals already chained to the current anchor. The 51st run would push to chain length 51, exceeding the limit. Escalates, producing a new anchor full. The chain restarts under that new anchor.

## Depth limits

Long chains have linearly-growing restore cost and linearly-growing single-point-of-failure exposure. The configurable max-chain-depth limit forces a full once the chain would exceed it.

Two sources of truth, in priority order:

1. `backup_schedules.max_chain_depth` — per-schedule override (INTEGER, nullable, R3l C73 schema)
2. `system_meta.max_chain_depth` — global default (TEXT, seeded to `'100'` by the C73 migration)

The C65 `MAX_CHAIN_DEPTH = 1000` in `restore-chain.js` is a runaway-walk safety cap (the chain walker refuses to follow chains longer than 1000 regardless of what the operator configured); the operationally-tunable limit sits well below it.

Differentials are NOT subject to the depth limit. Their restore chain is always 2 links regardless of how many differentials accumulate, so the depth-limit pressure doesn't apply.

### Operator control

```
POST /api/backup-schedules
{
  "name": "Hourly incremental",
  "backup_strategy": "incremental",
  "max_chain_depth": 24,    // force a full every 24 incrementals
  ...
}
```

Or to update the global default:

```
INSERT OR REPLACE INTO system_meta (key, value) VALUES ('max_chain_depth', '50')
```

(No HTTP endpoint exposes the system_meta global setter yet — direct DB manipulation only, intentional given how rarely this should change.)

### Choosing a depth limit

A few defensible starting points:

- **Hourly schedule + 24-hour SLA:** `max_chain_depth = 24` produces one full per day plus 23 incrementals
- **Hourly schedule + tight restore SLA (15 min):** `max_chain_depth = 4` produces one full every 4 hours
- **Daily schedule + storage-budget-driven:** `max_chain_depth = 100` (the default) produces one full every ~100 days
- **Continuous integration / test environment:** `max_chain_depth = 10` keeps test-data fresh and bounds restore time

## Failure modes

What happens when something goes wrong with a chain. All of these are detected by `validateChain` before any destructive work happens.

### Link N's archive file is missing

`fs.existsSync` check in the `/execute-chain` endpoint catches this. Returns 400 with the missing link's id and the file label (manifest / archive / signature / wrappedKey). No restore attempted. Operator can investigate the missing file and either restore from backup-of-backup or pick a different leaf.

### Link N's manifest SHA-256 doesn't match `backups.sha256_hash`

The on-disk manifest was modified or corrupted after the backup was created. `validateChain` reports `step: 'manifest_sha256'` failure. The chain is unrecoverable downstream of this point — restore from an earlier leaf or from an alternative chain (if differentials exist alongside incrementals).

### Link N's signature doesn't verify

The manifest was tampered with, OR the signing key has been rotated and the old key's public material is no longer available. `validateChain` reports `step: 'manifest_signature'` failure. Signing-key public material is preserved through rotations (see backup-signing-keys.js), so this typically indicates tampering.

### Link N's INCR bundle has a per-page SHA-256 mismatch

A page's bytes don't hash to the value recorded in the bundle (or the bundle's metadata doesn't match the manifest's frames descriptor). `validateChain` reports `step: 'incr_bundle_per_page'` failure with the offending frame number. The chain is unrecoverable downstream.

### Salt change since backup was taken

A WAL checkpoint between the backup and the restore attempt has re-salted the WAL. This doesn't affect restore (restore extracts the anchor's DB payload and replays frames into it; it doesn't reference the live WAL), but it does mean future incrementals can't extend this chain. The escalation reason `salt-change` will fire next time an incremental tries.

## Operator decision matrix

| Need | Recommended strategy | Why |
|------|----------------------|-----|
| Predictable hourly snapshots of compliance-relevant tables | snapshot | Self-contained, restorable independently, no chain bookkeeping |
| Cheap nightly captures, occasional restore (developer reset) | incremental + small depth limit (10-20) | Storage minimized, chain stays manageable |
| Cheap nightly captures, frequent restore (test env reset) | differential | Each differential is independently restorable; restore time stays low |
| Long-retention frozen archives (no restore expected) | full + retention policy | Simplest shape, no chain dependencies |
| Just-in-case before a risky change | snapshot | Captures point-in-time without joining a chain |
| Hourly backups with 15-minute restore SLA | differential | Restore complexity capped at 2 links regardless of hours elapsed |
| Hourly backups, tight storage budget, no SLA pressure | incremental + depth limit ~50 | Smallest archives, accept longer restore time |

## API reference

### POST /api/backup?strategy=...

On-demand backup with strategy selection. Body is empty or `{}`. Returns the standard backup result plus:

```
{
  requested_strategy: "incremental",
  actual_strategy: "incremental",   // or "full" if escalated
  escalated: false,
  escalation_reason: null,          // or one of the six reason strings
  backup_strategy: "incremental",
  parent_backup_id: <id>,
  parent_full_backup_id: <id>,
  page_count: 48,
  wal_start_position: "32:0",
  wal_end_position: "196640:48",
  ...
}
```

### GET /api/backup/:id/chain

Read-only chain preview. No locks, no audit, no validation overhead. Returns:

```
{
  ok: true,
  leafBackupId: <id>,
  anchorBackupId: <id>,
  chainLength: 3,
  totalPageCount: 142,
  restorable: true,         // every link's files exist AND every link is status='verified'
  chain: [
    {
      id, backup_strategy, created_at, page_count, size_bytes,
      parent_backup_id, parent_full_backup_id, status,
      filesPresent, missingFiles, wal_start_position, wal_end_position
    },
    ...
  ]
}
```

### POST /api/restore/execute-chain/:id

Chain restore with full approval-gate machinery. Body shape matches `/execute/:id`:

```
{
  confirmHash: "<first 8 chars of LEAF backup's hash>",
  approval_id: <id>         // when approval policy requires it
}
```

Steps: auth check, leaf lookup, walkChain, confirm hash, approval pre-validate, file existence check for every chain link, validateChain end-to-end, approval consume, pre-restore snapshot of current DB (prefix `pre-restore-chain-<ts>.db`), replayChain to DB_PATH with `skipValidation:true`, audit log `DATABASE_RESTORED`.

Error codes: `CHAIN_RESTORE_REQUIRED` (from `/execute/:id` when called with a chain backup, redirecting), `CHAIN_WALK_FAILED` (walkChain threw), `CHAIN_VALIDATION_FAILED` (validateChain reported `!ok`).

## Implementation map

| File | Responsibility |
|------|----------------|
| `server/services/wal-extractor.js` | Read SQLite WAL frames, compute per-page SHA-256, serialize position descriptors |
| `server/services/wal-checkpoint.js` | Safe coordination of `PRAGMA wal_checkpoint`; `withAutoCheckpointDisabled` wrapper |
| `server/services/backup-incremental.js` | `performIncrementalBackup`, INCR-v1 bundle builder, parent / depth-limit resolution |
| `server/services/backup-differential.js` | `performDifferentialBackup` (anchor-full parent variant of incremental) |
| `server/services/restore-chain.js` | `walkChain`, `validateChain`, `replayChain`, INCR-v1 bundle parser |
| `server/services/backup-schedules.js` | Validation for `backup_strategy`, `backup_kind`, `destination_filter`, `max_chain_depth` |
| `server/db/init.js` | Schema migrations (C53/C54/C55/C73 columns + system_meta seeds) |
| `server/routes/backup.js` | `POST /?strategy=`, `GET /:id/chain` |
| `server/routes/restore.js` | `POST /execute-chain/:id`, redirect block in `POST /execute/:id` |
| `frontend/firealive-mc.jsx` | Strategy form fields, chain panel, restore-preview modal, Take-Incremental/Differential buttons |

## See also

- `docs/full-suite-backup.md` — the v2 four-file layout that incremental/differential archives also use
- `docs/two-person-restore.md` — the approval policy machinery that `/execute-chain` reuses
- `FEATURE-GUIDE.md` — operator-facing summary in the Data & Backup section
