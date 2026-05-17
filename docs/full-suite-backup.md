# Full-Suite Backup

FireAlive's full-suite backup endpoint produces an archive bundling the entire instance — database, configuration, version manifest, and (on MC-side) signing-key material — into a single tar.gz suitable for disaster-recovery restoration. This document describes the architecture, the MC-side v2 vs GD-side v1 shape divergence, the operating procedures, and how full-suite backups interact with the two-person restore approval workflow.

## Why this exists

Three operator problems motivate the feature:

- **Single-DB backups lose configuration.** The pre-R3k backup path (`POST /api/backup`) captures only the SQLite database file. An operator restoring from that backup recovers user accounts and audit history but loses the configuration table state (integrations, webhook URLs, key bindings, branding), the signing-key material, and the version manifest needed to verify rollback safety. Recovery from this state is hours of manual reconstruction.
- **No archive-level signature.** A backup file on backup media is a download without provenance. An attacker with access to a backup destination (NAS, S3, SFTP) can swap a malicious archive for a legitimate one and the restore endpoint cannot tell.
- **No tamper-evident manifest.** A backup file taken at 02:00 last Tuesday should still verify as that file when an auditor checks it next quarter. Without a manifest hash committed at backup time, drift between "what we backed up" and "what's on the backup volume" is invisible.

The full-suite backup endpoint resolves all three by capturing the entire suite (DB + config + signing keys + version manifest) into one archive, computing a SHA-256 hash of the archive at write time, and (on MC-side) Cosign-signing the manifest separately so that an offline auditor can verify both the archive integrity and the manifest authenticity.

## Architecture overview: MC vs GD

The full-suite backup lives at two architectural locations with different shapes due to backup-schema divergence between MC and GD:

### MC-side: v2 backup engine

- **Service:** `server/services/backup-full-suite.js`
- **Route:** `POST /api/backup/full-suite` (admin JWT)
- **Schema:** `backups` table with R3k C2 ALTER adding `kind` column (`'full-suite'` distinguishes from `'single-db'`); v2-aware columns `format_version`, `manifest_path`, `archive_path`, `signature_path`, `wrapped_key_path`.
- **Output (v2 four-file layout):**

```
data/backups/<id>/
  manifest.json          ← captured snapshot + hashes
  archive.tar.gz         ← DB + config + signing keys
  signature              ← Cosign signature of manifest.json
  wrapped-key            ← envelope-encrypted backup-content key
```

The four-file layout separates the signed-and-verified manifest from the data archive. An auditor can verify the manifest signature without unpacking the archive, then verify the archive's SHA-256 against the manifest's recorded hash. The wrapped-key file holds an AES-256-GCM-wrapped data encryption key sealed to the operator's KEK; restoration requires both the archive and the wrapped-key (the archive alone is undecryptable).

### GD-side: v1 backups schema

- **Helper:** `gdPerformFullSuiteBackup` (inline in `packages/global-dashboard-server/index.js`)
- **Route:** `POST /api/backup/full-suite` (ciso JWT)
- **Schema:** `backups` v1 (single `destination` column, SHA-256 in `hash` column, no v2 columns).
- **Output (single-archive layout):**

```
data/backups/
  <id>-firealive-gd-full-suite.tar.gz
```

The archive bundles `global-dashboard.db`, `config-snapshot.json`, and `version-manifest.json` in one tar.gz. The SHA-256 of the entire archive lives in `backups.hash`. The literal token `firealive-gd-full-suite` in the filename distinguishes full-suite archives from plain v1 single-DB backups by inspection.

### Why the divergence

GD has not yet been migrated to the v2 backup engine. Implementing a parallel v2 engine for GD purely to enable full-suite backups would have doubled the Sub-phase 6 lift. The pragmatic path was a v1-shape adaptation that captures the same logical contents (DB + config + version manifest) in a single hashed archive without a separate manifest, signature, or wrapped key.

The cost of this divergence is documented:

- The MC-side regression runner's `backups v2-aware` check intentionally fails on GD because the v2 columns it asserts are intentionally absent from GD's schema. This is diagnostic surface flagging the GD's v1 backup posture, not an error.
- GD full-suite archives have SHA-256 tamper-detect (anyone can verify the archive matches `backups.hash` after retrieval) but no archive-level Cosign signature. A future GD v2 backup engine migration would unlock cosign-signed archives and a passing regression check.

## What's in a bundle

### MC v2 manifest schema

```json
{
  "format_version": "firealive-mc-full-suite-v2",
  "backup_id": "9c8d3f2e1a7b6c5d",
  "kind": "full-suite",
  "captured_at": "2026-05-17T12:00:00Z",
  "instance": {
    "version": "1.0.36",
    "fuse_counter": 28,
    "build_id": "20260516.1"
  },
  "contents": {
    "database_hash": "sha256:abc123...",
    "config_rows_count": 47,
    "users_count": 12,
    "audit_log_count": 8421,
    "signing_keys": {
      "active": 1,
      "rotated": 2,
      "revoked": 0
    }
  },
  "archive_hash": "sha256:def456...",
  "wrapped_key_hash": "sha256:789xyz..."
}
```

The manifest is signed with the active `backup_signing_keys` row's Ed25519 key. The signature lives at `data/backups/<id>/signature` as a Cosign-format blob.

### GD v1 manifest schema (in-archive)

```json
{
  "format": "firealive-gd-full-suite-v1",
  "backup_id": "1a2b3c4d5e6f7a8b",
  "captured_at": "2026-05-17T12:00:00Z",
  "version": {
    "version": "1.0.36",
    "fuse_counter": 28,
    "build_id": "20260516.1"
  },
  "management_consoles": {"total": 5, "active": 4},
  "signing_keys": {"total": 3, "active": 1},
  "side": "gd"
}
```

GD's `version-manifest.json` lives inside the archive rather than separately. There is no GD-side signature on the manifest — the SHA-256 of the entire archive in `backups.hash` is the integrity gate.

## The capture pipeline

Both MC and GD follow the same five logical steps with implementation differences:

1. **DB snapshot via VACUUM INTO.** Both sides issue `VACUUM INTO '<workdir>/<db-file>'` against SQLite. This is the canonical SQLite hot-snapshot method — it produces a transactionally consistent copy without locking the live database. Falls back to `fs.copyFileSync` on the rare older SQLite build that restricts VACUUM INTO.

2. **Config snapshot.** Both sides dump all rows from the `config` table into a flat key/value JSON object at `<workdir>/config-snapshot.json`.

3. **Version manifest.** Both sides write `version-manifest.json` with the snapshot metadata (version, fuse, build_id, table counts).

4. **Archive assembly.** Both sides shell out to `tar -czf <archive>.tar.gz -C <workdir> .` to bundle the workdir into a gzipped tarball.

5. **Hashing + persistence + (MC-only) signing.** Both sides compute SHA-256 of the archive bytes. MC additionally invokes Cosign to sign the separate manifest.json and writes the wrapped-key file. Both insert a row into `backups` with the archive path, size, and hash.

## Routes

Both sides:

```
POST /api/backup/full-suite
  Authorization: Bearer <admin JWT on MC, ciso JWT on GD>
  Body: (empty — server reads all state from the DB)
```

Success response (MC):

```json
{
  "id": "9c8d3f2e1a7b6c5d",
  "kind": "full-suite",
  "format_version": "firealive-mc-full-suite-v2",
  "manifest_path": "/path/.../manifest.json",
  "archive_path": "/path/.../archive.tar.gz",
  "signature_path": "/path/.../signature",
  "wrapped_key_path": "/path/.../wrapped-key",
  "manifest_hash": "sha256:abc...",
  "archive_hash": "sha256:def...",
  "signing_key_id": "1234abcd5678efgh",
  "size_bytes": 5242880
}
```

Success response (GD):

```json
{
  "id": "1a2b3c4d5e6f7a8b",
  "type": "full",
  "kind": "full-suite",
  "destination": "/path/.../1a2b3c4d5e6f7a8b-firealive-gd-full-suite.tar.gz",
  "size_bytes": 4194304,
  "hash": "sha256:abc123...",
  "manifest": { ... in-archive manifest object ... },
  "status": "completed"
}
```

## Operating the feature

### From the MC frontend

The Backup tab's **Trigger Full Backup Now** button (R3k C38 wiring) issues `POST /api/backup/full-suite` against the MC. The Backups list updates with an optimistic placeholder, then refreshes with the server-returned id, size, and manifest hash. Audit events `FULL_SUITE_BACKUP_TRIGGERED` (request start), `FULL_SUITE_BACKUP_CREATED` (success), or `FULL_SUITE_BACKUP_FAILED` (error) are written to both the server-side `audit_log` and the local activity feed.

### From the GD frontend

The Backup & Restore tab's **Trigger Manual Backup Now** button (R3k C41 wiring) issues `POST /api/backup/full-suite` against the GD. A result card displays the backup id, size in MB, archive path, and first-32-hex of SHA-256. Audit event `FULL_SUITE_BACKUP_CREATED` writes to GD's `audit_log` and the local activity feed.

### From the API directly

```bash
curl -X POST https://<firealive-host>/api/backup/full-suite \
  -H "Authorization: Bearer <admin JWT>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

There is no request body — the endpoint captures the live state of the database it's running against. To take a backup of a different FireAlive instance, an operator must direct the request to that instance's hostname.

## Audit trail

| Event | Severity | Detail | Sides |
|-------|----------|--------|-------|
| `FULL_SUITE_BACKUP_TRIGGERED` | info | (no detail) | MC only — frontend logs request start |
| `FULL_SUITE_BACKUP_CREATED` | info | `id=<id> size=<bytes> hash=<first16hex>` | MC + GD |
| `FULL_SUITE_BACKUP_FAILED` | warning | `<first200chars of error message>` | MC + GD |

The events persist in the standard audit log surface and are queryable via the audit log endpoints.

## Storage and retention

Full-suite archives live under `data/backups/` on the FireAlive host. The MC v2 layout uses one subdirectory per backup containing four files; the GD v1 layout uses one tarball per backup directly under `data/backups/`.

Neither side applies automatic retention to full-suite archives — these are operator-curated artifacts. The recommended pattern is to push archives off-host to long-term backup storage (S3 with Object Lock, Azure Blob immutable, off-site NAS with WORM) immediately after each backup completes, then prune local copies on the org's standard rotation cadence.

The `backups` table retains rows indefinitely regardless of whether the archive remains on disk. If an archive is manually deleted, the row remains for audit purposes; any future restore attempt against that id will fail at the file-read step with a clear error.

## Restoration

Restoration from a full-suite backup follows the existing two-person restore approval workflow documented in `docs/two-person-restore.md`. The restore endpoint accepts full-suite archive ids identically to single-DB archive ids — the two-person approval gate, MFA-at-approval check, and configurable cooling-off window apply uniformly.

The actual restore mechanics differ between single-DB and full-suite:

- **Single-DB restore** overwrites only the SQLite file. Configuration, signing keys, and signing-key wrap state remain from the live instance.
- **Full-suite restore** overwrites the DB *and* replays the captured `config` rows *and* (MC-side only) unwraps and re-imports the captured signing-key material. The post-restore instance is byte-equivalent to the source at capture time.

Operators with mixed backup types should label them clearly in their storage destination — restoring a single-DB backup over a configuration crash recovers user data but not configuration state, while a full-suite restore on a fresh node fully reconstitutes the source instance.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Backup archive replaced on backup media | MC: Cosign signature on manifest detects tampering offline. GD: SHA-256 in `backups.hash` detects tampering when matched against retrieved archive. |
| Captured config exposes secrets | MC v2: backup content key is wrapped to operator's KEK; archive is undecryptable without the KEK. GD v1: archive contains plaintext config; operators must store full-suite archives only in encrypted destinations. |
| Captured signing-key material exfiltration | MC: private keys remain Tier-1-KEK-wrapped in `cloud_iac_signing_keys.private_key_wrapped`; archive includes only the wrapped form. Recovery requires the receiving instance to have the same KEK. |
| Restore of malicious archive overwrites live data | Two-person restore approval workflow (see `docs/two-person-restore.md`) prevents single-admin destructive action. |
| Rollback via restoring an old backup | Fuse-counter check at startup detects: post-restore fuse counter is recorded in `system_meta`; a restore that lowers it without operator override fails to start. |
| Backup-creation DoS | Endpoint is rate-limited by the global `apiLimiter` middleware. |

## Related documents

- `docs/cloud-iac-generation.md` — sibling feature using the same Cosign signing infrastructure (MC-side)
- `docs/cicd-generation.md` — sibling feature using the same SBOM + Cosign infrastructure
- `docs/two-person-restore.md` — the destructive-operation gate that controls restoration from full-suite backups
- `docs/backup-destinations-eu.md` — operational guidance on EU-sovereignty-compatible backup destinations
