# Full-Suite Backup

FireAlive's full-suite backup endpoint produces an archive bundling the entire instance — database, configuration, version manifest, and (on MC-side) signing-key material — into an encrypted, signed, four-file artifact suitable for disaster-recovery restoration. This document describes the architecture, the per-realm bundle contents (both realms use the same v2 engine), the operating procedures, and how full-suite backups interact with the two-person restore approval workflow.

## Why this exists

Three operator problems motivate the feature:

- **Single-DB backups lose configuration.** The pre-R3k backup path (`POST /api/backup`) captures only the SQLite database file. An operator restoring from that backup recovers user accounts and audit history but loses the configuration table state (integrations, webhook URLs, key bindings, branding), the signing-key material, and the version manifest needed to verify rollback safety. Recovery from this state is hours of manual reconstruction.
- **No archive-level signature.** A backup file on backup media is a download without provenance. An attacker with access to a backup destination (NAS, S3, SFTP) can swap a malicious archive for a legitimate one and the restore endpoint cannot tell.
- **No tamper-evident manifest.** A backup file taken at 02:00 last Tuesday should still verify as that file when an auditor checks it next quarter. Without a manifest hash committed at backup time, drift between "what we backed up" and "what's on the backup volume" is invisible.

The full-suite backup endpoint resolves all three by capturing the entire suite (DB + config + signing keys + version manifest) into an AES-256-GCM-encrypted archive, wrapping the archive's data key to the operator's KEK, and (on MC-side) Cosign-signing the manifest separately so that an offline auditor can verify both the archive integrity and the manifest authenticity.

## Architecture overview: MC vs GD

The full-suite backup lives on both realms atop the same v2 backup engine. What differs is only the bundle contents each realm captures:

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

### GD-side

- **Service:** `packages/global-dashboard-server/services/gd-backup-full-suite.js`
- **Route:** `POST /api/backup/full-suite` (ciso JWT); also `POST /api/backup?strategy=full-suite`
- **Schema:** the GD `backups` table with `format_version`, `manifest_path`, `archive_path`, `manifest_sig_path`, `wrapped_key_path`, `signing_key_id`. Full-suite is recorded `type='full'`, `format_version=2` (the GD distinguishes strategies by `type`, without a separate `kind` column).
- **Output (v2 four-file layout):**

```
data/backups/<id>-fullsuite/
  archive.tar.gz.enc     ← AES-256-GCM-encrypted bundle (DB + config + version manifest)
  wrapped-key.bin        ← bundle data key wrapped to the GD Tier-1 KEK
  manifest.json          ← canonical manifest with per-file SHA-256
  manifest.sig           ← Ed25519 signature over manifest.json
```

The GD bundle (`global-dashboard.db` + `config-snapshot.json` + `version-manifest.json`) is tarred, then run through the same pipeline as a single-DB v2 backup: that tar is the encrypted archive's payload, its data key is wrapped to the GD Tier-1 KEK, and a canonical manifest is Ed25519-signed. Every full-suite backup is also appended to the backup attestation chain. Restoration requires both the archive and the wrapped key — the archive alone is undecryptable.

### Realm parity

Both realms run the identical v2 engine; there is no format divergence. The GD was brought to full MC backup parity in Sub-phase 6b — the v2 engine, WAL-tracked incremental and differential backups, and the encrypted full-suite and snapshot strategies. The GD runs on the CISO's machine, arguably the most sensitive host in the deployment, so no backup strategy writes plaintext to disk or off-site: the encrypted, signed, chain-attested four-file artifact is the only shape produced. The GD's own regression suite asserts every strategy is callable and encrypted.

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

### GD version manifest (inside the bundle)

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

GD's `version-manifest.json` lives inside the archive rather than separately. There is a separate canonical `manifest.json`, Ed25519-signed exactly as on the MC — the signed manifest is the integrity gate.

## The capture pipeline

Both realms follow the same v2 pipeline:

1. **DB snapshot via VACUUM INTO.** Both sides issue `VACUUM INTO '<workdir>/<db-file>'` against SQLite. This is the canonical SQLite hot-snapshot method — it produces a transactionally consistent copy without locking the live database. Falls back to `fs.copyFileSync` on the rare older SQLite build that restricts VACUUM INTO.

2. **Config snapshot.** Both sides dump all rows from the `config` table into a flat key/value JSON object at `<workdir>/config-snapshot.json`.

3. **Version manifest.** Both sides write `version-manifest.json` with the snapshot metadata (version, fuse, build_id, table counts).

4. **Archive assembly + encryption.** Both sides tar the workdir into a single bundle, then encrypt it under a fresh AES-256-GCM data key, producing `archive.tar.gz.enc`. The plaintext bundle never touches the backup destination.

5. **Key wrapping, signing, persistence, attestation.** Both sides wrap the data key to the operator's KEK (`wrapped-key`), build a canonical `manifest.json` with per-file SHA-256 and sign it (MC: Cosign; GD: Ed25519), atomically write the four files, insert a `backups` row (`format_version=2`), and append a CREATE entry to the backup attestation chain.

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
  "format_version": 2,
  "type": "full",
  "kind": "full-suite",
  "manifest_path": "data/backups/1a2b3c4d5e6f7a8b-fullsuite/manifest.json",
  "archive_path": "data/backups/1a2b3c4d5e6f7a8b-fullsuite/archive.tar.gz.enc",
  "manifest_sig_path": "data/backups/1a2b3c4d5e6f7a8b-fullsuite/manifest.sig",
  "wrapped_key_path": "data/backups/1a2b3c4d5e6f7a8b-fullsuite/wrapped-key.bin",
  "size_bytes": 4194304,
  "manifest_sha256": "abc123...",
  "status": "verified",
  "chain_entry": { "id": 42, "this_hash": "..." }
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

Full-suite archives live under `data/backups/` on the FireAlive host. Both realms use the v2 layout: one subdirectory per backup containing the four files (encrypted archive, wrapped key, manifest, signature).

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
| Backup archive replaced on backup media | Both realms: the manifest signature detects tampering offline (MC: Cosign; GD: Ed25519), and the archive's SHA-256 is verified against the signed manifest before restore. |
| Captured config exposes secrets | Both realms: the backup content key is wrapped to the operator's KEK (GD: Tier-1 KEK); the archive is undecryptable without the KEK, so a captured archive discloses nothing. |
| Captured signing-key material exfiltration | MC: private keys remain Tier-1-KEK-wrapped in `cloud_iac_signing_keys.private_key_wrapped`; archive includes only the wrapped form. Recovery requires the receiving instance to have the same KEK. |
| Restore of malicious archive overwrites live data | Two-person restore approval workflow (see `docs/two-person-restore.md`) prevents single-admin destructive action. |
| Rollback via restoring an old backup | Fuse-counter check at startup detects: post-restore fuse counter is recorded in `system_meta`; a restore that lowers it without operator override fails to start. |
| Backup-creation DoS | Endpoint is rate-limited by the global `apiLimiter` middleware. |

## Related documents

- `docs/cloud-iac-generation.md` — sibling feature using the same Cosign signing infrastructure (MC-side)
- `docs/cicd-generation.md` — sibling feature using the same SBOM + Cosign infrastructure
- `docs/two-person-restore.md` — the destructive-operation gate that controls restoration from full-suite backups
- `docs/backup-destinations-eu.md` — operational guidance on EU-sovereignty-compatible backup destinations
