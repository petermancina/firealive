# Golden Baseline & Configuration Snapshots

FireAlive can capture a management console’s entire configuration as a
named snapshot, roll back to an earlier snapshot, and move a known-good
configuration between deployments as a single signed file. This document
describes the snapshot domain, the secrets-free design, the portable bundle
format, the import safety gate, the cross-deployment trust model, and how to
operate the feature.

## Why this exists

- **Configuration drift and mistakes need a rollback.** A lead tuning routing,
  SLA, reporting, and integrations needs to checkpoint a working configuration
  and return to it if a change goes wrong, without hand-reconstructing dozens
  of settings.
- **New and sister deployments need a known-good starting point.** Standing up
  a fresh console, or aligning a second region with an approved configuration,
  should not be a manual copy of every setting.
- **Configuration must move without leaking secrets.** A portable baseline that
  carried API keys or credentials would be a liability on disk and in transit.
  The baseline is deliberately secrets-free.

## What a snapshot captures

The capture domain is an explicit allowlist, defined in
`server/services/golden-baseline.js`. Only allowlisted keys and tables are
captured, so an unknown or sensitive key can never enter a snapshot. The domain
covers three areas:

- **Team configuration** — a fixed set of `team_config` keys (routing, SLA,
  wellbeing, scheduling, reporting, notification, and platform settings).
- **Instance configuration** — a fixed set of `config` table keys.
- **Configuration tables** — a set of per-table sections, each captured in
  one of three modes:
  - *rows*: `kms_providers`, `backup_destinations`, `backup_schedules`,
    `ai_provider_config`.
  - *singleton*: `scheduling_platform_config`, `gd_push_config`,
    `report_config`, `sla_config`, `notification_config`.
  - *manifest-only*: `integration_config`, `external_restore_sources`. These
    hold required secret columns, so the baseline records only that a row
    exists (a manifest), never the secret itself, and an import never creates
    or deletes these rows.

### Secrets are never captured

Where a captured row would otherwise contain a secret (an encrypted credential,
a private key), the snapshot stores a `secretsPresent` marker in place of the
value. On import or revert, the corresponding integration is restored in a
disabled, pending-credentials state: every non-secret setting is applied, but
the operator must re-enter the credential before the integration is used again.
This is why a revert or import reports which integrations need attention.

## The capture digest

A snapshot’s payload is serialized with a deterministic, key-sorted
canonical JSON encoding and hashed with SHA-256. The same configuration always
produces the same digest, which is what makes the signature verifiable on a
different deployment.

## The bundle format (FA-GB1)

Exporting a snapshot produces a single JSON file in the FA-GB1 format:

```
{
  "format": "FA-GB1",
  "baselineSchemaVersion": 1,
  "appVersion": "<producing deployment app version>",
  "instanceLabel": "<producing deployment label>",
  "exportedAt": "<ISO timestamp>",
  "snapshot": { "id": "...", "name": "...", "origin": "...", "createdAt": "..." },
  "payload": { "teamConfig": {...}, "configTable": {...}, "tables": {...} },
  "sha256": "<hex digest of the canonical payload>",
  "signature": "<base64 Ed25519 signature over the digest>",
  "signingKey": { "publicKeyPem": "<PEM>", "fingerprint": "<sha256 of the key>" }
}
```

The signature is produced with the exporting deployment’s active Ed25519
report-signing key. The bundle is self-contained: it carries the payload, its
digest, the signature, and the producing key’s public half and fingerprint.
Only current-format snapshots can be exported; legacy snapshots can be reverted
locally but not exported.

## Routes

All endpoints are mounted under `/api/config-baseline`, are admin-only, and sit
behind the configuration-lock chokepoint (mutations are blocked while the
console is locked). Revert and import additionally require a fresh WebAuthn
MFA step-up, sent as `stepup` in the request body.

```
GET    /api/config-baseline            list snapshots and the retention cap
POST   /api/config-baseline            save the current configuration
GET    /api/config-baseline/keys       list trusted signing keys
POST   /api/config-baseline/keys/validate  preview a pasted key’s fingerprint
POST   /api/config-baseline/keys       register an external signing key
DELETE /api/config-baseline/keys/:id   revoke a registered external key
POST   /api/config-baseline/import     import a signed FA-GB1 bundle (step-up)
GET    /api/config-baseline/:id/export download the signed FA-GB1 bundle
GET    /api/config-baseline/:id/diff   change report vs the current configuration
POST   /api/config-baseline/:id/revert revert to a snapshot (step-up)
DELETE /api/config-baseline/:id        delete a snapshot
```

`POST /api/config-baseline/import?dryRun=1` runs the full validation gate and
returns the change report without applying anything.

## The import gate

Import is the security-sensitive operation, and it is fail-closed at every
step. The order is enforced in `server/routes/config-baseline.js`, with the
validation layer in `server/services/golden-baseline-validate.js`:

1. **Scan the file.** The raw bytes are run through the content sanitizer and
   the malware scanners in all-configured mode (every configured scanner must
   return clean). If no scanner is configured, the import is refused with
   `MALWARE_SCANNER_REQUIRED` — a baseline is never applied unscanned.
2. **Validate the envelope.** The FA-GB1 format and schema version are checked.
3. **Verify the signature.** The payload digest is recomputed and checked
   against the bundle (`DIGEST_MISMATCH` on a mismatch), then the signature is
   verified **by fingerprint against a key already registered as trusted**
   (`SIGNING_KEY_UNTRUSTED` if the key is unknown or revoked,
   `SIGNATURE_INVALID` if the signature does not verify). The public key
   carried inside the bundle is never trusted directly.
4. **Validate the payload.** The configuration is checked against the domain
   allowlist and bounded (key allowlist, value types, size and depth caps,
   anti-smuggling checks). Unknown keys and disguised secrets are rejected.
5. **Snapshot, then apply.** The current configuration is captured as an
   automatic pre-import snapshot (the rollback point), then the new
   configuration is applied as a single transactional full-replace. If apply
   fails, it rolls back and the pre-import snapshot remains.

## Trust model

Verifying a baseline requires the producing deployment’s public key to be
registered first, which is what makes a cross-deployment import a deliberate
trust decision rather than something a file can assert about itself.

- **Register.** Obtain the producing deployment’s key fingerprint through a
  trusted out-of-band channel. Paste the public key and call validate to see
  the fingerprint the console computes; confirm it matches; then register. A
  pasted private key is rejected outright.
- **Verify.** An import verifies against the registered key whose fingerprint
  matches the bundle. A same-deployment round-trip (export then import on the
  same console) works without registration because that console’s own key is
  already present.
- **Revoke.** Revoking a registered external key is immediate: any later
  baseline signed by it fails verification. Revocation preserves the audit
  trail (who registered the key and when). Local keys are never revoked through
  this path.

Key storage and the signing/verification primitives live in
`server/services/report-signing-keys.js`. External keys are stored
verification-only (no private material, never active for signing).

## Operating the feature

### From the MC frontend

The Configuration Snapshots card and the Trusted Baseline Signing Keys card are
in the Backup tab. The card supports Save Current, Change Report, Revert,
Export, Delete, and Import Baseline; the keys card supports validating,
registering, and revoking external keys. Revert and import prompt for the
passkey step-up and report any integrations that came back pending credentials.

### From the API directly

Use the routes above with an admin token. Import and revert bodies must include
a `stepup` assertion obtained from `/api/mfa/stepup/options`. Use `?dryRun=1` on
import to validate a bundle before applying it.

## Audit trail

Every mutation is written to the tamper-evident audit log:
`CONFIG_SNAPSHOT_SAVED`, `CONFIG_SNAPSHOT_REVERTED`, `CONFIG_SNAPSHOT_DELETED`,
`CONFIG_SNAPSHOT_EXPORTED`, `CONFIG_SNAPSHOT_IMPORTED`, `CONFIG_SNAPSHOT_PRUNED`,
`BASELINE_KEY_REGISTERED`, and `BASELINE_KEY_REVOKED`.

## Storage and retention

Snapshots are stored in the `config_snapshots` table with their origin
(`manual`, `pre-revert`, or `pre-import`), the producing app version, the
baseline schema version, the canonical payload, and its digest. A retention cap
(default 20, held in the `config_snapshot_retention` setting) prunes the oldest
snapshots automatically when a new one is saved; the automatic pre-revert and
pre-import snapshots count toward the cap.

## Threat model

- A tampered baseline file is rejected: the digest check and the Ed25519
  signature both fail.
- A baseline from an untrusted or revoked key is rejected: verification is by
  fingerprint against a key the operator explicitly registered.
- A baseline cannot smuggle a secret or an unknown setting into the
  configuration: the import validates against the domain allowlist and rejects
  disguised secret columns.
- A baseline is never applied unscanned: with no malware scanner configured,
  import is refused.
- A baseline never carries secrets: credentials and private keys are left out
  of the snapshot, and affected integrations import disabled until their
  credentials are re-entered.

## Related documents

- `report-verification.md` — the Ed25519 report-signing keys and the
  fingerprint-based verification this feature reuses.
- `full-suite-backup.md` — whole-instance disaster-recovery backup (distinct
  from the configuration-only baseline described here).
