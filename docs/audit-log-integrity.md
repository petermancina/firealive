# Audit Log Integrity

FireAlive's audit log is **tamper-evident**, not merely append-only. Every entry is bound into a per-row SHA-256 hash chain, the chain head is periodically notarized by an Ed25519-signed checkpoint, and each event is also shipped to the operator's SIEM/SOAR as an external anchor. This document describes the architecture, the exact canonical specification (so an auditor can verify the chain independently of FireAlive), the checkpoint cadence, the threat model and its honest scope, and how to verify a checkpoint signature offline with OpenSSL.

The same design runs on the management console (MC) and the Global Dashboard (GD); the only differences are the audit-log column set and the at-rest encryption helper used for the signing key. Both surfaces expose `GET /api/audit/integrity`.

## Why this exists

Append-only is a weaker property than it sounds. A database trigger can reject `UPDATE`/`DELETE`, but anyone with raw file access (a stolen backup, a compromised host, a malicious DBA) can drop the trigger and rewrite history. Three problems follow:

- **In-place edits.** A row's `detail` or `event_type` could be altered to erase evidence of an action.
- **Deletions and reordering.** Rows could be removed or resequenced to hide a window of activity.
- **Wholesale rewrite.** An attacker who understands a naive hash chain can edit a row and recompute every downstream hash, leaving a perfectly self-consistent — but forged — chain.

The three legs below address all three, with the signed checkpoint specifically closing the wholesale-rewrite gap.

## The three legs

1. **Per-row SHA-256 hash chain.** Each row stores `hash` and `prev_hash`. A row's `hash` is computed over its own content **and** the previous row's `hash`, so any edit, deletion, or reorder breaks linkage at the first affected row. This catches in-place edits and deletions.

2. **Ed25519-signed checkpoints.** Periodically, the current chain head (`head_id`, `head_hash`, `entry_count`) is digested and signed with a private key held only by the server. An attacker who rewrites the chain can make it internally consistent, but cannot produce a signature over the new head without the private key — so the rewrite is detected when the live head fails to match the latest signed checkpoint. This closes the wholesale-rewrite gap.

3. **SIEM/SOAR external anchor.** Audit events are also emitted as CEF to the operator's SIEM (and routed to SOAR). A copy of each event therefore exists outside the FireAlive database, giving an independent record to cross-check against during an investigation.

## Architecture: MC vs GD

| | Management Console | Global Dashboard |
|---|---|---|
| Service module | `server/services/audit-chain.js` | `packages/global-dashboard-server/services/gd-audit-chain.js` |
| Append entry point | `appendAuditEntry(db, fields)` | `appendGdAuditEntry(db, fields)` |
| `audit_log` content columns | `user_id, event_type, detail, ip_address, cef_message` | `user_id, event_type, detail, ip, severity` |
| Private-key encryption | `server/services/encryption.js` | `services/gd-encryption.js` |
| Periodic check | `server/services/audit-integrity-scheduler.js` (hourly) | `setInterval` in `index.js` (hourly) |
| Break alert | critical `AUDIT_CHAIN_BREAK` via the B3 alert router (SIEM + SOAR + notification) | critical `AUDIT_CHAIN_BREAK` audit row (the GD's alert primitive) |
| Verify endpoint | `GET /api/audit/integrity` | `GET /api/audit/integrity` |

Both share the same two supporting tables (in their respective databases):

- **`audit_chain_checkpoint`** — `id, head_id, head_hash, entry_count, signature` (base64), `signing_key_id, created_at`. Append-only (its own `no_update`/`no_delete` triggers).
- **`audit_chain_signing_keys`** — `id, public_key` (PEM, SPKI), `private_key_encrypted` (AES-256-GCM at rest), `is_active, created_at, rotated_out_at, notes`. A partial-unique index enforces a single active key. This is a dedicated key family, separate from the report-signing, abuse-export, and MC-trust keys.

All audit writes go through the single `append…` path, which is wrapped in a serialized `db.transaction()` so concurrent writers cannot interleave a head read with an insert.

## Canonical specification

The chain is verifiable without FireAlive's code. All hashing uses SHA-256; all signing uses Ed25519 (RFC 8032, PureEdDSA — no pre-hash). Canonical JSON is compact (no whitespace) with object keys sorted lexicographically; `null` is emitted for absent values.

### Row payload

The hashed payload is exactly these fields (MC shown; GD replaces `ip_address`→`ip` and `cef_message`→`severity`), with `v` the payload version:

```
MC: { "v":1, "user_id":<str|null>, "event_type":<str>, "detail":<str|null>, "ip_address":<str|null>, "cef_message":<str|null> }
GD: { "v":1, "user_id":<str|null>, "event_type":<str>, "detail":<str|null>, "ip":<str|null>, "severity":<str|null> }
```

Canonicalized (MC), keys sorted:

```
{"cef_message":…,"detail":…,"event_type":…,"ip_address":…,"user_id":…,"v":1}
```

### Row hash

```
input  = (prev_hash || "") + canonical_json(payload) + timestamp
hash   = SHA-256(input)            // lowercase hex
```

`timestamp` is the row's stored value, a UTC string formatted `YYYY-MM-DD HH:MM:SS` (set explicitly at insert time so the hashed value equals the stored value). The genesis row has `prev_hash = NULL`; its input uses the empty string in place of `prev_hash`.

### Checkpoint head digest and signature

```
head        = { "v":1, "head_id":<int>, "head_hash":<hex>, "entry_count":<int>, "created_at":<ts> }
digest      = SHA-256(canonical_json(head))          // 32 raw bytes
signature   = Ed25519_sign(privateKey, digest)        // 64 bytes, stored base64
```

Canonicalized head, keys sorted:

```
{"created_at":"…","entry_count":<int>,"head_hash":"…","head_id":<int>,"v":1}
```

The signature is computed over the 32-byte digest as the message (Ed25519 signs the message directly; here the message is the digest).

## Verification semantics

- **`verifyFull(db)`** — walks the whole chain: for each row, recomputes the hash from its content and checks `prev_hash` linkage against the prior row, then validates the live head against the latest signed checkpoint (signature valid **and** the head row's hash matches the notarized `head_hash`). Returns `{ intact, entriesVerified, brokenAt, reason, detail, head, checkpoint }`, where `reason ∈ { linkage, content, checkpoint, signature }`.
- **`verifyIncremental(db)`** — validates the latest checkpoint, then walks only from the checkpointed head forward. O(new rows); used by the hourly watch.

The HTTP endpoint runs `verifyFull`, advances the checkpoint on success, and on a break raises the alert described above. The "Verify Now" buttons on the Log Integrity (MC) and Audit & Forensics (GD) tabs call the same endpoint.

## Checkpoint cadence

- **Periodic (hourly).** The scheduler runs `verifyIncremental`; if intact it writes a fresh checkpoint, advancing the notarized anchor. On the MC the cadence and toggle live in `team_config.audit_integrity_config` (`{ enabled, interval_minutes, gap_threshold_minutes }`); `enabled` is honored every cycle and `interval_minutes` is read at boot.
- **On demand.** Every successful `GET /api/audit/integrity` also writes a checkpoint, so an operator clicking "Verify Now" both checks and re-notarizes.

Checkpoints are cheap (one row, one signature) and the table is append-only, so frequent checkpointing is intentional.

## Migration and baseline (honest scope)

The chain is established by a run-once, guarded migration (`migrateAuditChain` / `migrateGdAuditChain`): it adds the `hash`/`prev_hash` columns, ensures an active signing key, **backfills the existing rows by chaining and notarizing them as the baseline without altering their content**, writes the first checkpoint, and only then installs the `audit_log` append-only triggers (so the backfill itself is not blocked).

The honest claim is therefore: **tamper-evident from baseline establishment at deployment.** Backfill does not — and must not — rewrite existing rows, so tampering that occurred *before* the chain existed is not retroactively detectable. From the baseline forward, edits, deletions, gaps, and head-forgery attempts are all detectable.

## Threat model

Detected:

- **In-place edit** of any chained row → content-hash mismatch (`reason: content`) at that row.
- **Deletion / reordering** → linkage mismatch (`reason: linkage`).
- **Wholesale rewrite** (edit a row, recompute all downstream hashes) → the live head no longer matches the latest signed checkpoint (`reason: checkpoint`), or a forged checkpoint fails signature verification (`reason: signature`). The attacker cannot forge a head signature without the private key.
- **Missing rows / offline windows** → the gap check (`detectMissingLogs`) flags `id` gaps and time gaps beyond the threshold; on the MC this routes a `MISSING_LOGS` alert through the alert router.

Not detected / out of scope:

- **Pre-baseline tampering** — see the honest-scope note above.
- **Live private-key compromise** — an attacker who exfiltrates the active signing key (which is AES-256-GCM-encrypted at rest under the Tier-1 key) could sign a forged head. This is why the signing key is a dedicated family, encrypted at rest, and ideally KMS-backed; and why the SIEM external anchor matters as an independent record.
- **Truncation of the most recent uncheckpointed tail** — rows appended after the last checkpoint and then deleted before the next checkpoint leave no checkpoint to contradict them; the hourly cadence and the on-write gap check bound this window, and the SIEM copy still holds those events.

## Verifying a checkpoint with OpenSSL

An auditor with read access to the database can verify the latest checkpoint's signature without FireAlive:

1. Export the active public key:

```sql
SELECT public_key FROM audit_chain_signing_keys WHERE is_active = 1;
```

   Save it to `pub.pem` (it is already PEM/SPKI).

2. Reconstruct the signed digest. Read the latest checkpoint row:

```sql
SELECT head_id, head_hash, entry_count, signature, created_at
FROM audit_chain_checkpoint ORDER BY id DESC LIMIT 1;
```

   Build the canonical head JSON (compact, keys sorted) and SHA-256 it to the raw 32-byte digest:

```sh
printf '%s' '{"created_at":"<created_at>","entry_count":<entry_count>,"head_hash":"<head_hash>","head_id":<head_id>,"v":1}' \
  | openssl dgst -sha256 -binary > digest.bin
```

3. Decode the stored signature (base64) to raw bytes:

```sh
printf '%s' '<signature_base64>' | openssl base64 -d -A > sig.bin
```

4. Verify (Ed25519 over the raw digest message):

```sh
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in digest.bin -sigfile sig.bin
# -> "Signature Verified Successfully"
```

5. Confirm the live head matches the notarized head: the `audit_log` row with `id = head_id` must have `hash = head_hash`. Optionally recompute that row's hash from the row-hash formula above to confirm the head content itself.

To verify the whole chain, recompute each row's hash in `id` order with the row-hash formula and confirm `prev_hash` linkage; any standard SHA-256 tool reproduces the same hex.

## Operational notes

- **Key rotation.** Generate a new Ed25519 key, mark it active, and set the prior key's `rotated_out_at`; the partial-unique index keeps exactly one active key. Old public keys are retained so historical checkpoints (which record their `signing_key_id`) remain verifiable.
- **Retention.** The `audit_log` is never purged by the retention lifecycle — it is permanently append-only, which is what makes the chain meaningful over time.
- **Triggers.** `audit_log_no_update` and `audit_log_no_delete` reject mutation at the database level; the checkpoint table carries equivalent triggers. These are defense-in-depth, not the integrity guarantee — the hash chain and signed checkpoints are what make tampering *evident* if the triggers are ever bypassed.
- **Regression.** Both the MC and GD regression suites verify the chain (recompute + linkage) and validate the latest signed checkpoint's signature; the checks are forward-aware and activate automatically once the chain exists.
