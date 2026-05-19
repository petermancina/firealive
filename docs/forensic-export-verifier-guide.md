# Forensic Export Verifier Guide

This document is for **external auditors, regulators, and incident response teams** who have received a FireAlive forensic export tarball and need to verify its integrity before relying on its contents. The verification procedure produces independent cryptographic evidence that:

1. The archive has not been modified since FireAlive produced it.
2. The slice contents (audit log entries, backup chain entries, etc.) match what the manifest claims.
3. The export's creation, downloads, and deletion are recorded in an append-only chain with intact hash continuity.

No FireAlive tooling is required. The verification is performed with standard Unix utilities (`tar`, `sha256sum`), OpenSSL (for Ed25519 verification), and optionally Cosign (for OCI-style attestation). The architecture document (`docs/forensic-export-architecture.md`) describes the design; this document describes the procedure.

## What you received

A FireAlive forensic export comes as a single `.tar.gz` file:

```
firealive-forensic-<export-id>.tar.gz
```

The export id is a UUID. The MC-produced archive prefix is `firealive-forensic-`; the GD-produced archive prefix is `firealive-gd-forensic-`. Server identity (mc/gd) is also recorded inside the manifest.

You should additionally receive, out-of-band:

- The Ed25519 **public key PEM** corresponding to the signing key fingerprint recorded in the archive's manifest. This may be delivered as a separate file or as a copy-paste from FireAlive's `/api/forensic-exports/chain` endpoint (the `active_signing_key.public_key_pem` field).
- (Optional) The most recent **chain entries** from `/api/forensic-exports/chain` covering the period of interest, exported as JSON. The chain alone is insufficient to verify content but allows you to confirm the export's existence and metadata even if the archive itself is later deleted.
- (Optional) The Cosign **public key** if the deployment uses Cosign attestation.

## Tools required

| Tool | Purpose | Tested with |
|------|---------|-------------|
| `tar`  | Extract the .tar.gz | GNU tar 1.35 or BSD tar |
| `sha256sum` | Compute SHA-256 hashes | GNU coreutils 9.x; on macOS use `shasum -a 256` |
| `openssl` | Verify Ed25519 signatures | OpenSSL 3.x (Ed25519 requires ≥1.1.1) |
| `jq` | Inspect manifest JSON | jq 1.6 or later |
| `cosign` | Verify Cosign attestation (optional) | Sigstore cosign 2.x |

A Python 3 environment is convenient for canonical-JSON reproduction but not strictly required.

## Step 1: Extract the archive

```bash
mkdir verify/
cd verify/
tar -xzf ../firealive-forensic-<export-id>.tar.gz
ls -la
```

Expected layout:

```
manifest.json
manifest.sig
slices/
  {format-name}.{extension}
  ...
```

If `tar` rejects the file or extraction produces unexpected contents (extra files at the root, missing manifest.json, etc.), stop here — the archive has been modified at the structural level.

## Step 2: Verify the manifest signature

The manifest is signed with Ed25519. The signature in `manifest.sig` is over the **raw bytes** of `manifest.json` exactly as it appears in the archive (no canonicalization, no whitespace stripping — the file bytes themselves).

```bash
# Assuming you have the public key as pubkey.pem
openssl pkeyutl -verify -inkey pubkey.pem -pubin \
  -rawin -in manifest.json -sigfile manifest.sig

# Expected output:
# Signature Verified Successfully
```

If verification fails:

- Confirm you have the correct public key. The manifest itself contains the `manifest_signing_key_fingerprint`; the fingerprint of your `pubkey.pem` (`openssl pkey -in pubkey.pem -pubin -outform DER | sha256sum | cut -c 1-16`) should match.
- Confirm the manifest.json hasn't been edited (any whitespace change invalidates the signature).
- Confirm openssl is ≥1.1.1 (earlier versions don't support Ed25519).

A successful verification means: **the manifest.json content is exactly what FireAlive's signing key authorized at export time**. The signing key's private half is at-rest encrypted with the server's Tier-1 KEK; a successful signature implies either FireAlive's signer ran legitimately or the server's KEK was compromised at the time of signing. The chain (Step 4) provides a second integrity surface.

## Step 3: Verify the slice hashes

The manifest's `slices` array contains the SHA-256 hash of each slice's canonical JSON. Each slice corresponds to one source table (audit_log, backup_chain, etc.) and is materialized as one or more files in `slices/` depending on the output formats requested.

The canonical JSON used for hashing is RFC 8785-style canonical JSON (lexicographically-sorted keys, no whitespace, normalized number representation, etc.) computed over the raw slice rows BEFORE any format-specific serialization. The format files inside `slices/` are not directly hashed — they are deterministic functions of the same source data, and verifying their integrity against the manifest works as follows:

```bash
# For each slice listed in the manifest:
jq -r '.slices[] | .name + " " + .sha256' manifest.json
# audit_log              <hash>
# backup_chain           <hash>
# incident_records       <hash>
# authentication_logs    <hash>
# user_access_logs       <hash>
```

To reproduce the slice hashes independently, you would need to reconstruct the canonical JSON. The simplest path is to use the `json-lines` output format if it was requested (each line is one event):

```bash
# If json-lines was in outputFormats:
cat slices/audit-log.jsonl | jq -s -c -S '.' | sha256sum
# This produces canonical-ish JSON; for strict RFC 8785 conformance,
# use a dedicated jcs library (e.g., npm install canonicalize).
```

If the format files are byte-identical to what FireAlive produced (a reasonable assumption given the source data is unchanged), the format-specific hashes can be computed:

```bash
# Per-format file integrity (these hashes are NOT in the manifest by
# default but serve as a secondary cross-check):
sha256sum slices/*
```

The primary integrity surface is the manifest signature (Step 2) plus the slice hashes in the manifest. If both pass, the export contents are cryptographically tied to FireAlive's signing key at the time of export.

## Step 4: Walk the chain

The forensic_export_chain is FireAlive's append-only ledger of every export's creation, downloads, and deletion. Verifying the chain proves:

- That the export was actually created (not retroactively inserted into the archive on disk by an attacker).
- That every download is recorded with the downloading user's identity.
- That if the export was later deleted, the deletion is also recorded.

You will need a JSON export of the chain — request the deployment's CISO to provide it via `GET /api/forensic-exports/chain` (output includes both the chain rows and the active_signing_key block).

```bash
# Find the chain entry for your export:
jq '.chain[] | select(.export_ref == "<export-id>" and .event_type == "EXPORT_CREATED")' chain.json
```

Expected output (single entry):

```json
{
  "id": <chain-row-id>,
  "prev_hash": "<hex>" or null,
  "this_hash": "<hex>",
  "signature": "<hex>",
  "event_type": "EXPORT_CREATED",
  "export_ref": "<export-id>",
  "actor_user_id": "<creator-user-id>",
  "created_at": "<iso-timestamp>"
}
```

To verify the chain entry's own integrity:

```bash
# Each chain entry's signature is Ed25519 over the this_hash hex bytes
# (NOT over the binary digest — the bytes of the hex string).

# Extract the signature and this_hash:
SIG=$(jq -r '.chain[] | select(.id == <chain-row-id>) | .signature' chain.json)
HASH=$(jq -r '.chain[] | select(.id == <chain-row-id>) | .this_hash' chain.json)

# Write to temp files:
echo -n "$HASH" > chain-hash.txt
echo -n "$SIG" | xxd -r -p > chain-sig.bin

# Verify with the same public key from Step 2:
openssl pkeyutl -verify -inkey pubkey.pem -pubin \
  -rawin -in chain-hash.txt -sigfile chain-sig.bin
# Expected: Signature Verified Successfully
```

To verify hash continuity (the chain links):

```bash
# For each chain entry, this_hash should equal:
#   SHA-256(prev_hash_bytes || canonical-JSON(payload))
# where payload = {event_type, export_ref, actor_user_id, timestamp}
# and prev_hash_bytes is the hex-decoded prev_hash from the prior row
# (or empty if this is the first row).

# This is most easily done with a small Python script:
python3 <<'EOF'
import json, hashlib

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(',', ':')).encode()

chain = json.load(open('chain.json'))['chain']
chain.sort(key=lambda r: r['id'])

prev = None
for row in chain:
    payload = {
        'event_type': row['event_type'],
        'export_ref': row['export_ref'],
        'actor_user_id': row['actor_user_id'],
        'timestamp': row['created_at'],
    }
    link_input = bytes.fromhex(row['prev_hash']) + canonical(payload) if row['prev_hash'] else canonical(payload)
    computed = hashlib.sha256(link_input).hexdigest()
    status = 'OK' if computed == row['this_hash'] else 'MISMATCH'
    print(f"id={row['id']} event={row['event_type']} {status}")
EOF
```

Every row should print `OK`. A single `MISMATCH` indicates the chain has been tampered with — either a row was inserted that didn't go through the orchestrator's append helper, or the prev_hash field of a subsequent row was rewritten. SQLite triggers prevent UPDATE and DELETE on the chain table (`no_update_forensic_export_chain`, `no_delete_forensic_export_chain` from schema C20), so chain tampering requires direct file-level database modification — which leaves OS-level evidence and is detectable by the runtime integrity monitor.

## Step 5: Verify the separate-actor invariant (if applicable)

If the chain contains an `EXPORT_DELETED` entry for the export, confirm:

```bash
# Find the CREATED entry's actor:
CREATOR=$(jq -r '.chain[] | select(.export_ref == "<export-id>" and .event_type == "EXPORT_CREATED") | .actor_user_id' chain.json)

# Find the DELETED entry's actor:
DELETOR=$(jq -r '.chain[] | select(.export_ref == "<export-id>" and .event_type == "EXPORT_DELETED") | .actor_user_id' chain.json)

echo "Creator: $CREATOR"
echo "Deletor: $DELETOR"

# The two MUST differ. If they match, the separate-actor enforcement
# was bypassed (which the route layer rejects with 403 — so a match
# indicates either database manipulation or a defect in the route).
[ "$CREATOR" != "$DELETOR" ] && echo "Separate-actor invariant: OK"
```

## Step 6: Verify Cosign attestation (optional)

If the deployment has `FIREALIVE_FORENSIC_USE_COSIGN=true` enabled, an additional `cosign.bundle` file may be present alongside the manifest. Verify with:

```bash
cosign verify-blob --key cosign-pubkey.pem --bundle cosign.bundle archive.tar.gz
# Expected: Verified OK
```

Cosign is optional — the Ed25519 manifest signature is the primary verification surface. Cosign provides additional sigstore-ecosystem compatibility for organizations standardized on SLSA / sigstore policy controllers.

## Step 7: Reconcile with the audit log (optional)

The MC's and GD's `audit_log` tables contain plain-text entries for every `FORENSIC_EXPORT_*` event. If you have access to the audit log (typically via the management console's Audit Log tab or via a separate audit export), confirm the events you expect appear:

- `FORENSIC_EXPORT_CREATED` (severity=info) when the export was created
- `FORENSIC_EXPORT_DOWNLOADED` (severity=info) on each download
- `FORENSIC_EXPORT_DELETED` (severity=info) if deleted
- `FORENSIC_EXPORT_DELETE_DENIED` (severity=warning) on any rejected delete attempts (e.g. same-actor violations)

The audit log is mutable in principle (SQLite has no triggers preventing UPDATE on audit_log), but the runtime integrity monitor checksums the audit log periodically and reports gaps or hash mismatches. Cross-referencing the chain (immutable) with the audit log (mutable but monitored) provides defense-in-depth: a tampered audit log without a tampered chain shows the tampering; a tampered chain without a tampered audit log shows the chain manipulation.

## What success looks like

A complete verification produces these affirmations:

```
[OK] tar extraction succeeded, expected files present
[OK] manifest.json signature verified with provided public key
[OK] manifest fingerprint matches recorded signing key
[OK] slice hashes documented in manifest
[OK] chain entry exists for EXPORT_CREATED with this export's id
[OK] chain entry signature verifies with same public key
[OK] chain hash continuity intact (no MISMATCH rows)
[OK] separate-actor invariant holds (if applicable)
[OK] cosign attestation verifies (if applicable)
[OK] audit log events match chain entries (if accessible)
```

With all these checkmarks, the archive is independently verifiable as authentic and untampered.

## What failure looks like and what it means

| Failure | Likely cause | Action |
|---------|--------------|--------|
| `tar` extraction fails | Archive corrupted in transit | Request retransmission |
| `openssl pkeyutl -verify` fails on manifest | manifest.json edited; wrong public key | Confirm key fingerprint matches; if so, manifest is forged or tampered |
| Slice hash in manifest doesn't match recomputed canonical-JSON hash | Slice file edited inside archive | Archive's contents are tampered |
| `MISMATCH` in chain continuity walk | Chain tampered at row level | Database-level evidence manipulation — escalate to incident response |
| EXPORT_CREATED chain entry not found | Export id was never created on this server | Archive is fabricated or originated from a different server |
| Creator and deletor user_ids match | Database-level same-actor violation OR route defect | Investigate route logic + DB direct-write evidence |
| Audit log lacks corresponding events | Audit log tampering OR archive predates current audit log retention | Cross-check against archived audit logs |

## Reporting

A standard verification report should record:

1. The export id and source server (MC vs GD).
2. The signing key fingerprint used for verification.
3. The verification commands run and their outputs.
4. Each affirmation from "what success looks like" with timestamp.
5. Any anomalies noted.
6. Your identity and verification date.

Retain the report alongside the verified archive. Future re-verification should be reproducible — the same commands against the same archive with the same public key must yield the same affirmations.

## See also

- `docs/forensic-export-architecture.md` — the design document covering the workflow, threat model, and code layout. Read this if you need to understand why the workflow is structured the way it is.
- `docs/two-person-restore.md` — the parallel two-person workflow for destructive restore operations. The separate-actor concept is the same.
- RFC 8785 — canonical JSON specification used for slice hashing.
- NIST SP 800-92 — log management guidance covering forensic audit trail requirements.
- ISO 27001 A.9.4.5 — separation of duties for system administration. The separate-actor invariant is the technical implementation of this control.
