# Forensic Export Architecture

FireAlive's forensic export workflow produces cryptographically-signed, tamper-evident archives of platform audit data for compliance investigations, incident response, and regulator requests. This document describes the architecture, the create/download/delete sequence flows, the separate-actor enforcement, the threat model, and the code layout across the management console (MC) and global dashboard (GD) servers.

## Why this exists

When a regulator requests "all audit log entries between Q3 dates concerning user X" or an incident response team needs to reconstruct an attacker's session, the platform has to produce a trustworthy artifact. Three things matter:

- **Format compatibility.** The receiving analyst is rarely using FireAlive's UI to inspect the data. They're loading it into Splunk, ArcSight, Sentinel, Autopsy, plaso, or a TIP. The export must speak their tool's native dialect.
- **Cryptographic integrity.** Six months later, the receiving party needs to prove the file is genuine, hasn't been silently edited, and matches what FireAlive produced at the time. A standalone JSON dump fails this; an Ed25519-signed manifest with a hash chain passes it.
- **Procedural integrity.** A single admin generating exports and then deleting the evidence of inconvenient ones defeats the purpose. SOC 2 / ISO 27001 / regulated-industry frameworks require separation-of-duties for destructive actions on audit data. The workflow has to encode "two different humans were involved" at the architecture level, not as a policy hope.

The C20-C35 work delivers a workflow that meets all three requirements end-to-end.

## High-level architecture

The forensic export workflow spans both FireAlive servers — MC (regional management console) and GD (global dashboard for cross-region oversight) — with structurally identical code on each side. The two servers maintain independent cryptographic identities (separate signing keys, separate Tier-1 KEKs) so a compromise of one cannot pivot into a compromise of the other.

```
                      ┌─────────────────────────────────────────┐
                      │            MC frontend                  │
                      │      (firealive-mc.jsx, C33)            │
                      │  Tab: Forensic Exports (admin/CISO)     │
                      └─────────────┬───────────────────────────┘
                                    │ POST/GET/DELETE
                                    │ /api/forensic-exports
                      ┌─────────────▼───────────────────────────┐
                      │            MC backend                   │
                      │  server/routes/forensic-exports.js C29  │
                      │  server/services/forensic-export.js C22 │
                      │  server/services/forensic-formats/ C23-28│
                      │  encryption.js (Tier-1 MC KEK)          │
                      │  Tables: forensic_exports +              │
                      │          forensic_export_chain +         │
                      │          forensic_export_chain_signing_  │
                      │          keys (C20)                      │
                      └─────────────────────────────────────────┘

                      ┌─────────────────────────────────────────┐
                      │            GD frontend                  │
                      │   (global-dashboard.jsx, C34)           │
                      │  Tab: Forensic Exports (VP/CISO)        │
                      └─────────────┬───────────────────────────┘
                                    │ POST/GET/DELETE
                                    │ /api/forensic-exports
                      ┌─────────────▼───────────────────────────┐
                      │            GD backend                   │
                      │  packages/global-dashboard-server/      │
                      │    index.js (inlined routes, C32)       │
                      │    services/forensic-export.js (C31b)   │
                      │    services/forensic-formats/ (C31c-j)  │
                      │  gd-encryption.js (Tier-1 GD KEK)       │
                      │  Tables: same as MC + GD-specific role  │
                      │          mapping (C30)                  │
                      └─────────────────────────────────────────┘

                      ┌─────────────────────────────────────────┐
                      │         Analyst client                  │
                      │   (analyst-client.jsx, C35)             │
                      │  Read-only transparency card in audit   │
                      │  tab; no API calls; informational only  │
                      └─────────────────────────────────────────┘
```

The analyst client does not consume any forensic-export endpoint — those are gated to admin/CISO/VP roles, and analysts have neither. The card in the analyst's audit tab is purely informational.

## Role mapping: who can do what

The separate-actor invariant requires two distinct roles for create and delete. The roles differ between servers:

| Server | Creator role | Deletor role | Read roles |
|--------|--------------|--------------|------------|
| MC     | `admin`      | `ciso`       | `admin` or `ciso` |
| GD     | `vp`         | `ciso`       | `vp` or `ciso`    |

The GD-server is operated by the CISO and the VP (the CISO's deputy in this deployment). The natural separate-actor pair there is VP/CISO. On the MC, the operator is the management-console admin; the CISO acts as the separate-actor deletor.

Both pairings satisfy ISO 27001 A.9.4.5 separation-of-duties and NIST 800-53 AC-5. The DELETE handler enforces an additional check beyond role: the deleting user must not be the original requester (compared by `requested_by_user_id` against `req.user.id` at delete time). A user holding both admin and ciso roles cannot bypass the separate-actor requirement by holding both hats — they must still be a different person from the original creator.

## Sequence: Create flow

```
1. Operator (admin on MC; vp on GD) opens the Forensic Exports tab.
2. Operator fills in:
     - Time window (optional ISO 8601 start/end)
     - Event type filter (optional comma-separated list)
     - Rationale (free text; recorded in audit log)
     - Output formats (multi-select from 8 supported)
     - Slice include flags (audit log, backup chain, incident records,
       authentication logs, user access logs — all default true)
3. POST /api/forensic-exports with the form payload.
4. Server route handler validates JWT + role; rejects 403 if non-admin/non-vp.
5. Server inserts row in forensic_exports with status='pending', generates
   UUID for export id.
6. Server marks row status='in_progress', invokes
   forensic-export.createForensicExport(db, opts) which:
     a. Loads or generates the active Ed25519 signing key
        (forensic_export_chain_signing_keys; private PEM at-rest
        encrypted with Tier-1 KEK per server).
     b. Reads each enabled slice via column-omitted SELECT (private
        fields like session refresh-token and API-key hashes
        are excluded by construction at the SELECT level — they cannot
        appear in any export).
     c. Lazy-loads each requested format serializer; if a format isn't
        registered (e.g. file missing), createForensicExport throws
        cleanly without producing a partial archive.
     d. Builds the manifest JSON: format version, slice list with
        SHA-256 of each slice's canonical JSON, requested-by user,
        time window, format list, server identity (mc vs gd), Ed25519
        public key fingerprint, and per-format file paths inside the
        tar.
     e. Inline POSIX ustar tar builder writes manifest.json,
        manifest.sig (Ed25519 signature of canonical manifest bytes),
        and one file per format into a single .tar.gz archive in the
        on-disk artifacts directory.
     f. (Optional) If FIREALIVE_FORENSIC_USE_COSIGN=true, invokes
        cosign sign-blob against the archive to produce an additional
        OCI-style attestation alongside the manifest signature.
     g. Appends a chain entry: prev_hash = last chain row's this_hash,
        this_hash = SHA-256(prev_hash || canonical-JSON(payload)),
        signature = Ed25519(this_hash). Payload includes export id,
        actor user, event_type='EXPORT_CREATED', and ISO timestamp.
     h. Updates forensic_exports row: status='complete', archive_path,
        archive_sha256, size_bytes, completed_at,
        manifest_signing_key_fingerprint.
7. Server appends FORENSIC_EXPORT_CREATED to audit_log (severity=info)
   with id + formats + size summary.
8. Server returns {id, status, sizeBytes, archiveSha256,
   manifestSigningKeyFingerprint, ...}.
9. Frontend shows success banner + refreshes export list.
```

If step 6 throws at any point, the row is updated with status='failed' and error_message, and FORENSIC_EXPORT_FAILED is appended to audit_log with severity=error. The chain receives no EXPORT_CREATED entry for failed creates — the chain only records successful operations.

## Sequence: Download flow

```
1. Operator clicks "Download" on a status=complete row.
2. Frontend calls api.download('/api/forensic-exports/:id/download',
   filename, {method:'GET'}).
3. Server validates JWT + admin role on MC (vp role on GD).
4. Server reads the row; rejects 404 if not found, 409 if status !=
   complete, 410 if archive_path file no longer exists on disk.
5. Server appends a chain entry FIRST, BEFORE streaming the body:
   event_type='EXPORT_DOWNLOADED'. This ensures the chain reflects
   the download even if the client connection drops mid-stream.
6. Server stamps the row with downloaded_at and
   downloaded_by_user_id.
7. Server appends FORENSIC_EXPORT_DOWNLOADED to audit_log.
8. Server sets Content-Disposition (attachment; filename=...) and
   Content-Type (application/gzip), then pipes the archive file to
   the response stream.
9. Frontend's api.download helper receives the blob, creates an
   anchor element, triggers click for download, and revokes the
   blob URL.
```

The chain-entry-before-stream ordering is deliberate. If the operator interrupts the download (closes laptop, kills the browser), the chain still records that an EXPORT_DOWNLOADED event was attempted. A subsequent audit will see the chain entry and the absence of a corresponding completion marker in the operator's local artifacts — the discrepancy is detectable rather than hidden.

## Sequence: Delete flow (separate-actor)

```
1. Operator (ciso role) clicks "Delete" on any row.
2. Frontend's window.confirm() prompts with the full separate-actor
   explanation; if cancelled, no API call is made.
3. Frontend calls api.del('/api/forensic-exports/:id').
4. Server validates JWT + ciso role.
5. Server reads the row; rejects 404 if not found.
6. Server compares row.requested_by_user_id to req.user.id:
     - If they MATCH, rejects 403 with message:
       "separate-actor violation: the actor performing DELETE must be
        a different person from the requesting [admin|vp]"
     - If they DIFFER, proceeds.
7. Server appends a chain entry FIRST, BEFORE destructive ops:
   event_type='EXPORT_DELETED'. The chain records that the deletion
   occurred and by whom, even if the on-disk file unlink or row
   DELETE encounters errors.
8. Server attempts fs.unlinkSync on archive_path, manifest_path, and
   manifest_sig_path. Each unlink is independent best-effort
   (try/catch with ignored errors); a missing file is not an error.
9. Server runs DELETE FROM forensic_exports WHERE id = ?.
10. Server appends FORENSIC_EXPORT_DELETED to audit_log
    (severity=info; includes original creator's user_id in detail).
11. Server returns {deleted: true, id}.
12. Frontend refreshes the list.
```

After deletion, the row is gone but the chain entries (both EXPORT_CREATED and EXPORT_DELETED) remain. A future audit can reconstruct that an export existed, who created it, who deleted it, and approximately when — without the export contents themselves. This is the intended posture: the chain proves what happened; deletion removes the contents but cannot retroactively claim the export never existed.

## Threat model

The workflow defends against these specific threats:

**1. Compromised admin account exfiltrates and tampers with audit data.**
- A compromised admin can create exports they shouldn't.
- The chain records every creation with the admin's user id and rationale.
- The admin cannot delete their own creates (separate-actor blocks same-actor DELETE).
- A CISO reviewing the chain will see suspicious creation patterns and can revoke the admin's session.
- The chain is append-only enforced by SQLite triggers (no_update_forensic_export_chain, no_delete_forensic_export_chain from C20); the compromised admin cannot rewrite history.

**2. Compromised CISO account erases forensic evidence.**
- A compromised CISO can delete arbitrary exports.
- The chain records every deletion with the CISO's user id.
- The chain entry survives the deletion (append-only triggers).
- A future audit reconstructs which exports existed and who deleted them.
- The on-disk artifact is gone, but the manifest hash + chain entry let auditors verify what the export contained if they retain a copy externally.

**3. Both accounts compromised by the same attacker (collusion case).**
- An attacker who controls both admin and CISO accounts can create and delete exports freely.
- The separate-actor check (user IDs differ) prevents both operations from one account but does not prevent both accounts from being the same attacker.
- The mitigation here is at the human/procedural layer: organizations should not use one human as both admin and CISO. The platform encodes the requirement; the deployment enforces it.

**4. Server compromise leaks the signing key.**
- The forensic_export_chain_signing_keys.private_key_encrypted column is AES-256-GCM encrypted with the server's Tier-1 KEK (TIER1_ENCRYPTION_KEY on MC; GD_ENCRYPTION_KEY on GD).
- An attacker reading the SQLite database file alone cannot forge signatures — they need the KEK from environment variables or KMS at runtime.
- Separation between MC and GD KEKs means a compromise of one server's KEK does not compromise the other server's signing chain. Each server has its own independent forensic_export_chain.

**5. Tampering with exported archives.**
- The manifest contains SHA-256 of each slice's canonical JSON.
- The manifest is Ed25519-signed with a key whose fingerprint is recorded both in the manifest itself and in the forensic_exports row.
- A receiver who has the public key (from the chain endpoint or from prior provisioning) can verify the signature offline and detect any modification.
- The chain entry corresponding to EXPORT_CREATED contains a SHA-256 of the canonical event payload; a receiver who has the chain can verify the export's existence and approximate metadata even without the archive.

## Format catalog

The 8 forensic format serializers in `forensic-formats/` are pure functions of the slice data. Each is byte-identical between MC and GD (only the orchestrator's encryption require differs). The catalog:

| Format | Primary consumers | Notes |
|--------|-------------------|-------|
| `sleuth-kit-bodyfile` | Sleuth Kit `mactime`, Autopsy timeline | 11-field pipe-delimited; all four MACB timestamps equal for point-in-time events |
| `json-lines` | Splunk, Elastic, generic JSON consumers | One event per line; per-line HMAC-SHA256 for defense-in-depth |
| `plaso-l2t-csv` | plaso `psort`, Autopsy timeline, Splunk log2timeline ingest | 17-column native log2timeline CSV; US date order; CRLF terminators |
| `cef` | ArcSight ESM, IBM QRadar, Splunk CIM, Sentinel, FortiSIEM | CEF:0 v0 with proper extension escaping; severity 0-10 heuristic |
| `evtx-xml` | Windows Event Viewer, Sentinel WindowsEvent table | Fixed provider GUID + channel mapping per slice |
| `stix-21` | Anomali ThreatStream, IBM X-Force, OpenCTI, MISP | OASIS STIX 2.1 bundle; UUIDv5 deterministic IDs |
| `dfxml` | fiwalk, Autopsy DFXML module, SleuthKit ecosystem | DFXML 1.2.0; both MD5 (legacy) and SHA-256 hashdigest |
| `csv` | Excel, generic spreadsheet tools, simple greppable text | 8-column flat CSV with canonical_json column carrying full event |

A single export may produce any subset of these formats. The most operationally common pairing is `json-lines + csv` (Splunk-friendly + Excel-friendly).

## Storage layout

```
{FORENSIC_ARTIFACTS_DIR}/                   default: ./artifacts/forensic-exports/
  {export_id}/                              UUID per export
    archive.tar.gz                          the sealed bundle
    manifest.json                           cleartext copy of in-archive manifest
    manifest.sig                            Ed25519 signature of manifest.json
    cosign.bundle                           optional Cosign attestation (when enabled)
```

The directory is created on first export. The on-disk files outside the tar are convenience copies — the canonical signed manifest is the one inside the .tar.gz. Delete operations remove all four files (best-effort unlink) and then DELETE the row.

The tar.gz internal layout:

```
manifest.json
manifest.sig
slices/
  {format-name}.{extension}           one file per requested format
  ...
```

The slices subdirectory contains one file per output format requested. Files use the format's natural extension: `.bodyfile` for sleuth-kit-bodyfile, `.jsonl` for json-lines, `.csv` for plaso-l2t-csv and csv, `.cef` for cef, `.xml` for evtx-xml, `.json` for stix-21, `.dfxml` for dfxml.

## Code layout reference

```
server/                                              MC backend
  db/init.js                                         schema (C20 — tables + triggers + indexes)
  services/
    audit-export-shared.js                           canonical-JSON + manifest helpers (C21)
    forensic-export.js                               orchestrator (C22)
    forensic-formats/
      sleuth-kit-bodyfile.js                         C23
      json-lines.js                                  C24
      plaso-l2t-csv.js                               C25
      cef.js                                         C26
      evtx-xml.js                                    C27a
      stix-21.js                                     C27b
      dfxml.js                                       C28a
      csv.js                                         C28b
    encryption.js                                    Tier-1 KEK for MC
  routes/forensic-exports.js                         6 HTTP endpoints (C29a)
  index.js                                           one-line route mount (C29b)
frontend/firealive-mc.jsx                            Forensic Exports tab (C33)

packages/
  global-dashboard-server/                           GD backend
    db-init.js                                       schema mirror with GD role notes (C30)
    services/
      audit-export-shared.js                         GD copy (C31a — byte-identical)
      forensic-export.js                             GD copy (C31b — one require diff)
      forensic-formats/                              C31c-j (byte-identical to MC)
      gd-encryption.js                               Tier-1 KEK for GD
    index.js                                         6 routes inlined + mount (C32)
  global-dashboard/global-dashboard.jsx              Forensic Exports tab (C34)
  analyst-client/analyst-client.jsx                  Transparency card in audit tab (C35)

docs/
  forensic-export-architecture.md                    this document (C36a)
  forensic-export-verifier-guide.md                  external auditor guide (C36b)
```

## Operational notes

**On signing key rotation.** The active signing key is selected by `WHERE active = 1 LIMIT 1` in the chain helpers. Rotation is a future R3l item (the schema supports it via the active column, but no rotation routes are exposed yet). When rotation lands, the rotation handler will mark the old key inactive, generate a new keypair, store the new key with active=1, and append a chain entry of type `SIGNING_KEY_ROTATED` that signs the transition with the old key one last time. External verifiers cache public keys by fingerprint, so a rotated export remains verifiable as long as the verifier retains the old key's public PEM.

**On Cosign attestation.** Cosign is optional, gated on `FIREALIVE_FORENSIC_USE_COSIGN=true`. When enabled, the orchestrator shells out to `cosign sign-blob` against the archive and stores the resulting bundle. Cosign provides OCI-ecosystem-compatible attestation suitable for software supply chain workflows (SLSA, sigstore policy controllers). The Ed25519 manifest signature provides standalone verification without Cosign; Cosign is an optional additional path for organizations standardized on sigstore.

**On the chain length.** The forensic_export_chain table grows monotonically — append-only with no rotation. Each export contributes at minimum 1 chain entry (CREATED), plus one per download, plus one per delete. For a typical SOC running ~10 exports/month with ~3 downloads each, the chain grows by ~40 entries/month. At 10 years the table holds ~5000 entries, which is a few hundred KB — orders of magnitude smaller than the audit_log table itself.

## See also

- `docs/forensic-export-verifier-guide.md` — step-by-step external auditor verification procedure for a forensic export archive.
- `docs/two-person-restore.md` — the parallel two-person workflow for destructive restore operations. The threat model and separate-actor concept carry over directly; restore uses approval workflow, forensic export uses creator/deletor-must-differ.
