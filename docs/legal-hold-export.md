# Legal Hold Export Architecture

FireAlive's legal hold workflow produces cryptographically-signed, litigation-grade evidence preservation archives of platform audit data for e-discovery, regulatory inquiries, and litigation holds. This document describes the architecture, the create/release/download sequence flows, the triple-layer separate-actor enforcement on release, the indefinite-retention contract, the eight e-discovery format serializers, the threat model, and the code layout across the management console (MC) and global dashboard (GD) servers.

## Why this exists distinct from forensic exports

Forensic exports (the C20-C35 workflow documented in `forensic-export-architecture.md`) are operational: an admin generates an archive for an incident response, hands it to an analyst, and after the IR closes the export may be cleaned up. The chain entry persists; the file does not have to.

Legal holds are different. When a court issues a preservation order, when a regulator opens an inquiry, when an internal investigation begins, the platform has to preserve evidence *indefinitely* until a release authority decides the matter is closed. Three things change relative to forensic exports:

- **Indefinite retention by default.** A legal hold never expires on a schedule. The `indefinite_retention` flag (default 1) signals the retention job to skip the archive forever. Time-bounded preservation orders explicitly set the flag to 0.
- **No deletion, only release.** A legal hold cannot be deleted. It transitions through a `release` workflow that records who released, why, and when — and emits a `HOLD_RELEASED` chain entry that persists forever alongside the original `HOLD_CREATED` / `HOLD_COMPLETED`. The archive remains downloadable after release for post-litigation audit and verification.
- **Separate-actor enforced at three layers on release.** Forensic exports require separate actor at the route and orchestrator layers. Legal holds add a third layer: a SQLite `CHECK` constraint on `legal_hold_exports` that refuses any UPDATE setting `hold_released_by_user_id == requested_by_user_id`. This is structurally impossible to bypass — opposing counsel cannot argue "the application could have been compromised" because the constraint lives in the database file itself.

Plus a different set of output formats. Forensic exports speak to SIEMs and forensic-analysis tools (Splunk, ArcSight, Sentinel, Autopsy, plaso, TIPs). Legal holds speak to e-discovery review platforms (Relativity, Concordance, Reveal, Logikcull, Everlaw, kCura) and to legal counsel directly via PDF and TIFF with Bates numbering.

The C36-C52 work delivers a workflow that meets all of these requirements end-to-end.

## High-level architecture

```
                  ┌─────────────────────────────────────────┐
                  │            MC frontend                  │
                  │      (firealive-mc.jsx, C48/C49)        │
                  │  Tab: Legal Hold (admin/CISO)           │
                  │   • Create modal                        │
                  │   • Existing holds list                 │
                  │   • Release modal (CISO + separate)     │
                  └─────────────┬───────────────────────────┘
                                │ POST/GET
                                │ /api/legal-hold-exports
                  ┌─────────────▼───────────────────────────┐
                  │            MC backend                   │
                  │  server/routes/legal-hold-exports.js C46│
                  │  server/services/legal-hold-export.js C38│
                  │  server/services/legal-hold-formats/    │
                  │     edrm-xml, eml-mime, pst (C39-C41)   │
                  │     concordance, relativity (C42-C43)   │
                  │     json-tarball (C44)                  │
                  │     pdf-bates, tiff-bates (C45)         │
                  │  encryption.js (Tier-1 MC KEK)          │
                  │  Tables: legal_hold_exports +           │
                  │          legal_hold_chain +             │
                  │          legal_hold_chain_signing_keys  │
                  │          (C37, DISTINCT from forensic)  │
                  └─────────────────────────────────────────┘

                  ┌─────────────────────────────────────────┐
                  │            GD frontend                  │
                  │   (global-dashboard.jsx, C50)           │
                  │  Tab: Legal Hold (VP/CISO)              │
                  │   • Inline create card                  │
                  │   • Chain inspector                     │
                  │   • Holds list + Release modal          │
                  └─────────────┬───────────────────────────┘
                                │ POST/GET
                                │ /api/legal-hold-exports
                  ┌─────────────▼───────────────────────────┐
                  │            GD backend                   │
                  │  packages/global-dashboard-server/      │
                  │    index.js (inlined routes, C47e/f)    │
                  │    services/legal-hold-export.js (C47c) │
                  │    services/legal-hold-formats/ (C47d)  │
                  │    gd-encryption.js (Tier-1 GD KEK)     │
                  │  Tables on GD database (C47b):          │
                  │    legal_hold_exports                   │
                  │    legal_hold_chain                     │
                  │    legal_hold_chain_signing_keys        │
                  │      (DISTINCT from GD forensic keys)   │
                  └─────────────────────────────────────────┘
```

Four independent Ed25519 key sets across the platform — MC forensic, MC legal-hold, GD forensic, GD legal-hold — each rotatable independently. Cross-workflow and cross-server cryptographic isolation is maintained throughout.

## Schema design (C37 MC, C47b GD)

Three tables, each on both MC and GD with structurally identical definitions modulo the encryption module reference at service-layer.

### legal_hold_exports

The top-level hold record. Notable columns:

- `case_id` — required litigation/regulatory/investigation reference. Indexed.
- `requested_by_user_id` — references `users(id)`. The creator.
- `rationale` — required, 20-char minimum enforced at route layer.
- `custodian_filter` — optional JSON array of user_ids; restricts evidence to a specific person's activity. Threaded through to slice fetches.
- `indefinite_retention` — INTEGER NOT NULL DEFAULT 1. Retention job MUST check this flag.
- `status` — enum: `'pending'`, `'in_progress'`, `'active'`, `'released'`, `'failed'`. Note `'active'` not `'complete'` — a hold is actively preserving evidence, not "done."
- `hold_released_at`, `hold_released_by_user_id`, `hold_release_rationale` — populated atomically on release.

Two CHECK constraints enforce the separate-actor invariant at the schema layer:

```sql
CHECK (hold_released_by_user_id IS NULL
       OR hold_released_by_user_id != requested_by_user_id)
CHECK ((hold_released_at IS NULL AND hold_released_by_user_id IS NULL)
       OR (hold_released_at IS NOT NULL AND hold_released_by_user_id IS NOT NULL))
```

The first enforces "different actor." The second enforces "released_at and released_by are set atomically — neither can be NULL when the other is non-NULL."

### legal_hold_chain

Append-only chain of hash-linked, Ed25519-signed event entries:

- `event_type` — CHECK constraint enum: `'HOLD_CREATED'`, `'HOLD_COMPLETED'`, `'HOLD_DOWNLOADED'`, `'HOLD_RELEASED'`, `'CHAIN_VERIFIED'`.
- `prev_hash`, `this_hash`, `signature` — same hash chain pattern as forensic_export_chain. `this_hash = SHA-256(prev_hash || canonical(payload))`. `signature = Ed25519(this_hash)`.
- `hold_ref` — references `legal_hold_exports(id)`.
- Two append-only triggers refuse UPDATE and DELETE on any row.

### legal_hold_chain_signing_keys

Ed25519 keypair set for legal hold chain signing. DISTINCT from `forensic_export_chain_signing_keys`. `private_key_encrypted` is encrypted at rest with the host server's Tier-1 KEK. Active key is selected via `WHERE active = 1` partial index.

## Lifecycle

A hold progresses through these statuses:

```
pending → in_progress → active → released
              │
              └→ failed
```

- **pending**: row INSERTed by the orchestrator. Brief — exists only inside the transaction that starts the run.
- **in_progress**: slice fetch + serialization + manifest assembly in flight.
- **active**: archive complete, manifest signed, HOLD_CREATED + HOLD_COMPLETED chain entries appended. The hold is now actively preserving evidence. Downloads are allowed. The retention job MUST skip this row.
- **released**: separate CISO has issued a release with rationale. `hold_released_at` / `hold_released_by_user_id` / `hold_release_rationale` populated atomically inside the release transaction. HOLD_RELEASED chain entry appended. Downloads remain allowed (for post-litigation audit). Retention job is now free to handle this row per its time-bounded policy if `indefinite_retention=0`.
- **failed**: serialization or manifest signing failed. `error_message` populated. Row exists for diagnostics but no archive on disk.

A released hold is not deleted. It remains forever for litigation admissibility — opposing counsel can request the archive years later for case review or appeal.

## The eight format serializers (C39-C45)

Each format file in `server/services/legal-hold-formats/` (or its GD twin) exports:

```
{
  formatId: string,
  fileExtension: string,
  lineOriented: boolean,
  serialize(slices): Buffer
}
```

Loaded into the orchestrator's FORMAT_SERIALIZERS registry via tryLoad() — silent MODULE_NOT_FOUND tolerance during early deploys when some formats may not be present.

| formatId      | ext      | Consumed by                                                | C# |
|---------------|----------|------------------------------------------------------------|----|
| edrm-xml      | .xml     | EDRM-compliant repositories, Relativity ESI ingest        | C39|
| eml-mime      | .mbox    | mbox-parsing tools, email-discovery pipelines             | C40|
| pst           | .zip     | PST-equivalent ZIP container with EML folder layout       | C41|
| concordance   | .dat     | Concordance, Reveal, iCONECT (legacy DAT/OPT load)        | C42|
| relativity    | .zip     | Relativity / Relativity One (DAT+OPT+LFP+NATIVES bundle)  | C43|
| json-tarball  | .tar.gz  | Generic tooling — Python/Go/Rust + stdlib                 | C44|
| pdf-bates     | .pdf     | Any PDF reader, legal counsel direct review               | C45|
| tiff-bates    | .zip     | TIFF-imaged review pipelines + Opticon load file          | C45|

Eight formats covers the vast majority of e-discovery review platforms. The `json-tarball` format exists as the universal fallback for tooling that doesn't speak any of the proprietary formats.

Every format embeds the canonical SHA-256 of each event in a format-appropriate way:

- EDRM XML: `<Tag TagName="ContentHashSHA256" TagDataType="Text" TagValue="..."/>`
- EML/MIME: `X-FireAlive-CanonicalSHA256` header
- Concordance/Relativity: `FA_CANONICALSHA256` column
- JSON tarball: top-level `manifest.json` per-event `sha256` field
- PDF: rendered as text on every page
- TIFF: ImageDescription tag (270) as `CanonicalSHA256=...`

A receiver can verify integrity end-to-end: archive manifest's slice descriptor sha256 → format-specific per-event sha256 → re-compute over the canonical bytes of the event → must match exactly.

## Service orchestrator (C38 MC, C47c GD)

`createLegalHold(db, opts)`:

1. Validate inputs (caseId, rationale ≥ 20 chars, ≥ 1 output format).
2. INSERT row with status='pending', generate `lh-<rand>` ID.
3. Update status='in_progress'.
4. Fetch slices, optionally filtered by `custodianFilter` (user_id, user, sessions.user_id; backup_chain is unfiltered for chain integrity).
5. Serialize each requested format via FORMAT_SERIALIZERS registry.
6. Assemble inner tarball with per-format files + manifest.json + signature.
7. Sign manifest with active Ed25519 key from `legal_hold_chain_signing_keys`.
8. Optionally co-sign with sigstore Cosign if `FIREALIVE_LEGAL_HOLD_USE_COSIGN=1`.
9. Write outer tar.gz to `./data/legal-holds/<hold_id>.tar.gz`.
10. UPDATE row to status='active' with archive_path, archive_sha256, size_bytes.
11. Append HOLD_CREATED + HOLD_COMPLETED chain entries.

`releaseLegalHold(db, holdId, releasedByUserId, rationale)`:

1. Validate rationale ≥ 20 chars.
2. SELECT current row. Verify status='active'.
3. Verify `releasedByUserId !== requested_by_user_id` (orchestrator-layer separate-actor check). Throw `SeparateActorViolation` (statusCode=403) if same.
4. UPDATE row inside a transaction: status='released', hold_released_at=NOW, hold_released_by_user_id, hold_release_rationale. The schema CHECK constraint fires here if a bypass attempt reaches this layer.
5. Append HOLD_RELEASED chain entry.

The custodian filter is critical for privacy: if a hold is opened to preserve evidence relating to "Jane Doe's activity Q3," the resulting archive contains only events touching Jane. Other employees' audit records remain unrevealed. This is the operational hygiene difference between "preserve everything just in case" and "preserve only what the case actually scopes."

## Routes layer (C46 MC, C47e/f GD)

Six endpoints, each role-gated:

| Method | Path                                       | MC role gate       | GD role gate     |
|--------|--------------------------------------------|--------------------|------------------|
| POST   | /api/legal-hold-exports                    | admin OR ciso      | vp OR ciso       |
| GET    | /api/legal-hold-exports                    | admin or ciso      | vp or ciso       |
| GET    | /api/legal-hold-exports/:id/download       | admin or ciso      | vp or ciso       |
| GET    | /api/legal-hold-exports/:id/manifest       | admin or ciso      | vp or ciso       |
| POST   | /api/legal-hold-exports/:id/release        | CISO ONLY          | CISO ONLY        |
| GET    | /api/legal-hold-exports/chain              | admin or ciso      | vp or ciso       |

The CISO-only release gate is identical across MC and GD because release authority is invariant across the platform — only CISOs can sign off on terminating a preservation mandate.

### Triple-layer separate-actor enforcement on release

```
Layer 1 (Route handler):
  Explicit row.requested_by_user_id === req.user.id check.
  Returns 403 with structured response BEFORE invoking orchestrator.
  Cleanest UX path — caught immediately, no DB write.
       │
       ▼
Layer 2 (Orchestrator):
  releaseLegalHold re-checks. Throws SeparateActorViolation
  (statusCode=403). Caught via err.name === 'SeparateActorViolation'.
  Defense-in-depth if a future route bypass exists.
       │
       ▼
Layer 3 (Schema):
  SQLite CHECK constraint on legal_hold_exports refuses the UPDATE.
  SQLITE_CONSTRAINT_CHECK error. Caught via err.code.
  STRUCTURALLY impossible to bypass — lives in the database file itself.
```

Each layer emits `LEGAL_HOLD_RELEASE_DENIED` with a distinct `reason=` subfield:

- `not_found`: 404, hold doesn't exist.
- `not_active`: 409, hold is in pending/in_progress/released/failed state.
- `same_actor`: 403, layer-1 caught.
- `same_actor_orchestrator`: 403, layer-2 caught (layer-1 was bypassed).
- `schema_check`: 403, layer-3 caught (layers 1+2 were bypassed).

Post-hoc audit reports can distinguish which control layer caught the violation. In normal operation, layer 1 always catches first; the lower layers exist to make litigation admissibility provable in court.

## Frontend (C48/C49 MC, C50 GD)

MC uses the existing `<Modal/>` primitive for both Create and Release flows. GD follows its inline-card pattern from 2a's forensic-export tab for create; Release uses a raw fixed-position div (GD has no reusable Modal component).

Both frontends:

- Default `outputFormats` to `["edrm-xml", "eml-mime"]` (the two most universal e-discovery formats).
- Live counter on rationale fields showing `N/20 minimum chars` in danger color until threshold met.
- Status badge per-hold: active=green, released=muted, failed=red, in_progress=blue, pending/other=yellow.
- Release button only appears on `active` holds.
- Download button appears on `active` OR `released` holds.
- Release modal includes a yellow warning card explaining triple-layer separate-actor enforcement.
- No client-side role gate. Server-side enforcement is the security control; client-side gating would be UX-only and bypassable via browser dev tools anyway.

The yellow warning sets expectations before the user tries to release; the modal's error banner surfaces backend errors verbatim if the user proceeds despite the warning. Honest UX: tell users the rules, attempt the action, show the precise error if it fails.

## Chain of custody

The `legal_hold_chain` table tracks every lifecycle event with hash-linked Ed25519 signatures:

```
HOLD_CREATED  ──┐
HOLD_COMPLETED ┘  (atomic pair, emitted on createLegalHold)
HOLD_DOWNLOADED   (emitted per download from route layer)
HOLD_RELEASED     (emitted on releaseLegalHold)
```

Each entry: `this_hash = SHA-256(prev_hash || canonical(payload))`, `signature = Ed25519(this_hash)`. The chain is unforgeable in retrospect — modifying any historical entry breaks every subsequent hash. Append-only triggers prevent UPDATE/DELETE at the SQLite level.

The `signing_key_id` is recorded in the archive manifest so a receiver can fetch the corresponding public key from `/api/legal-hold-exports/chain` and verify signatures even after key rotation.

## ESI repository compatibility matrix

| Review platform        | Native formats    | Alternative                  |
|------------------------|-------------------|------------------------------|
| Relativity / Relativity One | relativity   | edrm-xml, concordance        |
| Concordance            | concordance       | edrm-xml                     |
| Reveal                 | concordance       | edrm-xml, relativity         |
| Everlaw                | edrm-xml          | relativity, concordance      |
| Logikcull              | edrm-xml          | concordance                  |
| DISCO                  | relativity        | edrm-xml                     |
| iCONECT, Ringtail      | concordance + tiff-bates | edrm-xml                |
| Outlook for opposing counsel | pst, eml-mime |                             |
| In-house Python / Go / shell | json-tarball |                             |
| Legal counsel direct review | pdf-bates    | tiff-bates                   |
| Court filings          | pdf-bates         |                              |

A hold producing all 8 formats covers any conceivable review-platform combination. Most cases need only 2-3; CISOs default to edrm-xml + eml-mime and add others as case-specific needs emerge.

## Hand-to-counsel workflow

1. Hold is created and reaches `active` status. The CISO (or delegated counsel-team member with admin or ciso role on MC, vp or ciso on GD) downloads the archive from `/api/legal-hold-exports/:id/download`.
2. The downloaded `<hold_id>.tar.gz` is transferred to opposing counsel or the receiving e-discovery vendor via the case-specific secure channel (typically encrypted SFTP or a vendor-managed upload portal — both are external to FireAlive).
3. Counsel extracts the outer tar.gz to find `manifest.json`, `manifest.sig` (Ed25519 signature over the canonical manifest), and per-format files (e.g., `slices.edrm-xml`, `slices.eml-mime.mbox`, `slices.relativity.zip`).
4. Counsel verifies the manifest signature using the public key from `/api/legal-hold-exports/chain` (active_signing_key.public_key). FireAlive provides the verifier guide; alternatively any standard Ed25519 toolchain works (`openssl pkeyutl -verify`, `python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import ..."`, etc.).
5. Counsel imports the per-format file into their preferred review platform per the ESI repo compatibility matrix above.
6. The chain of custody is preserved: HOLD_CREATED, HOLD_COMPLETED, HOLD_DOWNLOADED entries exist forever in `legal_hold_chain`. Years later for an appeal, the same chain can be re-inspected via `/api/legal-hold-exports/chain`.

When the matter closes, a CISO (different from the original requester) issues a release with rationale via `POST /api/legal-hold-exports/:id/release`. The HOLD_RELEASED chain entry persists; the archive remains downloadable; only the retention job's behavior changes (now free to delete per time-bounded policy if indefinite_retention=0).

## Indefinite retention contract

The `indefinite_retention` flag is the boundary between scheduled retention and litigation hold:

- `indefinite_retention=1` (default for legal holds): retention job MUST skip this row. The archive lives until a release event followed by a future retention pass that the operator explicitly authorizes.
- `indefinite_retention=0`: retention job treats this as a time-bounded preservation order. After the case-specific retention period (set by the operator, typically the time_window_end + N days), the archive may be removed per the platform's retention policy — but the chain entries persist forever.

The retention job (a future C53+ workstream) queries `legal_hold_exports WHERE status IN ('released', 'failed') AND indefinite_retention=0 AND completed_at < ?` for candidates. Active holds are never candidates regardless of age. Released holds with `indefinite_retention=1` are also never candidates.

## Verification (receiver side)

A receiver — opposing counsel, regulator, internal investigator — verifies a delivered archive by:

1. **Extract**: `tar xzf <hold_id>.tar.gz`. Expect `manifest.json` + `manifest.sig` + per-format files.
2. **Read manifest**: parse `manifest.json`. Note `signing.key_id`, `signing.key_fingerprint`, per-slice `sha256` values.
3. **Verify signature**: fetch active or historical public key from `/api/legal-hold-exports/chain` (the response includes `active_signing_key` plus historical keys referenced by rotated `key_id` values). Verify `manifest.sig` against the canonical bytes of `manifest.json` using Ed25519.
4. **Verify slice integrity**: for each per-format file, compute SHA-256. Match against the manifest's slice descriptor `sha256` field. Mismatch indicates tampering.
5. **Verify per-event integrity**: for each event inside a slice file (e.g., a `<Document>` in EDRM XML, a Concordance DAT row, a JSON tarball entry), extract the format-specific canonical SHA-256 field (`ContentHashSHA256`, `FA_CANONICALSHA256`, manifest's per-file `sha256`, etc.). Re-compute SHA-256 over the canonical bytes of the event payload. Match.
6. **Verify chain entries**: fetch `/api/legal-hold-exports/chain`. Walk the chain forward from genesis (prev_hash IS NULL). For each entry, compute `this_hash = SHA-256(prev_hash || canonical(payload))`. Verify Ed25519 signature on `this_hash`. Match.

Any verification failure at any step is grounds to declare the archive non-admissible in the receiver's proceeding. The triple-layer integrity guarantee — Ed25519 manifest signature, archive slice hash, per-event canonical hash — is designed for this scrutiny.

## Threat model

What's defended:

- **Single-actor abuse of release authority**: schema-level CHECK prevents the same user from creating and releasing. SOC 2 / ISO 27001 / SOX-style controls satisfied by structural enforcement, not policy hope.
- **Silent tampering of exported archive**: Ed25519 signature on manifest + per-slice sha256 + per-event canonical hash. Any byte modification anywhere in the chain breaks verification.
- **Cross-workflow key contamination**: legal_hold signing keys are DISTINCT from forensic_export signing keys. Compromise of one workflow's key does not taint the other.
- **Cross-server key contamination**: MC and GD have independent Tier-1 KEKs and independent legal_hold signing keys. Compromise of one server's KEK does not expose the other's.
- **Chain modification**: append-only triggers + Ed25519 chain signatures. Modifying any historical chain entry breaks every subsequent hash.
- **Premature release of evidence**: status='active' is the only releasable state. Pending/in_progress/released/failed all refuse re-release at both orchestrator and route layers.
- **Privacy bleed in custodian-scoped holds**: custodian_filter restricts slices at fetch time to the named user_ids. Events not touching the custodian never reach the archive. Backup_chain is unfiltered because chain integrity requires the full sequence.

What's NOT defended (operator responsibility):

- **Tier-1 KEK compromise on a single server**: a malicious operator with the Tier-1 KEK on (say) MC can sign arbitrary chain entries on MC. This is mitigated by the GD server having its own independent KEK and chain; cross-correlation reveals any single-server compromise. Standard Tier-1 KEK protection (HSM, KMS, careful operator access) is the operator's responsibility.
- **Pre-creation tampering of audit_log**: legal holds preserve what's in the audit_log at hold-creation time. If audit events were never recorded (e.g., the platform was bypassed), they cannot be recovered by any preservation mechanism. The audit_log signing-key chain from R3l Workstream 1 (C1-C19) mitigates this at the audit-log layer.
- **Coordinated multi-actor collusion**: separate-actor enforcement requires two different humans, but two colluding humans (the original requester convincing a friendly CISO to release) cannot be prevented structurally. This is mitigated by audit-log retention of the release event with the CISO's user_id and rationale, which a future review can scrutinize. The chain entry captures the act forever.

## Code layout summary

```
MC:
  server/db/init.js                              (C37: schema additions, +89 lines)
  server/services/legal-hold-export.js           (C38: orchestrator, 808 lines)
  server/services/legal-hold-formats/
    edrm-xml.js                                  (C39, 345 lines)
    eml-mime.js                                  (C40, 366 lines)
    pst.js                                       (C41, 544 lines)
    concordance.js                               (C42, 345 lines)
    relativity.js                                (C43, 480 lines)
    json-tarball.js                              (C44, 300 lines)
    pdf-bates.js                                 (C45, 398 lines)
    tiff-bates.js                                (C45, 453 lines)
  server/routes/legal-hold-exports.js            (C46a, 475 lines)
  server/index.js                                (C46b: 1-line mount insert)
  frontend/firealive-mc.jsx                      (C48/C49: +192 net lines)

GD:
  packages/global-dashboard-server/
    db-init.js                                   (C47a/b: schema, +85 lines)
    services/legal-hold-export.js                (C47c: 808 lines, 1-line diff from MC)
    services/legal-hold-formats/                 (C47d: 8 files byte-identical to MC)
    index.js                                     (C47e/f: +313 inline route handlers)
  packages/global-dashboard/global-dashboard.jsx (C50: +303 net lines)

Docs:
  docs/legal-hold-export.md                      (C51: this file)
  FEATURE-GUIDE.md                               (C52: refreshed Legal Hold section)
```

Total: about 6,500 lines of net-new code across schema, service, formats, routes, and frontends. Eight format serializers cover every major e-discovery review platform; triple-layer separate-actor enforcement makes the release workflow structurally admissible; chain of custody is preserved forever via Ed25519-signed append-only entries; cross-workflow and cross-server cryptographic isolation maintained throughout.
