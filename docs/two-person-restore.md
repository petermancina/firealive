# Two-Person Restore Approval

FireAlive's destructive database restore endpoint (`POST /api/restore/execute/:id`) is gated by a two-person approval workflow modeled on the four-eyes principle used in SOC operations and financial controls. This document describes the workflow's design, the three operating modes, the operational procedures for admins, and the audit trail.

## Why this exists

A successful database restore overwrites the live `users`, `audit_log`, `backup_chain`, and every other table with the contents of a prior backup. From a threat-model perspective:

- A compromised admin account with a valid restore endpoint can be used to **roll back security controls** (re-enable disabled accounts, undo policy changes, erase audit evidence of an attack).
- A disgruntled or coerced admin can **destroy operational state** as a single-keystroke action.
- A misclick on the wrong backup can **lose hours-to-weeks of analyst signal data** with no undo.

Requiring a second human's explicit approval before the destructive operation runs converts a one-person attack or accident into a two-person collusion or accident. This is the same pattern used in nuclear-launch authorization, large-value bank transfers, and HSM key generation.

The implementation gates the restore endpoint at the route layer (`server/routes/restore.js`) by requiring the request body to reference a successfully-approved row in the `restore_approvals` table. The approval row is created by the requesting admin, marked approved by a second admin (after verifying TOTP), and consumed by the restore endpoint. Each transition is captured in the audit log and the immutable backup chain.

## Three operating modes

The mode is configured via `system_meta.restore_approval_mode` and read by `services/restore-approval-policy.js`. Choose based on your operational team size and threat model:

### Mode: `strict` (recommended default)

Two distinct admins are required: one to request, one to approve. The approver must verify a TOTP code at approval time. The original requester then has a configurable window (default 24 hours) to consume the approval and run the restore.

Use this mode when:

- You have at least two on-call admins available within the approval window.
- Your threat model includes account compromise (single admin password/JWT theft).
- You operate under SOC 2 / ISO 27001 / regulated-industry expectations of separation of duties.

This is the only mode that fully delivers two-person assurance.

### Mode: `delayed-self-approval`

A single admin can both request and approve their own restore, **but only after the configured window has elapsed since the request**. The window acts as a forced cooling-off period. During the window, a second admin may still approve immediately if available.

Use this mode when:

- You operate a small team (one admin on call) but still want defense against impulse decisions.
- The 24-hour cooling-off period is acceptable in your incident-response posture.
- You want a fallback path if the second admin is unreachable.

The mode trades two-person assurance for time-based assurance. An attacker who steals an admin account can still self-approve, but only after waiting 24 hours during which the legitimate admin is likely to notice the unusual `RESTORE_APPROVAL_CREATED` audit event and revoke the session.

### Mode: `disabled`

No human approval required. The route's approval gate still runs but auto-creates an approved row with `approval_method = 'disabled-mode-bypass'` so the audit trail remains uniform. The restore proceeds as soon as the admin sends the request.

Use this mode when:

- The deployment is a development or test environment with no production analyst data.
- You are running a single-admin home-lab / personal install where the friction outweighs the threat.
- You explicitly accept the risk and have alternative compensating controls.

This mode is **not appropriate for production deployments handling real analyst data**. It exists to keep the code paths uniform and to support unit tests.

## Configuring the mode and window

Mode and window are stored in `system_meta` and read by `services/restore-approval-policy.js`. There is no admin endpoint for changing them in this release; modify via SQL or a future config-management commit:

```sql
UPDATE system_meta SET value = 'strict' WHERE key = 'restore_approval_mode';
UPDATE system_meta SET value = '24'      WHERE key = 'restore_approval_window_hours';
```

Valid mode values are `'strict'`, `'delayed-self-approval'`, `'disabled'`. The window must be a positive integer (hours).

A change to the mode takes effect for **newly created** approval requests. In-flight requests retain the mode they were created under (recorded as `restore_approvals.approval_mode_at_creation`). This prevents a malicious mode-swap from retroactively widening or narrowing approval semantics.

## TOTP enrollment (one-time per admin)

Before an admin can approve a restore in `strict` or `delayed-self-approval` mode, they must enroll a TOTP authenticator (Google Authenticator, 1Password, Authy, etc.). Enrollment is per-user; each admin enrolls their own.

The endpoints are under `/api/mfa/*` and require an authenticated session.

### Step 1 — start enrollment

```http
POST /api/mfa/enroll-start
Authorization: Bearer <jwt>
```

Response:

```json
{
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/FireAlive%20%28alice%29?secret=JBSWY3DPEHPK3PXP&issuer=FireAlive&..."
}
```

The frontend should render `otpauth_url` as a QR code (e.g., via `qrcode-svg` client-side) for the user to scan with their authenticator app. The `secret_base32` value is shown as a fallback for users whose authenticator app does not support QR-code import.

The secret is stored encrypted-at-rest in `users.totp_secret` (Tier-3 AES-256-GCM, hex-encoded into the SQLite TEXT column). Compromise of the column ciphertext alone does not bypass MFA; the attacker also needs `TIER3_ENCRYPTION_KEY`.

The user's enrollment status at this stage: `in_enrollment = true, enrolled = false`. The user has a secret but has not yet proven their authenticator app generates valid codes for it.

### Step 2 — confirm enrollment

The user opens their authenticator app, enters the 6-digit code shown for the FireAlive entry, and submits:

```http
POST /api/mfa/enroll-confirm
Authorization: Bearer <jwt>
Content-Type: application/json

{ "totp_code": "123456" }
```

Response on success:

```json
{ "enrolled_at": "2026-04-18T14:23:11.000Z" }
```

After this, `users.totp_enrolled_at` is set, `users.totp_last_used_step` is seeded with the just-verified step (so the same code cannot be replayed for verify), and the user is fully enrolled.

If the code is wrong, the response is `401 CODE_INVALID`. The user can simply enter the next code from their authenticator. **Failed enrollment confirmations do not count toward the verify lockout** — enrollment is one-shot, locking would just frustrate users typing slightly slowly.

### Step 3 — verify TOTP works (optional sanity check)

```http
POST /api/mfa/verify
Authorization: Bearer <jwt>
Content-Type: application/json

{ "totp_code": "654321" }
```

Response on success:

```json
{ "verified": true, "step": 56908543 }
```

This is the same endpoint admins implicitly hit during the approve flow. Calling it directly is a useful pre-flight before navigating to a sensitive screen.

## The end-to-end restore flow

### Step 1 — admin A requests the restore

```http
POST /api/restore-approvals
Authorization: Bearer <jwt-of-admin-A>
Content-Type: application/json

{
  "backup_id": "abc123def456",
  "request_reason": "Production database corrupted by failed migration; rolling back to pre-migration backup"
}
```

Response (`201`):

```json
{
  "id": "f7a3b8c2d1e9...",
  "backup_id": "abc123def456",
  "requested_by_user_id": "alice-uuid",
  "requested_at": "2026-04-18T14:30:00.000Z",
  "request_reason": "Production database corrupted...",
  "status": "pending",
  "approval_mode_at_creation": "strict",
  "approval_window_hours": 24,
  "expires_at": "2026-04-19 14:30:00",
  ...
}
```

Audit log entry: `RESTORE_APPROVAL_CREATED`.

### Step 2 — admin B reviews the queue

```http
GET /api/restore-approvals/pending
Authorization: Bearer <jwt-of-admin-B>
```

Returns the FIFO queue of pending requests, oldest first. Admin B opens the request, reviews `request_reason`, the `backup_id`, the requester identity, and decides.

### Step 3 — admin B approves with TOTP

```http
POST /api/restore-approvals/f7a3b8c2d1e9.../approve
Authorization: Bearer <jwt-of-admin-B>
Content-Type: application/json

{ "totp_code": "789012" }
```

The route handler:

1. Checks admin B's role (must be `admin`).
2. Calls `totp.verify(db, admin-B's-id, code)`. On any TOTP failure, responds with `TOTP_*` error code mapped to HTTP and writes audit `RESTORE_APPROVAL_APPROVE_TOTP_FAIL`. The approval row is **not** touched.
3. On TOTP success, calls `approvalsSvc.approve()` with `totp_verified: true`. The service enforces the per-mode rules (in `strict`, approver must differ from requester).
4. Writes audit `RESTORE_APPROVAL_APPROVED` with the consumption deadline.

Response on success:

```json
{
  "id": "f7a3b8c2d1e9...",
  "previous_status": "pending",
  "new_status": "approved",
  "approval_method": "second-person-totp",
  "approver_user_id": "bob-uuid",
  "approved_at": "2026-04-18 14:35:00",
  "approval_mode_at_creation": "strict",
  "requested_by_user_id": "alice-uuid",
  "expires_at": "2026-04-19 14:30:00",
  "consumption_deadline": "2026-04-19 14:35:00"
}
```

After approval, the original requester (admin A) has until `consumption_deadline` to consume the approval. The deadline is `approved_at + window_hours` — independent of the request's original `expires_at` to give the requester a full window from the moment of approval.

### Step 4 — admin A consumes the approval and runs the restore

```http
POST /api/restore/execute/abc123def456
Authorization: Bearer <jwt-of-admin-A>
Content-Type: application/json

{
  "approval_id": "f7a3b8c2d1e9...",
  "confirmHash": "..."
}
```

The route handler (`server/routes/restore.js`):

1. Verifies the backup row exists and matches `confirmHash` (R3d-1 idempotency guard).
2. Pre-validates the approval (cheap reads, no mutation):
   - `row.backup_id == :id` (no cross-backup approval reuse).
   - `row.requested_by_user_id == req.user.id` (only the original requester can consume).
   - `row.status == 'approved'`.
3. For v2 backups, verifies the manifest signature and parses archive hashes.
4. Appends a `RESTORE_REQUEST` chain entry to `backup_chain`.
5. Calls `approvalsSvc.consumeApproval()`, which atomically transitions the row to `consumed` and re-checks the consumption deadline (defense-in-depth — the deadline was also enforced inside `approve()` and `findUsableForBackup()`).
6. Performs the destructive write (`fs.copyFileSync` for v1, archive extract for v2).
7. Appends a `RESTORE_COMPLETE` chain entry on the restored DB.
8. Writes audit `DATABASE_RESTORED` and returns chain provenance.

If the consume fails for any reason after step 4, the `RESTORE_REQUEST` chain entry stays in the chain. This is the desired forensic signature of an aborted restore: a `REQUEST` without a matching `COMPLETE` in the chain history.

## Approval expiry — three classes

The system tracks three separate hard-expiry classes, each enforced at multiple layers (defense-in-depth):

### Class 1 — strict pending expiry

A `strict`-mode pending row that never gets approved within the window expires at `expires_at` (= `created_at + window_hours`).

```
created_at -------- window -------- expires_at
                                    │
                                    └─ status set to 'expired'
```

After expiry, the original requester must create a new approval request from scratch. This forces the request reason to be re-examined in the new context (the original justification may no longer apply 24+ hours later).

### Class 2 — delayed-self-approval hard expiry

A `delayed-self-approval` pending row has a longer hard-expiry ceiling because the requester might legitimately wait until the window elapses to self-approve. The hard expiry is `created_at + 2 × window_hours`:

```
created_at ---- window ---- expires_at ---- window ---- hard_expiry
                            │                            │
                            │                            └─ status set to 'expired'
                            │
                            └─ requester may now self-approve (if no other admin has)
```

This bounds the maximum lifetime of any pending row at `2 × window_hours`. Combined with the consumption deadline (Class 3), the total lifetime of an approval is capped at `3 × window_hours` (= 72 hours at the 24h default).

### Class 3 — approved consumption expiry

An approved row must be consumed within `window_hours` of `approved_at`. After the deadline, attempting to consume returns `APPROVAL_CONSUMPTION_DEADLINE_PASSED` and the row is marked expired.

```
approved_at -------- window -------- consumption_deadline
                                     │
                                     └─ status set to 'expired'
```

This prevents an approved-but-unused approval from sitting indefinitely as a latent attack vector.

### Where expiry is enforced

The defense-in-depth model means expiry is enforced at four independent points:

1. `expirePending()` — periodic sweeper (TODO: scheduler integration commit). Marks expired rows in batch.
2. `approve()` — refuses to approve a row past its hard expiry, even if the sweeper hasn't run.
3. `findUsableForBackup()` — refuses to surface an approved row past its consumption deadline.
4. `consumeApproval()` — final check immediately before the destructive write, even if the row was marked usable a millisecond ago.

A bug in any one of these layers does not break the security model. All four would have to be defective for a stale approval to be consumed.

## Audit trail

Every state transition writes a row to `audit_log` (CEF format, SIEM-streamable) and to the appropriate operational logger (winston).

### Audit events

| Event type                              | Written when                                          | Who    |
|------------------------------------------|-------------------------------------------------------|--------|
| `RESTORE_APPROVAL_CREATED`               | Pending row inserted                                  | requester |
| `RESTORE_APPROVAL_APPROVED`              | Pending → approved                                    | approver  |
| `RESTORE_APPROVAL_DENIED`                | Pending → denied                                      | denier    |
| `RESTORE_APPROVAL_APPROVE_TOTP_FAIL`     | TOTP verification failed at approve-time              | approver  |
| `RESTORE_APPROVAL_APPROVE_REJECTED`      | Service rejected approve (mode mismatch, race, etc.)  | approver  |
| `TOTP_ENROLL_START`                      | Secret generated and stored                           | self      |
| `TOTP_ENROLL_CONFIRM_OK` / `_FAIL`       | Enrollment confirmation outcome                       | self      |
| `TOTP_VERIFY_OK` / `_FAIL`               | Step-up verification outcome                          | self      |
| `TOTP_VERIFY_REPLAY` / `_REPLAY_RACE`    | Replay attempt detected                               | self      |
| `TOTP_VERIFY_BLOCKED`                    | Lockout active, request rejected                      | self      |
| `TOTP_DISABLED`                          | User-initiated MFA disable (with valid OTP)           | self      |
| `DATABASE_RESTORED`                      | Destructive restore completed                         | requester |

Plus `RESTORE_REQUEST` and `RESTORE_COMPLETE` entries in `backup_chain` (separate from `audit_log` — the chain is the immutable provenance record for the database itself).

### Querying the audit trail

A typical SOC investigation might use the query tool (`POST /api/query`) to reconstruct a restore event:

```sql
SELECT created_at, user_id, event_type, detail, ip_address
FROM audit_log
WHERE event_type LIKE 'RESTORE_APPROVAL_%'
   OR event_type LIKE 'TOTP_%'
   OR event_type = 'DATABASE_RESTORED'
ORDER BY created_at DESC
LIMIT 100;
```

The CEF column (`audit_log.cef_message`) is what gets streamed to your external SIEM if you've configured one.

## Troubleshooting

### Approve returns `TOTP_NOT_ENROLLED` (403)

The admin attempting to approve has not yet enrolled their authenticator. Walk them through `POST /api/mfa/enroll-start` → scan QR → `POST /api/mfa/enroll-confirm`. After enrollment they can retry the approve.

### Approve returns `TOTP_LOCKED_OUT` (429)

The admin has failed TOTP verification 5 times in 15 minutes. The lockout is in-memory and namespaced as `totp:${userId}`, so it does not affect login. The lockout clears automatically after 30 minutes, or earlier if the server restarts (acceptable for SOC-grade because the audit log retains every failure for forensics — short-term restart resets do not erase the evidence).

### Approve returns `APPROVER_SAME_AS_REQUESTER` (403) in `strict` mode

Strict mode requires two distinct admins. The currently-logged-in admin is the same as the requester. A different admin must approve.

### Approve returns `WINDOW_NOT_ELAPSED` (403) in `delayed-self-approval` mode

The original requester is trying to self-approve before the window has elapsed. They must wait until `expires_at` or have a different admin approve.

### Restore returns `APPROVAL_CONSUMPTION_DEADLINE_PASSED` (409)

The approval was approved more than `window_hours` ago. Create a fresh approval request and start over.

### Restore returns `APPROVAL_REQUESTER_MISMATCH` (403)

The currently-logged-in admin is not the original requester named on the approval. Each approval is bound to its requester at creation time and cannot be consumed by anyone else, even if they're another admin. This is intentional — it forces the audit trail to reflect a clear chain of custody.

### Code returns `CODE_REPLAY` (401)

The admin entered a TOTP code that was already used (either for verify or for enrollment) within its 30-second window. They must wait for the next code from their authenticator.

### Lost authenticator device

There is no self-service recovery path in this release. The admin must:

1. Contact a fellow admin.
2. The fellow admin manually clears `users.totp_secret` and `users.totp_enrolled_at` via a database administration tool.
3. The original admin re-enrolls via `POST /api/mfa/enroll-start`.

A future commit should add a recovery-codes column and a recovery flow that itself requires two-person approval (so an attacker who claims to have lost their device cannot trivially bypass MFA).

## Mode tradeoff matrix

| Property                                  | `strict`              | `delayed-self-approval` | `disabled`      |
|-------------------------------------------|-----------------------|-------------------------|-----------------|
| Two-person assurance                      | Yes                   | After window only       | No              |
| Single-admin compromise resistant         | Yes                   | Time-based (24h notice) | No              |
| Operationally usable with one admin       | No                    | Yes (with delay)        | Yes             |
| Acceptable for production analyst data    | Yes                   | With caveats            | No              |
| Audit trail uniform across approvals      | Yes                   | Yes                     | Yes (bypass row)|
| Time-to-restore in routine ops            | Minutes (admin avail) | Minutes (admin avail)   | Seconds         |
| Time-to-restore worst-case                | Window hours          | 2× window hours         | Seconds         |
| TOTP enrollment required                  | All admins            | All admins              | None            |
| SOC 2 / ISO 27001 compatible default      | Yes                   | Acceptable              | No              |

## See also

- `services/restore-approvals.js` — service implementation with hard-expiry rules.
- `services/restore-approval-policy.js` — mode/window configuration accessor.
- `services/totp.js` — TOTP service used by the approve gate.
- `routes/restore-approvals.js` — admin endpoints (queue, approve, deny).
- `routes/restore.js` — destructive restore endpoint that consumes approvals.
- `routes/mfa.js` — TOTP self-service endpoints (enroll, verify, disable).
- `db/init.js` — `restore_approvals`, `users.totp_*` schema.

## Threat model summary

This control mitigates these threats:

1. **Single-admin account compromise.** Attacker with one admin's credentials cannot restore alone in `strict` mode; cannot restore quickly in `delayed-self-approval` mode.
2. **Compelled-action / coercion.** A second admin's verification creates a witness; coerced restore requires two compromised admins or two coerced admins.
3. **Operator misclick.** The cooling-off window in `delayed-self-approval` and the second-admin gate in `strict` give a chance to catch and abort.
4. **Latent approved-but-unused approval as attack target.** Three-class hard expiry caps total lifetime; consumption deadline forces use-it-or-lose-it.
5. **Cross-backup approval reuse.** `backup_id` is bound at approval creation; consume rejects mismatch.
6. **TOTP replay within validity window.** `totp_last_used_step` advances on every accept; same code cannot be reused even within its 30-second window.
7. **TOTP brute force.** Lockout after 5 failures in 15 minutes; 30-minute cooldown.
8. **Audit log tampering by restore.** `RESTORE_REQUEST`/`RESTORE_COMPLETE` chain entries are recorded on the destination database; `audit_log` is append-only and recovered with the backup it came from. The pair-or-orphan signature in the chain is explicit forensic evidence of any aborted restore.

This control does **not** mitigate:

- Compromise of `TIER3_ENCRYPTION_KEY` (would expose TOTP secrets).
- Compromise of two distinct admin accounts simultaneously.
- Out-of-band access to the database file (bypasses all application controls).
- A malicious operator with shell access to the server (bypasses all application controls).

For these residual risks, see the broader infrastructure-hardening guidance in [infrastructure-hardening.md](./infrastructure-hardening.md) (TBD) and the deployment recipe documents (TBD).
