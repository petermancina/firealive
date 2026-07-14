# Two-Person Restore Approval

FireAlive's destructive database restore endpoint (`POST /api/restore/execute/:id`) is gated by a two-person approval workflow modeled on the four-eyes principle used in SOC operations and financial controls. This document describes the workflow's design, the three operating modes, the operational procedures for admins, and the audit trail.

## Why this exists

A successful database restore overwrites the live `users`, `audit_log`, `backup_chain`, and every other table with the contents of a prior backup. From a threat-model perspective:

- A compromised admin account with a valid restore endpoint can be used to **roll back security controls** (re-enable disabled accounts, undo policy changes, erase audit evidence of an attack).
- A disgruntled or coerced admin can **destroy operational state** as a single-keystroke action.
- A misclick on the wrong backup can **lose hours-to-weeks of analyst signal data** with no undo.

Requiring a second human's explicit approval before the destructive operation runs converts a one-person attack or accident into a two-person collusion or accident. This is the same pattern used in nuclear-launch authorization, large-value bank transfers, and HSM key generation.

The implementation gates the restore endpoint at the route layer (`server/routes/restore.js`) by requiring the request body to reference a successfully-approved row in the `restore_approvals` table. The approval row is created by the requesting admin, marked approved by a second admin (after a fresh hardware-passkey step-up), and consumed by the restore endpoint. Each transition is captured in the audit log and the immutable backup chain.

## Three operating modes

The mode is configured via `system_meta.restore_approval_mode` and read by `services/restore-approval-policy.js`. Choose based on your operational team size and threat model:

### Mode: `strict` (recommended default)

Two distinct admins are required: one to request, one to approve. The approver must complete a fresh user-verified WebAuthn hardware-passkey step-up at approval time. The original requester then has a configurable window (default 24 hours) to consume the approval and run the restore.

Use this mode when:

- You have at least two on-call admins available within the approval window.
- Your threat model includes account compromise (single admin session/JWT theft — note there is no password to steal; login is a hardware passkey).
- You operate under SOC 2 / ISO 27001 / regulated-industry expectations of separation of duties.

This is the only mode that fully delivers two-person assurance.

### Mode: `delayed-self-approval`

A single admin can both request and approve their own restore, **but only after the configured window has elapsed since the request**. The window acts as a forced cooling-off period. During the window, a second admin may still approve immediately if available.

Use this mode when:

- You operate a small team (one admin on call) but still want defense against impulse decisions.
- The 24-hour cooling-off period is acceptable in your incident-response posture.
- You want a fallback path if the second admin is unreachable.

The mode trades two-person assurance for time-based assurance. An attacker who compromises an admin session can still self-approve, but only after waiting 24 hours during which the legitimate admin is likely to notice the unusual `RESTORE_APPROVAL_CREATED` audit event and revoke the session.

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

## The second-approver step-up

There is no separate enrollment for restore approval. The approving admin re-uses the same FIDO2 hardware passkey they sign in with — approval simply requires a **fresh** user-verified WebAuthn assertion, proving the human at the keyboard is present right now (not merely holding a live session).

The approve route is gated by the shared `mfaStepUp()` middleware (`server/middleware/mfa-stepup.js`), the same step-up used for config-lock, migration, key operations, and data-subject erasure. The client obtains a one-time challenge and signs it before calling approve:

```http
POST /api/mfa/stepup/options
Authorization: Bearer <jwt>
```

Response: a WebAuthn `PublicKeyCredentialRequestOptions` plus a short-lived `challengeToken` (a signed JWT binding the challenge to this user). The client runs `navigator.credentials.get()` with the options, then sends the serialized assertion and the `challengeToken` back inside the approve request's `body.stepup` (see Step 3). The assertion is single-use and bound to the challenge; the middleware rejects an unknown or foreign credential, a wrong or replayed challenge, or a non-user-verified assertion.

Because the step-up credential is the admin's login passkey, there is no shared secret at rest and no per-admin enrollment ceremony to manage. An admin who can sign in can approve; an admin who has lost their hardware key uses the break-glass path (see Troubleshooting).

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

### Step 3 — admin B approves with a passkey step-up

Admin B first fetches step-up options and signs the challenge (see "The second-approver step-up" above), then submits the assertion with the approve call:

```http
POST /api/restore-approvals/f7a3b8c2d1e9.../approve
Authorization: Bearer <jwt-of-admin-B>
Content-Type: application/json

{
  "stepup": {
    "challengeToken": "<jwt from POST /api/mfa/stepup/options>",
    "response": { /* serialized WebAuthn assertion */ }
  }
}
```

The route handler (`routes/restore-approvals.js`):

1. `approveAdminGate` — refuses non-admins with `403 FORBIDDEN` before any step-up work.
2. `mfaStepUp()` — verifies a fresh user-verified WebAuthn assertion from `body.stepup`. On failure it responds with the step-up error (`401 MFA_STEPUP_REQUIRED` if none supplied, `400 INVALID_INPUT` if malformed, `401 STEPUP_FAILED` if the credential is unknown/foreign or the assertion fails verification) and the approval row is **not** touched. On success it sets `req.mfaStepUp.method = 'webauthn'`.
3. Delegates to `approvalsSvc.approve()` with `stepup_verified: true`. The service enforces the per-mode rules (in `strict`, the approver must differ from the requester) and rejects a call without a verified step-up via `STEPUP_NOT_VERIFIED`.
4. Writes audit `RESTORE_APPROVAL_APPROVED` with the consumption deadline. If the service rejects the transition (mode mismatch, race, etc.), it writes `RESTORE_APPROVAL_APPROVE_REJECTED` instead.

Response on success:

```json
{
  "id": "f7a3b8c2d1e9...",
  "previous_status": "pending",
  "new_status": "approved",
  "approval_method": "second-person-webauthn",
  "approver_user_id": "bob-uuid",
  "approved_at": "2026-04-18 14:35:00",
  "approval_mode_at_creation": "strict",
  "requested_by_user_id": "alice-uuid",
  "expires_at": "2026-04-19 14:30:00",
  "consumption_deadline": "2026-04-19 14:35:00"
}
```

The `approval_method` is `second-person-webauthn` when a second admin approves. In `delayed-self-approval` mode, a requester who self-approves after the window records `delayed-self-webauthn`; in `disabled` mode the auto-created row records `disabled-mode-bypass`.

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
| `RESTORE_APPROVAL_APPROVED`              | Pending → approved (after a verified step-up)         | approver  |
| `RESTORE_APPROVAL_APPROVE_REJECTED`      | Service rejected approve (mode mismatch, race, etc.)  | approver  |
| `RESTORE_APPROVAL_DENIED`                | Pending → denied                                      | denier    |
| `DATABASE_RESTORED`                      | Destructive restore completed                         | requester |

A failed step-up at approve time is refused by the `mfaStepUp()` middleware before the service is reached; the WebAuthn step-up ceremony (challenge issue, assertion verify, and any failure) is itself audited by the shared step-up middleware, so a failed approval attempt is still forensically visible without a restore-specific event.

Plus `RESTORE_REQUEST` and `RESTORE_COMPLETE` entries in `backup_chain` (separate from `audit_log` — the chain is the immutable provenance record for the database itself).

### Querying the audit trail

A typical SOC investigation might use the query tool (`POST /api/query`) to reconstruct a restore event:

```sql
SELECT created_at, user_id, event_type, detail, ip_address
FROM audit_log
WHERE event_type LIKE 'RESTORE_APPROVAL_%'
   OR event_type = 'DATABASE_RESTORED'
ORDER BY created_at DESC
LIMIT 100;
```

The CEF column (`audit_log.cef_message`) is what gets streamed to your external SIEM if you've configured one.

## Troubleshooting

### Approve returns `MFA_STEPUP_REQUIRED` (401)

No step-up assertion was supplied in `body.stepup`. The client must first call `POST /api/mfa/stepup/options`, run `navigator.credentials.get()`, and resend the approve request with the serialized assertion and `challengeToken`. In the Management Console this is automatic — the approve button drives the ceremony for you.

### Approve returns `STEPUP_FAILED` (401)

The assertion did not verify: the credential is unknown or belongs to a different user, the challenge was wrong or already used, or user-verification (PIN/biometric) was not satisfied. Retry the step-up; if it persists, confirm the admin is using a hardware key already registered to their own account.

### Approve returns `INVALID_INPUT` (400)

The `body.stepup` payload was malformed (missing `challengeToken` or `response`, or an unparseable assertion). This is a client-integration error, not a credential problem.

### Approve returns `STEPUP_NOT_VERIFIED` (403)

The service was asked to record an approval without a verified step-up. In normal operation the route guarantees this cannot happen (the `mfaStepUp()` middleware runs first); seeing it indicates a route wired to call `approve()` without the middleware — a bug to fix, not an operational condition.

### Approve returns `APPROVER_SAME_AS_REQUESTER` (403) in `strict` mode

Strict mode requires two distinct admins. The currently-logged-in admin is the same as the requester. A different admin must approve.

### Approve returns `WINDOW_NOT_ELAPSED` (403) in `delayed-self-approval` mode

The original requester is trying to self-approve before the window has elapsed. They must wait until `expires_at` or have a different admin approve.

### Restore returns `APPROVAL_CONSUMPTION_DEADLINE_PASSED` (409)

The approval was approved more than `window_hours` ago. Create a fresh approval request and start over.

### Restore returns `APPROVAL_REQUESTER_MISMATCH` (403)

The currently-logged-in admin is not the original requester named on the approval. Each approval is bound to its requester at creation time and cannot be consumed by anyone else, even if they're another admin. This is intentional — it forces the audit trail to reflect a clear chain of custody.

### Lost hardware key

There is no self-service reset for a lost passkey (a self-service reset would be a bypass an attacker could claim). The admin recovers login — and therefore approval capability — through the break-glass enrollment path (`POST /api/auth/break-glass`, which authorizes registering a new hardware key), then approves as normal. Because approval re-uses the login passkey, once the admin can sign in again they can approve again; there is nothing restore-specific to re-enroll.

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
| Approver step-up required                 | Hardware passkey      | Hardware passkey        | None            |
| SOC 2 / ISO 27001 compatible default      | Yes                   | Acceptable              | No              |

## See also

- `services/restore-approvals.js` — service implementation with hard-expiry rules and the `stepup_verified` contract.
- `services/restore-approval-policy.js` — mode/window configuration accessor.
- `middleware/mfa-stepup.js` — the shared WebAuthn step-up middleware used by the approve gate.
- `routes/restore-approvals.js` — admin endpoints (queue, approve, deny).
- `routes/restore.js` — destructive restore endpoint that consumes approvals.
- `docs/iam-and-authentication.md` — the hardware-passkey login and step-up model.
- `db/init.js` — `restore_approvals` schema.

## Threat model summary

This control mitigates these threats:

1. **Single-admin account compromise.** An attacker with one admin's session cannot restore alone in `strict` mode; cannot restore quickly in `delayed-self-approval` mode. Login is a hardware passkey, so there is no password to phish or replay in the first place.
2. **Compelled-action / coercion.** A second admin's step-up creates a witness; a coerced restore requires two compromised admins or two coerced admins, each physically present with their hardware key.
3. **Operator misclick.** The cooling-off window in `delayed-self-approval` and the second-admin gate in `strict` give a chance to catch and abort.
4. **Latent approved-but-unused approval as attack target.** Three-class hard expiry caps total lifetime; consumption deadline forces use-it-or-lose-it.
5. **Cross-backup approval reuse.** `backup_id` is bound at approval creation; consume rejects mismatch.
6. **Session-replay approval.** Approval requires a *fresh* user-verified assertion, so a stolen JWT alone cannot approve — the attacker would also need the admin's hardware key, present and unlocked at approve time.
7. **Stolen-session restore without presence.** The step-up is phishing-resistant and device-bound; there is no shared secret to exfiltrate that would let an attacker approve remotely.
8. **Audit log tampering by restore.** `RESTORE_REQUEST`/`RESTORE_COMPLETE` chain entries are recorded on the destination database; `audit_log` is append-only and recovered with the backup it came from. The pair-or-orphan signature in the chain is explicit forensic evidence of any aborted restore.

This control does **not** mitigate:

- Compromise of two distinct admin accounts *and* their hardware keys simultaneously.
- Out-of-band access to the database file (bypasses all application controls).
- A malicious operator with shell access to the server (bypasses all application controls).

For these residual risks, see the broader infrastructure-hardening guidance in [infrastructure-hardening.md](./infrastructure-hardening.md) (TBD) and the deployment recipe documents (TBD).
