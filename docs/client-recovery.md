# Per-Client Recovery & Fleet Operations

FireAlive can recover an individual analyst client that has been compromised
or lost, and can run signed operational checks across the connected fleet.
Both surfaces ride the same authenticated WebSocket dispatch channel the
compromise scan uses, and both keep identity pseudonym-only. This document
describes what tear-down and re-provision do, how a rebuilt client recovers
its key, the fleet operations, the routes, and how an operator runs the
feature.

## Why this exists

- **A compromised client must be evicted decisively.** When a compromise scan
  or a reduced-routing tripwire confirms a bad client, the operator needs to
  revoke its credentials server-side immediately — not wait for the client to
  cooperate.
- **Recovery is not offboarding.** The analyst keeps their job and their
  history. Tearing a client down must not destroy the analyst's sealed
  wellbeing data; it must be recoverable on a clean machine.
- **The fleet's health should be verifiable on demand.** A lead needs to pull
  live, signed integrity and posture from connected clients, not trust a mock
  dashboard.

## Tear down

Tear-down is a server-side eviction. It runs in a single transaction and:

- **Revokes the client's active certificates** (`ca.revokeCert`), so the next
  mutual-TLS handshake fails.
- **Retires the device signing key** (`ac_device_signing_keys` active set to
  0), so any further device-signed report is rejected.
- **Deletes the passkey** (`webauthn_credentials`), so the old authenticator
  can no longer log in.

After the transaction commits, the server sends a best-effort `wipe_local`
signal over the WebSocket if the client is still connected; the client clears
its four local files (the E2EE store, the burnout-key wrap, the device key,
and the CA pin) and drops its in-memory key caches. The local wipe is a
courtesy on a possibly-compromised machine — the real guarantee is the
server-side revocation.

**What is deliberately preserved:** the analyst's private key record
(`analyst_keys`) and the recovery wraps (`analyst_key_recovery_wraps`). These
are never crypto-erased by tear-down, because the analyst will recover them on
the rebuilt client. The sealed wellbeing history in the full-suite server
backup stays intact and readable once the key is recovered.

Every tear-down is recorded in `client_recovery_runs` with the certificates
revoked, the device-key and passkey outcomes, and whether the wipe was
dispatched.

## Re-provision

Re-provision issues a one-time enrollment token for binding a fresh, clean
install to the **same** analyst identity (same user id, same pseudonym). The
token is scoped `re-provision`, expires in seven days, and is stored only as a
SHA-256 hash at rest; the plaintext is returned exactly once for out-of-band
delivery. Re-provision advances the open recovery run to `token_issued`.

On the rebuilt client the analyst recovers their existing key rather than
minting a new one — minting a new key would orphan everything the server has
sealed to the old public key. The flow:

1. The client finds no key enrolled locally and asks the server
   (`GET /api/analyst-keys/me`). The server returns the analyst's public key
   and recovery wraps.
2. The analyst enters their offline recovery code and confirms with the new
   passkey. The client unwraps the **same** private key from the recovery-code
   wrap, verifies it matches the expected public key, and re-wraps it under the
   new authenticator's PRF.
3. The client registers the new `prf_primary` wrap with the server
   (`POST /api/analyst-keys/register`), keeping the still-valid recovery-code
   and backup wraps. The key is recovered, never re-minted.

### The recovery code is the only restore path

The offline recovery code shown once at first enrollment is the **only** way
to restore the sealed wellbeing data on a new device. It is stored nowhere in
readable form — not by the analyst, not by the server, not by the
administrator. **If the analyst loses the recovery code and also loses access
to the original device's passkey, the burnout history and baseline cannot be
recovered by anyone.** Helper-pay points and training records are operational,
not sealed to the key, and return regardless. The analyst client states this
in plain terms on the recovery-code screen.

## Fleet operations

A lead or admin dispatches a fleet operation to all connected clients. Four
operations assert system or security state and return an Ed25519 device-signed
result the server verifies before storing:

- **refresh_metrics** — current memory, uptime, version, platform.
- **log_integrity** — the client's sealed local stores still decrypt
  (tamper-evidence).
- **regression** — the client's local subsystems are functional, plus a
  server-reachability probe.
- **vuln_scan** — local security posture and EDR presence per policy.

Two further operations are command-and-acknowledge, with no signed result:
**config_resync** (the client re-pulls feature toggles and re-syncs its
signals) and **update_push** (the client acknowledges an available update).

Connected clients are dispatched immediately; offline clients are queued for
delivery on reconnect within a 15-minute window. A signed result counts toward
run completion only if its signature verifies; an acknowledged command counts
on its ack. Failed or unverified results route through the alert router
(failed -> critical, unverified -> high). There is no per-client backup
operation — the full-suite server backup is canonical.

## Routes

Per-client recovery (`/api/client-recovery`, admin only, config-lock +
MFA step-up):

- `POST /teardown` — body `{ userId, reason? }`. Evicts the client.
- `POST /reprovision` — body `{ userId }`. Returns the plaintext enrollment
  token once.
- `GET /connected` — connected analyst sessions (pseudonym + liveness).
- `GET /runs`, `GET /runs/:id` — recovery run history.

Fleet operations (`/api/client-ops`, lead/admin, operational — no config-lock):

- `POST /dispatch` — body `{ op_type, targets?, params? }`.
- `GET /runs`, `GET /runs/:id` — run history and per-client signed results.
- `GET /retention`, `PUT /retention` — result retention window (admin; null
  for indefinite, or 1..3650 days).

The analyst client's device signing key is registered once via
`POST /api/compromise/device-key` and signs both compromise-scan and fleet-op
results.

## Operating the feature

### From the Management Console

1. Open **System Health**. The **Per-Client Recovery** and **Fleet
   Operations** cards list the connected analyst clients by pseudonym.
2. To recover a client, choose **Tear Down**, confirm the destructive action,
   and complete the MFA step-up. Then choose **Re-provision** to issue the
   enrollment token; it is shown once. Deliver it to the analyst out of band.
3. The analyst installs a fresh client, redeems the token, and recovers their
   key with the offline recovery code and their new passkey.
4. To check the fleet, dispatch a fleet operation; connected clients return
   signed results within a moment. Failed or unverified results raise alerts —
   investigate, and recover the affected client if compromise is confirmed.

### From the API directly

```
POST /api/client-recovery/teardown      { userId, reason?, stepup }
POST /api/client-recovery/reprovision    { userId, stepup }
POST /api/client-ops/dispatch            { op_type, targets, params? }
```

`stepup` is the WebAuthn step-up assertion described in the MFA step-up
middleware. The dispatch endpoint returns the run id, target count, dispatched
count, and the unreachable (queued) ids.

## Sync cadence and urgent refresh

The signal-refresh cadence (`sync_interval_config`) is pushed to each analyst
client over the WebSocket when the client connects and again whenever a lead
saves a change, so a connected client adopts a new interval live. Engaging
panic mode, or an alert-router critical, broadcasts an immediate refresh to
every connected analyst client, so the heightened state surfaces on-device at
once rather than at the next interval.

## Audit trail

Tear-down writes `AC_TEARDOWN`; re-provision writes
`AC_REPROVISION_TOKEN_ISSUED`; fleet dispatch writes `CLIENT_OP_DISPATCHED`.
The recovery and fleet-op runs persist in their own tables
(`client_recovery_runs`, `client_ops_runs`, `client_ops_results`,
`client_ops_queue`) for review. All identity in these surfaces is
pseudonym-only.

## Security model

- **Decisive eviction.** Revoking certificates, retiring the device key, and
  deleting the passkey are all server-side, so a compromised client cannot keep
  acting even if it ignores the wipe signal.
- **Recovery without escrow.** The server holds only opaque recovery wraps it
  cannot unwrap. The key is recovered on-device from the analyst's own recovery
  code, then re-wrapped under the new authenticator. The server never sees a
  private key.
- **No identity leak to management.** Tear-down, re-provision, and fleet
  results are pseudonym-only; the pseudonym-to-name mapping is an out-of-band
  export, never stored.
- **Signed results only.** State-asserting fleet results are verified against
  the registered device key before storage; an unverified result is treated as
  a tampering signal and raised through the alert router.

## Related documents

- `docs/golden-baseline.md` — configuration snapshots and the portable
  baseline.
- `docs/full-suite-backup.md` — the canonical server backup that holds every
  analyst's recoverable state.
- `docs/runtime-monitoring-and-system-health.md` — the System Health tab the
  recovery and fleet-op surfaces live in.
- `docs/iam-and-authentication.md` — passkeys, certificates, and MFA step-up.
