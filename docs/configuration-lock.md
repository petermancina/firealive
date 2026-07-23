# Configuration Lock & Coverage

FireAlive can freeze every configuration-changing operation behind a single
hardware-passkey ceremony. When the lock is engaged, a request that would change
platform configuration or expand trust is refused at the route layer; reads,
operational actions, and machine-to-machine ingest continue unaffected. This
document describes why the lock exists, exactly what it gates on each server, what
is deliberately left open, the refusal shapes a client sees, how the coverage is
enforced as a CI-checked invariant, and why a database restore always lands locked.

The lock is enforced independently on both server components: the Regional Server
(`server/`) and the Global Dashboard server (`packages/global-dashboard-server/`).
The mechanisms are structural twins, but their wiring differs (see "How the lock is
wired" below), so the two are described together and their differences called out.

## Why this exists

- **Configuration must not drift while nobody is watching.** A lead or CISO who
  steps away should be able to freeze the console so that a walk-up, a forgotten
  open session, or a background task cannot quietly change routing, retention,
  trust anchors, or signing keys.
- **A hijacked session must not be able to mint persistence.** The lock and a
  step-up defend different threats. A step-up proves a human is present for one
  sensitive action; the lock holds the entire configuration surface closed for a
  whole idle window. Engaging the lock converts "any write the session can reach"
  into "no write until someone re-authenticates with hardware."
- **The freeze must be complete, or it is theatre.** A lock that gates the
  obvious `PUT .../config` routes but misses a trust-anchor write, a signing-key
  rotation, or an HA pairing hand-off gives false assurance. Completeness is the
  whole point, so coverage is enforced by CI rather than by review (see "Coverage
  is a CI-checked invariant").

## What the lock gates

The lock gates **configuration-changing and trust-expanding writes** — the
operations that alter how the platform is configured or what it trusts. In
practice this is every mutating request (`POST`/`PUT`/`PATCH`/`DELETE`) that lands
on a registered configuration surface, including:

- Configuration writes proper — routing, retention, reporting, notification,
  SLA-adjacent, self-protection, auto-update-schedule, SASE/SDN, and data-residency
  settings.
- **Trust-anchor and credential-root changes** — the hardware-key attestation
  roots and model allow-list (`/api/iam`), backup and cloud signing-key rotation
  and external-key registration, and registering a new management console with the
  Global Dashboard.
- **Config-time infrastructure hand-offs** — high-availability configuration,
  admin-initiated HA pairing (issuing a pairing token, pairing with a standby),
  storage destinations and routing, migration, external-restore sources, and the
  CI/CD webhook secret.

The set of gated surfaces is not hard-coded into the chokepoint. It is declared in
a registry — `server/middleware/config-write-routes.js` on the Regional Server and
`packages/global-dashboard-server/services/gd-config-write-routes.js` on the Global
Dashboard — as a list of mounts, exact `{method, path}` entries, and a few
patterns. The chokepoint consults the registry on every request, matching against
the full request path (`req.originalUrl`) so the decision is independent of where a
router happens to be mounted.

## What is deliberately left open

Some mutating operations must keep working while the configuration is frozen, or
the freeze would cause an outage or lock an operator out of recovery. These are an
explicit, reasoned allow-list — never an accident of the shape of a path:

- **Lock control itself.** Engaging and releasing the lock, and reading the
  unlock options, must work while locked — otherwise there is no way back.
- **Login and step-up.** Passwordless sign-in, device-key challenges, and the
  step-up assertion must work while locked, because you authenticate *in order to*
  unlock.
- **Credential lifecycle.** Enrolling and revoking a hardware passkey or a device
  certificate is governed by the login + step-up requirement, not by the
  configuration lock, so recovery enrollment is possible even when an operator is
  locked out. (Whether minting a new credential should additionally require a fresh
  step-up is a separate hardening tracked under machine-credential hardening, not
  this lock.)
- **Inbound machine-to-machine ingest.** The Global Dashboard keeps accepting
  metric, compliance-report, and leaderboard pushes from managed consoles, and the
  ticketing/SOAR activity feed keeps flowing into the Regional Server, so a lock
  window never drops operational telemetry. On the Regional Server the activity
  feed (`POST /api/integrations/ticketing/activity-events`) is deliberately mounted
  ahead of the lock gate for exactly this reason.
- **High-availability peer data plane.** The pinned-mTLS replication, heartbeat,
  lease, and pairing-handshake handlers between an active node and its standby run
  outside the lock. Because admin-initiated pairing *is* gated, no new pairing can
  begin while locked, so the inbound handshake handlers are safe to leave open.
- **Operational actions that change no configuration** — running a report,
  triggering an update check, running a compromise or regression scan, generating a
  CI/CD manifest, acknowledging a notification, and so on.

## The three refusal shapes

When the lock (or the anti-clone quarantine that shares the same chokepoint)
refuses a write, the client receives one of three JSON shapes. They are identical
on both servers, and clients key on the machine-readable `code`:

- `403 { code: "INSTANCE_QUARANTINED" }` — the deployment is quarantined because a
  possible clone, fork, or rollback was detected; configuration changes are
  disabled until the instance identity is re-established.
- `423 { code: "CONFIG_LOCK_STATE_MISSING" }` — the lock-state row could not be
  read, so the chokepoint fails closed rather than guess.
- `423 { code: "CONFIG_LOCKED" }` — the configuration is locked, either explicitly
  or by idle auto-relock. The `error` string names hardware MFA as the way to
  proceed.

On the Global Dashboard front-end these are surfaced centrally: any refused write,
from any panel, flips the console to its locked state and shows one clear message
rather than a raw error, so a newly-gated action never fails silently.

## How the lock is wired

The two servers reach the same guarantee by different routes:

- **Global Dashboard — one broad chokepoint.** A single
  `app.use('/api', configLockChokepoint())` fronts every `/api` route, so
  *registering* a path is sufficient to gate it. The Global Dashboard is held to a
  **strict** coverage standard: every mutating endpoint must be gated or listed in
  a reasoned operational allow-list.
- **Regional Server — a chokepoint per mount.** Each configuration mount carries
  its own chokepoint, which only acts on registered paths and passes everything
  else through. This lets a mixed router (for example one that serves both a gated
  `/config` and an operational `/generate`) freeze only the configuration path. A
  Regional Server surface is therefore gated only when *both* its path is
  registered *and* its serving mount carries the chokepoint.

## Coverage is a CI-checked invariant

Completeness is enforced by `scripts/check-config-lock-coverage.js`, which runs in
CI and fails the build if either server has a gap. It enumerates every route on
both servers (resolving aliased mounts, exported-property mounts, and inline
handlers) and checks:

- **Global Dashboard (strict):** every mutating endpoint is either gated or in the
  operational allow-list — a new mutating write of any shape that is neither will
  fail the build.
- **Regional Server (shaped):** every configuration-write-shaped endpoint (a
  `PUT .../config`, a signing-key write, or a trust-anchor write) is gated or
  allow-listed.
- **No stale registry entries** — every registered path corresponds to a real
  route.
- **Wiring** — the Global Dashboard's broad chokepoint exists and every gated
  mount sits behind it; on the Regional Server every registered mount, feature
  router, and the HA config router carries the chokepoint, **and** every registered
  exact path is served by a mount that actually carries the chokepoint. This last
  check closes a subtle gap where a path could be registered yet served by an
  un-choked mount, and so ship ungated.

## A restore always lands locked

A database restore overwrites the live database wholesale from a backup, which
would otherwise carry two node-local security records the platform treats
everywhere else as never-carried: the configuration-lock state and the
anti-rollback fuse high-water mark. Restoring a pre-lock backup would land the node
*unlocked*, and restoring an older backup could roll the anti-rollback mark
*backwards*.

After any restore — the single-file path, the archive path, and the chain-replay
path, on both servers — a post-restore fixup runs on the restored database before
the operator-prompted restart and:

- **re-engages the configuration lock**, so a restored node always comes up frozen
  and requires a hardware unlock before any configuration change; and
- **ratchets the anti-rollback fuse high-water to the maximum of the pre-restore
  and restored values**, so a restore can never lower it. A supported recovery
  (restoring an older good backup under the current binary) still boots, but an
  attempt to run an older binary after a rollback restore is refused.

The fixup is recorded as a dedicated `POST_RESTORE_POSTURE_APPLIED` entry in the
restored node's audit chain. This lands a restore in the same doctrine the golden
baseline already applies to configuration reverts, which likewise never carry the
lock state or the anti-rollback mark.

## Operating the lock

- **Engage / release.** A lead or CISO engages the lock from the sidebar. Engaging
  is a plain action; releasing requires a fresh user-verified hardware-passkey
  step-up at the moment of unlock — a soft credential cannot open it.
- **Idle auto-relock.** The lock re-engages automatically after an idle window
  (default 15 minutes), so a forgotten open session does not leave the
  configuration writable indefinitely.
- **While locked.** Configuration controls refuse writes with a clear message;
  reads, dashboards, operational actions, and inbound ingest continue. Unlock,
  make the change, and either re-lock explicitly or let the idle timer re-engage.
