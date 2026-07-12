# Global Dashboard — High Availability

The Global Dashboard is where a CISO sees the whole fleet. Losing it does not stop analysts working — the
Regional Servers keep serving them — but it blinds cross-region visibility exactly when several regions are in
trouble at once, which is when that view matters most.

High Availability pairs two GD nodes. One is **active** and holds a lease. The other is a **passive** warm
standby that continuously replicates from the active and refuses every write. If the active is lost, the
passive promotes itself.

It is **opt-in**. A GD that has never been paired behaves exactly as it did before this feature existed: every
gate described below fails open when the node is standalone.

---

## Why active/passive, and not active/active or a cluster

Two nodes writing to the same fleet state cannot both be right. The design makes exactly one node entitled to
write at any moment, and makes that entitlement **verifiable from the database itself** rather than from a
convention everyone agrees to follow.

Active/active would require distributed consensus over every write, or last-write-wins, and last-write-wins on
compliance evidence, key material, and audit chains is not a trade a CISO can accept. Multi-node clustering with
shared session state solves a problem the GD does not have: it is a console for a handful of executives, not a
horizontally-scaled service.

If you are reading this because the old console offered "Active-Active (load balanced)" and Redis-backed
clustering: those controls were a mockup wired to nothing, and they were removed. Nothing in the product ever
implemented them.

---

## What "active" means: the lease and the epoch

`gd_ha_lease` holds a single row with an **epoch** (a monotonically increasing integer) and a **holder**. A node
may write only while it holds the current-epoch lease and that lease has not expired.

Promotion claims the **next** epoch. A database trigger, `gd_ha_lease_epoch_monotonic`, aborts any update that
would lower the epoch, so a recovered stale active cannot resurrect itself and diverge.

The trigger forbids a *decrease*, **not a tie**. Any node claiming an epoch after its peer may have claimed one
must adopt the peer's value first, so its own claim lands strictly higher. Both servers assert this in their
regression suites, because a tie is two actives at the same epoch — the exact condition the fence exists to
prevent.

### What a passive refuses

A passive is not merely "expected not to write". Every write path is fenced:

| Path | Fence |
|---|---|
| Mutating HTTP (`POST`/`PUT`/`PATCH`/`DELETE`) | `503` with code `ha_passive_read_only` |
| Background scheduler jobs | `mayRunWriteJob()` |
| Replication apply | epoch fence + destination table allow-list |
| Alert notifications | the replicated `notifications` row is withheld |
| Periodic sweeps (retention, storage retry, archival seal, integration health) | write-gated on the scheduler |
| Scheduled update check | gated in place |

Reads always pass, and the `/api/ha` control plane is always reachable, or you could never pair, promote, drill,
or recover a standby.

**One deliberate exception.** `gdAuditIntegrityTimer` keeps running on the passive. Every node must keep
verifying its **own** audit hash chain: the standby is a live, attackable server, and gating that check would
blind its tamper-evidence — the opposite of what HA is for. It is safe because it writes nothing that
replicates: its checkpoint and any break record are node-local. Do not "fix" this.

---

## The key model

The GD's Tier-1 KEK is sealed to that node's **own hardware root**. There is no software path and no raw-key
fallback. That is what makes a stolen database file useless.

It also means a passive cannot simply be handed the active's key. During pairing, the shared material is wrapped
to the standby's hardware-bound X25519 key via anchor-to-anchor key agreement. The standby stores it sealed and
can only unwrap it on the hardware it was wrapped to. At promotion it unseals that material, installs the shared
KEK and JWT secret, and only then takes the lease.

Two consequences an operator should expect:

- **Sessions survive a failover.** The promoted node installs the shared JWT secret, so tokens the former active
  issued still verify. Nobody is forced to log in again mid-incident.
- **A node with no sealed material refuses to promote.** It would come up unable to read Tier-1 columns. Refusing
  is correct; promoting into a half-working state is not.

---

## Pairing the standby

Pairing is a two-step exchange over mutually-authenticated mTLS, with a one-time token.

1. On the node that will be the **standby**, generate a one-time pairing token
   (`POST /api/ha/pairing-token`, or the button in the console's High Availability tab). It is shown **once** and
   it expires.
2. Carry it to the node that will be the **active**, and pair from there
   (`POST /api/ha/pair` with `{ peerEndpoint, token }`).

The active then verifies the standby's instance anchor and its CA binding, wraps the shared material to the
standby's hardware, ships a baseline snapshot, and finalises the roles. Both nodes pin each other's anchor
fingerprint and TLS leaf thumbprint; the peer control plane admits nothing else.

A node that is already paired refuses to mint a second token or pair again (`409`).

---

## Replication and the recovery point

Replication is **asynchronous**. The active journals changes and ships them to the standby every
`syncIntervalSec` (default 5s). Failover therefore has a **bounded RPO, not zero data loss**: anything the active
had journalled but not yet shipped is lost when it dies.

Watch `replication.lagSeconds` in `GET /api/ha/status` or the console's tab. Under normal conditions it should
sit near zero. Sustained lag means the standby is behind by roughly that many seconds of writes, and that is what
you would lose.

The baseline restore copies only the **replicated** tables. `audit_log` is excluded, so a restored standby keeps
its **own** tamper-evident chain rather than inheriting the active's. `config` is replicated, which is why a
freshly paired standby streams to the same SIEM as its active.

---

## Failure detection and promotion

The active sends a heartbeat every `heartbeatIntervalSec` (default 5s) and renews its lease. The passive
promotes when the heartbeat has been stale for longer than `missCount × heartbeatIntervalSec` (default 15s).

A passive that has never heard a heartbeat does **not** promote. Otherwise a freshly paired standby would take
over during the seconds before the first heartbeat arrives.

Promotion is refused, and audited, when:

- **the node has no sealed promotion material** — it could not serve Tier-1 columns;
- **in Cloud Mode, the node cannot re-attest** as a current confidential VM.

That second refusal is deliberate and it is a real trade. Attestation is time-bounded evidence: a node verified
when it paired may have since been live-migrated, rebooted into a debug state, or had its guest replaced.
Promotion is the moment it unseals the Tier-1 KEK and becomes the fleet's sole writer, so cloud mode re-verifies
first and **fails closed**. The cost is GD availability; the alternative is decrypting fleet data on an
unverified platform, and possibly handing write authority to it while the "dead" active is merely partitioned and
healthy. **Integrity over availability** — and the Regional Servers keep serving analysts throughout.

The attestation check runs **before** the KEK is unsealed, not after.

### Two more ways a node steps down

- **Stale epoch.** An active that discovers the peer holds a higher epoch adopts it and demotes. This is the
  no-split-brain guarantee on the peer-to-peer path.
- **Isolation self-fence.** An active demotes itself only when it has lost **both** the peer link **and** client
  traffic for `selfFenceTimeoutSec`. Both signals are required: an active still serving the SOC is never fenced
  merely because its peer is unreachable. Health-probe traffic from a load balancer does not count as client
  traffic.

---

## Per-deployment tailoring

- **Cloud** — promotion re-attests the local confidential VM and fails closed (above).
- **SDN** — after a role flip the new active re-registers the east-west peer segment. This is best-effort and
  never blocks or unwinds a promotion: your load balancer routes client traffic, not the SDN registration.
- **SASE** — nothing is auto-registered. The peer link must be permitted by your operator-declared
  connector-source allow-list, by design: the SASE boundary is yours to declare, not ours to mutate.
- **Bare-metal / virtualized** — no additional gate.

---

## What reaches your SIEM

HA lifecycle events are appended to the tamper-evident audit chain **and** streamed to your configured SIEM as
CEF, at these severities:

| Severity | Events |
|---|---|
| `critical` | `HA_PROMOTION_REFUSED` |
| `high` | `HA_PROMOTED`, `HA_SELF_FENCED`, `HA_MANUAL_FAILOVER` |
| `warning` | `HA_DEMOTED`, `HA_PAIRED`, `HA_UNPAIR`, `HA_PEER_UNPAIR_RATE_LIMITED`, `HA_PEER_REJECTED`, `HA_PAIR_FAILED`, `HA_SEGMENT_REREGISTER_FAILED` |
| `info` | `HA_SEGMENT_REREGISTERED`, `HA_PROMOTION_THROTTLED`, `HA_PAIR_INITIATED`, `HA_PAIRING_TOKEN_ISSUED`, `HA_CONFIG_UPDATED`, `HA_TEST_STARTED`, `HA_TEST_COMPLETE` |

`HA_PROMOTION_REFUSED` is critical because in Cloud Mode it means the node could not re-attest at the moment it
was to take write authority: the platform is unverified **and** the pair may now have no active at all.

`HA_PEER_REJECTED` is a warning rather than a page. One rejection is usually a certificate rotation on the peer.
A **burst** of them — something repeatedly presenting an unrecognised client certificate to the peer control
plane — is what your correlation rules should alert on.

Operator-initiated events carry the actor in the CEF message as `[actor=...]`.

**These events reach the SIEM only.** They do not go to SOAR, email, or webhooks. If you need a page, build the
rule in your SIEM.

**A drill emits nothing.** Events are delivered only when they are recorded on the live database. A promotion or
self-fence exercised against a scratch copy — as the regression suite does on every run — is recorded where the
change happened and streamed nowhere. A drill can neither forge a row into the audit chain nor page a SOC with a
failover that never occurred.

---

## Operating it

### Run the self-test

**The self-test is a real failover, not a simulation.** It steps this node down, promotes the peer, checks that
the peer serves and that its data checksum matches, and then takes the lease back. Writes are refused for the few
seconds in between.

`POST /api/ha/self-test` (or the console button, which says so before you confirm) returns measured numbers:

- `failoverTimeMs`, `failbackTimeMs` — measured, never claimed
- `served` — the peer actually took the active role
- `integrityOk` — the data checksum matched across the pair
- `restored` — this node took the lease back

**If `restored` is false, the peer is still active.** Check the roles before relying on this node. That is a safe
state — the peer holds a strictly higher epoch — but it is not the state you started in.

The self-test emits `HA_TEST_STARTED` and `HA_TEST_COMPLETE` to your SIEM when run against the live database.

### Trigger a manual failover

`POST /api/ha/manual-failover`, from the **active**. It steps down **first**, then signals the peer to promote —
make-before-break, so this node has stopped writing before the peer starts. If the signal cannot be delivered, the
peer promotes on its own once it notices the active is gone, and this node stays passive either way.

There is no undo from that node. To come back, run a manual failover from whichever node is then active.

Because it is a deliberate, high-consequence action, manual failover requires a fresh hardware MFA step-up in
addition to the CISO role and the configuration lock being open. Detection-driven automatic failover is
unaffected -- it is not a gated action.

### "Why didn't it promote?"

In order, check:

1. `GET /api/ha/status` → is `enabled` true and `peer.paired` true? An unpaired node never promotes.
2. Has a heartbeat ever arrived? `peer.lastHeartbeatAt` null means the pair has not yet exchanged one, and the
   passive will not promote.
3. Is the node inside the post-promotion cooldown (`promotionCooldownSec`, default 60s)? Look for
   `HA_PROMOTION_THROTTLED` in the audit log.
4. Look for `HA_PROMOTION_REFUSED`. In Cloud Mode this means attestation failed. Fix the platform; the node will
   not promote onto an unverified one.
5. Does the node have sealed promotion material? A node paired before the KEK was provisioned will refuse.
6. Does the node's sealed deployment-mode record verify against its own anchor? A record present but not
   verifying -- tamper evidence, or one left by another node -- blocks promotion. If a standby is stuck this way
   after an upgrade, see *Re-provision a standby's deployment mode*.

### Recover a demoted former active

Bring it back up. It will find the peer holding a higher epoch, adopt it, and stay passive. It then replicates
from the new active. Nothing needs to be re-paired.

If it was down long enough that its baseline is stale, re-pair it: `POST /api/ha/pairing-token` on the recovered
node, then `POST /api/ha/pair` from the current active.

### Watch replication lag

`replication.lagSeconds` is your recovery point. Alert on it. A lag of *n* seconds means a failover right now
loses roughly *n* seconds of fleet updates.

### Un-pair a node

`POST /api/ha/unpair`. It clears the peer, releases the lease, stops replication, resets the node to a clean
standalone state, and signals the peer to do the same -- audited `HA_UNPAIR`. Like manual failover it requires a
hardware MFA step-up, the configuration lock open, and the CISO role. The peer's inbound un-pair endpoint
(`/api/ha/peer/unpair`) is mutual-TLS-pinned and, in addition, rate-limited: a malfunctioning or compromised peer
cannot drive repeated teardowns, and a breach is audited (`HA_PEER_UNPAIR_RATE_LIMITED`) and rejected with a
`429`.

Un-pair is **fail-closed against data loss**. A node that was promoted at any point holds its replicated fleet
data under the key it adopted from the former active; un-pairing would strand that data under a key the
standalone node no longer uses, so such a node **refuses to un-pair** and directs you to rekey it first.
Re-binding the data to the node's own key is an offline rekey -- a separate maintenance action, and a later
capability. A node that was never promoted -- a standby you are decommissioning, or the original active --
un-pairs cleanly.

### Re-provision a standby's deployment mode

A node's deployment mode is sealed to its own hardware anchor and is node-local. If a standby was paired under an
earlier release that replicated the mode record, the active's record may have overwritten the standby's; the
standby then reads bare-metal -- the strict, fail-safe default -- and, because that record does not verify
against its own anchor, refuses to promote. Re-seal the mode on the standby by re-running the deployment-mode
ceremony there. New pairings keep the mode node-local through pairing, failover, and restart.

### Mind the cooldown

After promoting, a node will not promote again for `promotionCooldownSec`. This bounds flapping when a pair is
unstable. A `HA_PROMOTION_THROTTLED` in the audit log is that guard doing its job, not a failure.

---

## Configuration

`GET`/`PUT /api/ha/config` (CISO role; subject to the configuration lock). Defaults:

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | HA is opt-in |
| `mode` | `active_passive` | the only supported topology |
| `peerEndpoint` / `selfEndpoint` | `null` | set by pairing |
| `syncIntervalSec` | `5` | how often journalled changes ship |
| `heartbeatIntervalSec` | `5` | how often the active heartbeats and renews its lease |
| `leaseTtlSec` | `30` | how long a lease stays valid without renewal |
| `missCount` | `3` | missed heartbeats before the passive promotes |
| `promotionCooldownSec` | `60` | minimum time between promotions on one node |
| `selfFenceTimeoutSec` | `60` | isolation before an active fences itself |

Changing an interval re-registers the scheduler's HA jobs live; no restart.

---

## What High Availability does not include

- **Zero data loss.** Replication is asynchronous. See the recovery point, above.
- **Active/active or multi-node clustering.** Not implemented, and not planned.
- **Automatic fail-back.** A promoted standby stays active until an operator hands the lease back.
- **A load balancer.** Your LB routes client traffic. It does not decide failover, and the GD does not trust its
  routing: a passive refuses mutating requests no matter who sends them.
- **SOAR, email, or webhook delivery of HA events.** SIEM only.

---

## Quick reference

| | |
|---|---|
| Status | `GET /api/ha/status` |
| Configure | `GET`/`PUT /api/ha/config` |
| Mint pairing token (on the standby) | `POST /api/ha/pairing-token` |
| Pair (from the active) | `POST /api/ha/pair` `{ peerEndpoint, token }` |
| Failover drill (real failover) | `POST /api/ha/self-test` |
| Hand over the lease | `POST /api/ha/manual-failover` |
| Passive refusing a write | `503` `ha_passive_read_only` |

All `/api/ha` endpoints require the CISO role. Mutations are subject to the configuration lock (`423` when
locked).
