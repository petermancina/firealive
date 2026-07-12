# High Availability

High Availability gives a FireAlive Regional Server a warm standby and an
automated path to fail over to it. One node runs **active** and serves the
SOC; a second node runs **passive**, sealed and kept current, ready to take
over if the active stops responding. When the active fails, the passive
promotes itself, the organization's load balancer routes traffic to it, and
analysts keep working — without an administrator restoring last night's
backup by hand at 3 a.m.

This document describes shipped behavior. It is written for the SOC
administrators and team leads who configure, pair, and operate a
high-availability pair, and for the security reviewers who need to understand
what the failover authority actually is.

A note up front, because honesty here matters more than marketing. High
Availability is **not** a zero-downtime, zero-data-loss guarantee. Failover
takes a bounded but real amount of time — typically on the order of fifteen
to forty-five seconds, dominated by how long detection is allowed to wait
before it is sure the active is gone. Replication is near-synchronous, so the
recovery point is measured in seconds, not zero. What this feature replaces is
the slow, manual, error-prone recovery that would otherwise follow a server
failure: it turns "page the on-call engineer, find the backup, stand up a new
host, replay the data, re-point everyone" into an automatic promotion that
completes in under a minute. Treat it as automated restore-from-failure, not
as a promise that nothing is ever interrupted.

## Why active/passive, and why not active/active or a cluster

FireAlive has exactly one writer at a time, and that is a deliberate
structural choice, not a limitation waiting to be lifted.

The platform's privacy model seals analyst-private data under keys that the
management tier structurally cannot reach. Promotion to active involves
unsealing a pre-wrapped key-encryption key (KEK) through a hardware-anchored
key agreement — a step designed so that a node can only become a writer by
proving it is the genuine, anchored standby, not a copy. An active/active
design, where two nodes accept writes at once, would mean two independent
writers reconciling conflicting history against the same sealed key material.
That is precisely the situation the sealing is built to prevent. It would also
reintroduce the split-brain risk that the single-writer model exists to rule
out.

So the model is **active/passive**: a single sole-writer active, and a single
warm, sealed passive that becomes the writer only when it has cryptographically
established the authority to do so. An earlier "cluster / horizontal scaling"
direction was dropped entirely in favor of this — scaling FireAlive is a
matter of the work a single anchored instance can do, and availability is a
matter of having a standby ready, not of running many concurrent writers.

The Global Dashboard server is, in this release, a single anchored instance.
Pairing a standby for the GD tier is a separate capability and is out of scope
here.

## What "active" means: the lease and the epoch

The node that is allowed to write is the one holding the current **lease** at
the current **epoch**. This is an internal, cryptographic notion of authority,
and it is the heart of the whole design.

Each node tracks a monotonically increasing epoch number and a lease that
records which node holds write authority and until when. Holding the
unexpired lease at the highest epoch is what makes a node the writer.
Write authority is enforced in three places that all consult this same lease:
the data layer refuses writes from a node that does not hold it, the scheduler
suppresses its business write-jobs on a node that is not the confirmed writer,
and the request layer guards mutating endpoints. The epoch only ever moves
forward — a database-level rule rejects any attempt to lower it — so once a
standby has promoted to a higher epoch, a stale former active can never talk
its way back into authority at the old number.

This is why **the organization's load balancer routes traffic, and nothing
more.** FireAlive does not ship a load balancer and does not ask yours to make
failover decisions. Your balancer simply directs client traffic to whichever
node is reachable; the question of *who is allowed to write* is settled
entirely inside FireAlive by the lease and epoch. The payoff is important: a
flapping, misconfigured, or even compromised load balancer can affect
availability — it can send traffic to the wrong place — but it can never
create a second writer. The worst a bad balancer can do is route requests to a
node that will correctly refuse to write because it does not hold the lease.
Split-brain is contained by construction.

## Pairing the standby

A pair is established once, deliberately, over a mutually authenticated link.

The two servers talk over a dedicated peer channel secured with mutual TLS:
each presents a client certificate and each verifies the other's, so the link
is authenticated in both directions and is not something an outside party can
join. Pairing is initiated with a one-time token rather than a standing
password. During pairing the nodes pin each other's deployment **anchor
fingerprint** and **certificate fingerprint**, so that from then on each will
only accept the specific peer it was paired with — a substituted or cloned
peer presenting different material is rejected and the rejection is audited.

Pairing also performs the key step that makes safe promotion possible. The
passive receives a **pre-wrapped key-encryption key**: sealed material it
holds but cannot open while it is passive. Only at the moment of promotion,
through the hardware-anchored key agreement, does the newly active node unseal
that KEK and gain the ability to serve analyst-private data. A passive node at
rest is therefore warm and current but cryptographically unable to read the
protected tiers — exactly what you want a standby to be.

Finally, the active ships a **baseline snapshot** so the passive starts from a
faithful copy of current state, after which ongoing replication keeps it
current.

## Replication and the recovery point

Once paired, the active replicates its state to the passive
**near-synchronously** at the application level, over the same authenticated
peer link. Changes are journaled and shipped to the standby continuously; the
shipping cadence is governed by the configurable sync interval.

"Near-synchronous" is the honest description. The standby is kept within
seconds of the active, not locked to it transaction-for-transaction. If the
active fails, any writes it had accepted but not yet shipped — at most the last
few seconds' worth — are the recovery-point exposure. This bounded,
seconds-scale RPO is the deliberate trade for keeping the active fast and the
link resilient to brief stalls. The current replication lag is reported in the
status view so you can see, at any moment, how far behind the standby is.

## Failure detection and promotion

While it is active, a node delivers a **heartbeat** to its passive on every
heartbeat interval. The passive watches for those heartbeats. When it has
missed the configured number of them in a row — a threshold of roughly
*miss-count × heartbeat-interval* seconds — it concludes the active is gone,
claims the next epoch, unseals its promotion material, and becomes active.
This waiting period is the largest part of the failover time, and it is
tunable: a shorter heartbeat interval or a smaller miss count fails over
faster but is less tolerant of a brief network hiccup; a longer one is more
patient but slower to recover.

Several safeguards keep promotion correct rather than merely fast:

- **Stale-epoch fencing.** If a former active recovers and discovers that a
  higher epoch now exists — because its old standby promoted while it was
  down — it adopts the higher epoch and steps down to passive rather than
  competing. It cannot reclaim authority at its old epoch.
- **Promotion cooldown.** After a promotion, a cooldown window prevents a
  second promotion from firing immediately on top of it, so a transient
  disturbance cannot drive rapid back-to-back role changes. A throttled
  promotion is audited.
- **Isolation self-fence.** An active that finds itself cut off from *both*
  its peer and its clients — receiving neither replication contact nor client
  requests for the configured self-fence timeout — concludes it has been
  partitioned away from the SOC and **self-demotes to passive**, so it stops
  acting as a writer no one can reach. This check is careful in two ways: it
  fences only when *both* signals are stale (a node still serving clients, or
  still in contact with its peer, is not isolated and is left alone), and it
  observes a grace period after a node takes the lease, so a freshly promoted
  active is never demoted on stale readings before traffic has had a chance to
  arrive. The self-fence only ever steps a node *down*; it never promotes.

## How long failover takes

Plan for a failover window on the order of **fifteen to forty-five seconds**
under typical settings, and understand where the time goes: the great majority
of it is the detection wait described above, by design, so that a momentary
blip is never mistaken for a failure. The actual promotion — claiming the
epoch, unsealing the KEK, flipping the role — is fast once detection has
decided.

You do not have to take that range on faith for your own deployment. The
self-test runs a **real, measured failover-and-failback drill** against the
live pair and reports the actual milliseconds it took, whether the standby
served correctly, whether data integrity held, and whether the original active
was restored afterward. Run it after pairing and after any change to the
timing knobs to learn your true numbers.

## Configuration

High Availability is configured from the Management Console's High
Availability tab, which reads and writes the settings over the HA
configuration endpoint. The knobs:

- **Enabled** — whether this node participates in an HA pair at all. Disabled,
  the node runs standalone and writes freely; nothing about HA constrains a
  single-node deployment.
- **Self endpoint / Peer endpoint** — where this node is reachable and where
  its partner is, for the peer link.
- **Sync interval (seconds)** — how often the active ships replicated state to
  the passive. Lower keeps the standby closer to current; higher reduces link
  chatter.
- **Heartbeat interval (seconds)** — how often the active delivers a heartbeat,
  and the cadence at which the passive checks for one. This, with the miss
  count, sets how quickly a failure is detected.
- **Miss count** — how many heartbeats in a row the passive must miss before
  promoting. Detection threshold is approximately miss-count × heartbeat
  interval.
- **Lease TTL (seconds)** — how long a held lease stays valid between renewals.
- **Promotion cooldown (seconds)** — the window after a promotion during which
  another promotion is suppressed.
- **Self-fence timeout (seconds)** — how long an active may be isolated from
  both peer and clients before it self-demotes.

These are live settings. Saving them re-registers the timing of the heartbeat,
detection, and replication work immediately, so a changed interval takes
effect without restarting the server. Out of an abundance of caution the
intervals are clamped to a sane range internally, so a mistaken value cannot
spin a tight loop or stall delivery.

## Per-deployment tailoring

The pair is established the same way conceptually across substrates, but the
trust step that gates pairing follows the deployment's own root of trust:

- **Bare-metal and virtualized.** The peer link and anchor pinning are used as
  described; each node's hardware or virtual anchor backs its identity.
- **Cloud.** Pairing additionally expects mutual confidential-compute
  attestation, so each node proves it is the genuine enclave-backed instance
  before the partnership and the wrapped-KEK exchange proceed.
- **SDN-segmented networks.** The peer is reachable as a declared system
  segment, so segment-aware admission permits the replication and heartbeat
  channel between the two nodes while the rest of the surface stays
  default-deny.

## Operating it

### Run the self-test

From the HA tab, run the self-test against a healthy pair. It performs a real
failover to the standby and a failback to the original, and reports the
measured failover and failback times, whether the standby served, whether
integrity held, and whether the original was restored. Use it to learn your
deployment's true failover window and to confirm the pair is genuinely ready —
not merely configured.

### Trigger a manual failover

When you need to move the active role on purpose — to patch or reboot the
current active, for example — use the manual failover action rather than
killing the process and waiting for detection. It promotes the standby
deliberately and records the action in the audit log. Drain or redirect
client traffic at your load balancer as part of the same maintenance step.

Manual failover is a deliberate, high-consequence action, so beyond the
lead/admin role it requires a fresh hardware MFA step-up and the configuration
lock to be open. Detection-driven automatic failover is unaffected -- it is not
a gated action, so an unattended failure still promotes the standby on its own.

### "Why didn't it promote?"

If an active failed and the standby did not take over, work through the
expected reasons in order. Confirm the pair is **paired** and the peer link is
reachable from the standby's side — a standby that was never receiving
heartbeats has nothing to miss. Check that enough heartbeats have actually been
missed to cross the threshold; with a long interval and a high miss count, the
detection wait is simply longer than you expected. Check the promotion
cooldown — a promotion that fired recently will suppress another for the
cooldown window, and a throttled attempt is audited. And confirm the standby
is genuinely healthy and anchored, since promotion requires unsealing its
promotion material. Promotion also refuses if the standby's sealed
deployment-mode record is present but does not verify against its own anchor --
tamper evidence, or a record left behind by another node; if a standby is stuck
this way after an upgrade, see *Re-provision a standby's deployment mode* below.
The HA status view and the `HA_*` audit events together will show which of these
applies.

### Watch replication lag

The status view reports current replication lag in seconds. In steady state it
should sit at a few seconds or less. A lag that climbs and stays high points
to a constrained or unstable peer link, or an active under heavy write load
outrunning the shipping cadence; a lower sync interval, or attention to the
link, is the remedy. Lag is also your recovery-point gauge: it is, roughly,
the window of recently accepted writes you would be exposed to losing if the
active failed at that instant.

### Recover a demoted former active

When a failed node comes back after its standby has promoted, it does **not**
fight for the active role. It sees the higher epoch, adopts it, and rejoins as
the passive — now the standby for the node that took over. This is the normal,
healthy outcome: the pair is whole again, with the roles swapped, and you can
fail back on your own schedule (for instance with a manual failover during a
maintenance window) if you want the original node active again. No manual
de-conflicting is required, and there is never a moment when both nodes
consider themselves the writer.

### Rekey a promoted node (shed the shared key)

A node that was promoted holds its replicated operational data (integration
credentials, storage and backup destinations, the CA private key, and the like)
sealed under the key it adopted from the former active -- the shared KEK. Before
that node can be un-paired and run standalone, that data must be re-bound to the
node's own key. That is the offline rekey.

The rekey is a **destructive key operation**, gated by a two-person,
anchor-signed, single-use authorization (a KOA):

1. On the node, request it: `POST /api/key-ops/request` with
   `{ op: "rekey", key_op_ref: "<a label for this rekey>" }` (admin, configuration
   lock open, hardware step-up). This opens a pending two-person approval.
2. A **different** admin approves: `POST /api/key-ops/<approval-id>/approve`
   (admin, hardware step-up). The approver cannot be the requester.
3. Mint the authorization: `POST /api/key-ops/authorize` with
   `{ op: "rekey", key_op_ref: "<same label>", approval_id: "<approval-id>" }`.
   The response contains the KOA `id`.
4. On the node itself (a hardware root of trust is required), run:
   `node server/tools/rekey-node.js --koa <koa-id>`

The tool verifies the KOA offline against the node's anchor public key, consumes
it single-use, and -- in one atomic transaction -- re-seals every replicated
column from the shared KEK to the node's own KEK and then sheds the shared KEK.
It is all-or-nothing: any failure rolls the whole thing back, the authorization
stays usable, and nothing is left half-rekeyed. If a value will not open under
the shared KEK it aborts before writing anything. When it completes, the node is
standalone and un-pairs cleanly.

**Forward-only.** The rekey re-binds only the node's live operational data.
Existing backups and forensic exports stay sealed under the OLD key -- they are
chained, at-rest artifacts and are never rewritten. **Retain the old recovery
code**; it is what reads those older artifacts. Backups taken after the rekey are
under the node's own key.

### Un-pair a node

Un-pairing dissolves the pair and returns both nodes to standalone. Initiate it
with the un-pair action; it clears the peer, releases the lease, stops
replication, resets the node to a clean standalone state, and signals the peer
to do the same. Like manual failover it requires a hardware MFA step-up, the
configuration lock open, and the lead/admin role, and it is audited
(`HA_UNPAIR`). The peer's inbound un-pair endpoint is mutual-TLS-pinned and, in
addition, rate-limited, so a malfunctioning or compromised peer cannot drive
repeated teardowns; a breach is audited (`HA_PEER_UNPAIR_RATE_LIMITED`) and
rejected with a 429.

Un-pair is **fail-closed against data loss**. A node that was promoted at any
point holds its replicated operational data under the key it adopted from the
former active. Un-pairing would strand that data under a key the standalone node
no longer uses, so such a node **refuses to un-pair** and directs you to rekey it
first. Re-binding the replicated data to the node's own key is an offline rekey
-- a separate maintenance action; see "Rekey a promoted node" above. A node that was never
promoted -- a standby you are decommissioning, or the original active -- un-pairs
cleanly.

### Re-provision a standby's deployment mode

A node's deployment mode (bare-metal, virtualized, cloud, and so on) is sealed to
that node's own hardware anchor and is node-local. If a standby was paired under
an earlier release that replicated the mode record, the active's record may have
overwritten the standby's; the standby then reads its mode as bare-metal -- the
strict, fail-safe default -- and, because that record does not verify against the
standby's own anchor, it will refuse to promote. Re-seal the mode on the standby
by re-running the deployment-mode ceremony there. New pairings are unaffected:
the mode now stays node-local and survives pairing, failover, and restart
untouched.

### Mind the cooldown

After any promotion, the cooldown window intentionally blocks a second
promotion. If you are testing failover repeatedly, space your tests beyond the
cooldown, or you will see throttled-promotion audit events rather than the
behavior you were trying to observe.

## What High Availability does not include

- **Zero downtime or zero data loss.** Failover is bounded but not
  instantaneous, and the recovery point is seconds, not zero. This is
  automated restore-from-failure, not continuous uptime.
- **A FireAlive load balancer.** The organization's own load balancer routes
  client traffic. FireAlive settles write authority internally and does not
  ship or depend on a balancer for correctness.
- **Active/active or multi-node clustering.** There is one writer at a time, by
  design. Concurrent writers and horizontal write-scaling are out of scope.
- **Global Dashboard failover.** The GD tier runs as a single anchored
  instance in this release; a paired GD standby is a separate, later
  capability.

## Quick reference

| Property | High Availability |
| --- | --- |
| Topology | Active/passive: one sole-writer active, one warm sealed passive |
| Write authority | Internal cryptographic lease at a monotonic epoch; enforced at the data layer, the scheduler, and the request layer |
| Load balancer | Organization's own; routes traffic only — never decides failover, cannot create split-brain |
| Peer link | Dedicated channel, mutual TLS, both certificates verified |
| Pairing | One-time token; anchor and certificate fingerprints pinned; mismatched/cloned peer rejected and audited |
| Promotion key material | Pre-wrapped KEK held sealed by the passive; unsealed via hardware-anchored key agreement only at promotion |
| Replication | Near-synchronous, application-level, over the peer link; shipping cadence set by the sync interval |
| Recovery point (RPO) | Bounded, seconds-scale — at most the last unshipped writes |
| Detection | Passive promotes after miss-count missed heartbeats (≈ miss-count × heartbeat interval) |
| Failover time | Typically ~15–45s, dominated by the detection wait; self-test measures the real value |
| Stale-epoch fence | A recovered former active adopts the higher epoch and steps down; cannot reclaim the old epoch |
| Isolation self-fence | Active cut off from both peer and clients past the self-fence timeout self-demotes; both signals must be stale; grace period after promotion; never promotes |
| Promotion cooldown | Suppresses a second promotion for a configured window; throttled attempts audited |
| Configurable knobs | enabled, self/peer endpoint, sync interval, heartbeat interval, miss count, lease TTL, promotion cooldown, self-fence timeout — all live, no restart |
| Self-test | Real measured failover-and-failback drill; reports timing, served, integrity, restored |
| Audit events | `HA_CONFIG_UPDATED`, `HA_PAIR_INITIATED`, `HA_PAIRED`, `HA_PAIR_FAILED`, `HA_PEER_REJECTED`, `HA_PROMOTED`, `HA_DEMOTED`, `HA_SELF_FENCED`, `HA_PROMOTION_THROTTLED`, `HA_MANUAL_FAILOVER`, `HA_UNPAIR`, `HA_PEER_UNPAIR_RATE_LIMITED`, `HA_TEST_STARTED`, `HA_TEST_COMPLETE` |
| Per-mode pairing | Bare-metal/virtualized as described; cloud adds mutual confidential-compute attestation; SDN exposes the peer as a system segment |
| Global Dashboard HA | Out of scope (separate, later capability) |
