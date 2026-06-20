# SDN Mode

Operator runbook for running a FireAlive Regional Server inside a
software-defined network and having FireAlive treat that network as a
security boundary it continuously verifies. SDN Mode is a deployment mode
alongside bare metal, virtualized, and cloud. It exists so a SOC whose
network is segmented by an SDN fabric can have FireAlive confirm —
continuously, and without trusting the network blindly — that its own
segmentation is intact, and refuse to serve traffic when that assurance is
lost.

This document describes shipped behavior. It is written for SOC
administrators and team leads operating the Regional Server and Management
Console (MC).

A note up front, because it is the most common question: **SDN Mode does
not change how the FireAlive server runs.** The server is still a direct
host process on bare-metal hardware with a TPM, or a VM with a vTPM, exactly
as in bare-metal and virtualized mode. It is never a Kubernetes pod or a
managed container. SDN Mode adds a network-layer posture: FireAlive reads
the SDN controller, admits only permitted segments, fails safe if
segmentation assurance is lost, and generates a segmentation policy for the
operator to apply. It never programs the controller.

## Why SDN Mode exists

A segmented network is one of the strongest controls a SOC has: if analyst,
management, and infrastructure traffic live in separate micro-segments, a
foothold in one place does not become a foothold everywhere. But
segmentation is only as good as its current state. A misapplied policy, a
controller drift, or an attacker who has reached the fabric can quietly
erase the boundary the SOC believes it has.

SDN Mode makes FireAlive an active participant in that boundary rather than
a passive resident of it. It does three things a plain deployment cannot:

- It **admits connections by segment**, so the API is not even reachable
  from outside the segments FireAlive’s components are supposed to occupy.
- It **continuously verifies** the segmentation posture by reading the SDN
  controller, and it **fails safe** — locking its own API surface — when
  it can no longer prove segmentation is intact.
- It **generates a least-privilege segmentation policy** from the tiers it
  already separates internally, so the network boundary mirrors the data
  boundary.

Crucially, FireAlive only ever *reads* the controller. It never pushes,
applies, or programs network configuration. The fabric remains under the
operator’s control and change process; FireAlive verifies and advises.

## Supported controllers

SDN Mode integrates with the following controllers. Each integration is
**read-only** toward the controller and runs over a certificate-pinned
connection.

- **Cisco ACI** — the APIC controller’s REST API.
- **VMware NSX** — the NSX-T Manager policy API.
- **OpenFlow** — an OpenFlow SDN controller through its northbound REST API
  (for example OpenDaylight or ONOS).
- **Arista CloudVision** — the CloudVision Portal (CVP) API.
- **Juniper CN2** — Cloud-Native Contrail / Tungsten Fabric.
- **Calico** — the Calico (Tigera) policy API.
- **Cilium** — the Cilium policy API.
- **Custom REST** — a generic REST controller, for fabrics that expose their
  own segmentation API.

Three of these — Calico, Cilium, and Juniper CN2 — are Kubernetes-native
fabrics. FireAlive integrating with them means FireAlive **reads** that
fabric’s controller to verify segmentation and can generate native policy
objects for it. It does **not** mean FireAlive runs inside that cluster. The
FireAlive server remains on its own TPM/vTPM host and verifies the
surrounding fabric from there. (See *What SDN Mode does not include*.)

## What SDN Mode enforces

### Hardware root of trust: unchanged

SDN Mode reuses FireAlive’s instance-anchor design without modification. The
anchor’s private key is sealed to the host’s hardware root of trust — a TPM
2.0 on bare metal, or a vTPM in a virtualized guest — and underpins the
deployment CA, server certificates, analyst-client registrations, and
enrollment tokens, exactly as in every non-cloud mode. No new backend is
introduced, and there is no software-key fallback. A deployment with no
hardware root of trust refuses to start.

This is why SDN Mode is not a container workload: an orchestrated container
does not present a per-instance TPM, so it cannot hold the anchor
FireAlive’s identity depends on.

### Host substrate

SDN Mode is the one mode that composes with a *host substrate*. The other
modes are themselves the substrate — bare-metal, virtualized, and cloud each
describe the machine FireAlive runs on. An SDN deployment can run on any of
the three, so it records its host substrate separately and layers the
matching host defenses on top of its SDN networking and admission.

- **SDN on bare metal** — a hardware TPM 2.0 on dedicated hardware. The host
  is not easily copied, so beyond the anchor and SDN admission there is
  nothing further to enforce; this is a pass-through.
- **SDN on a virtualized host** — a vTPM in a VM or hypervisor. A VM is
  trivially snapshotted, paused, and cloned, so the host-presence and
  clock-integrity defenses apply: session-less enrollment and signed device
  actions are refused when the clock cannot be trusted, and an instance that
  looks cloned or rolled back is quarantined before authentication.
- **SDN on cloud** — a confidential VM on AWS, Azure, or GCP with a vTPM
  root of trust. Everything the virtualized substrate enforces applies, plus
  confidential-computing attestation at boot and refusal of spot and
  autoscaled instances, exactly as in cloud mode.

The substrate is **declared by the operator** and is **required**: set
`FIREALIVE_SDN_SUBSTRATE` to `bare-metal`, `virtualized`, or `cloud` before
the first start. If it is absent or invalid the server refuses to boot —
there is no default, because silently under-classifying a copyable host (for
example reading a cloud VM whose metadata is unreachable as bare metal) would
skip the very defenses that host needs.

Detection is used only to *refute* an unsafe declaration, never to relax one.
At boot the server independently detects the substrate; if what it detects is
stronger evidence of a copyable host than what was declared — a hypervisor is
present but bare metal was claimed — it refuses to start (anti-downgrade).
Over-claiming is allowed: declaring a stricter substrate than the host truly
is only adds enforcement, and the stricter gate self-corrects. Like the mode
itself, the substrate is sealed into the anchor-signed deployment record at
first boot, so it cannot be flipped later.

### Segment-aware admission

The operator declares, in the network map, which network segments
FireAlive’s own components occupy. When SDN Mode is active, an admission
check runs **before authentication** on every inbound connection: if the
connection’s source address does not fall within a permitted segment, it is
refused outright. A foothold elsewhere on the network cannot reach the API
surface to attack it, brute-force it, or probe it.

The permitted-segment list is matched by CIDR or exact address and is cached
with a short refresh interval, so updates to the network map take effect
without a restart. Loopback and local traffic are **always** admitted, so
the host itself remains manageable regardless of the declared segments.
Admission is only enforced in SDN Mode; in other modes the check passes
through.

### Continuous, read-only posture verification

A scheduler probes each enabled controller integration on a recurring
cadence. For each integration it decrypts the stored read-only credentials,
resolves the platform adapter, and performs a **read-only** probe over the
certificate-pinned connection — confirming the controller is reachable, that
the credentials authenticate, and that segmentation data can be read. The
probe never writes to or changes the controller.

Each probe result updates the integration’s success/failure counters and
appends an immutable posture event. A pure classifier then grades each
integration — roughly *up*, *watch*, or *down* — from its consecutive
results and the age of its last successful probe, using fixed thresholds (a
run of failures, a smaller run of authentication or error failures weighted
more heavily, a run of successes to recover, and a staleness ceiling). Those
per-integration grades roll up into one of three deployment posture states:
**healthy**, **uncertain**, or **degraded**.

Read-only is enforced structurally, not by convention. The adapter registry
refuses to load any adapter that exposes a write-capable method, and every
controller request goes through a single shared HTTPS client that mandates
certificate pinning, never disables TLS verification, refuses redirects,
supports optional mutual TLS, and caps response size. There is one outbound
chokepoint, and it cannot make a change on the controller.

### Assume-breach fail-safe lockdown

Posture verification is not advisory to the running server — it gates it.
When the deployment posture is **degraded**, a fail-safe denies the
**entire** `/api/` surface. The allow-list of endpoints that remain
reachable while degraded is **empty**: health and status endpoints are
denied along with everything else, on purpose, so the lockdown leaks no
information about system state and offers no in-band path to lift it. If the
posture state itself cannot be read, the gate treats that as degraded and
denies — it fails secure, not open.

The **uncertain** state, by contrast, passes traffic. Uncertain is the
debounce band between healthy and degraded; passing it prevents a single
flaky probe from locking the SOC out of its own tooling. Lockdown is
reserved for a posture the deployment has actually concluded is degraded.

Recovery is automatic and out-of-band: there is no override endpoint and no
operator bypass. When the underlying controllers become reachable and
authenticate again, the next posture evaluation returns the deployment to
healthy and the API surface comes back on its own. The operator’s job during
a lockdown is to fix the network, not to talk FireAlive out of the lockdown.

### Least-privilege segmentation policy

From the **tier-to-segment map** the operator declares, FireAlive generates
a **default-deny** micro-segmentation policy: every flow is denied unless it
is one of a small set of required, least-privilege flows. The policy is
rendered in the target platform’s own vocabulary — concrete policy objects
for the Kubernetes-native fabrics (Calico, Cilium, Juniper CN2), structured
intent for the controller platforms (Cisco ACI, VMware NSX, OpenFlow, Arista
CloudVision), and a canonical intent document for a custom REST fabric.
Every rendered artifact also embeds the canonical intent, so the operator
can verify that what was rendered for their platform matches what FireAlive
meant.

The policy is **advisory**. FireAlive generates it and makes it available to
download; the operator reviews it and applies it through their own change
control. FireAlive never applies it to the controller.

### Structural privacy at the network layer

The generated policy carries FireAlive’s central privacy guarantee down to
L3/L4. Management and aggregate zones (Tier-1) are **never** permitted to
reach analyst-private zones (Tier-3). This is true by construction: no flow
from a management or aggregate zone to an analyst-private zone exists in the
required-flow set, so no allow rule reaching analyst-private data can be
emitted for any platform. The separation FireAlive enforces in its data
model — management cannot read individual analyst data, even with database
access — is the same separation the network policy expresses.

## Configuring the controller integration

SDN configuration lives behind the MC’s SDN surface and is reachable only by
an administrator, and only when the configuration lock is open. The surface
covers:

- **Integrations** — create, list, read, update, and delete controller
  integrations. Each integration has a name, a platform, the controller’s
  API endpoint, and read-only credentials.
- **Probe** — run an on-demand read-only probe of one integration.
- **Topology and segmentation** — read the topology and segmentation data an
  integration exposes.
- **Network map** — read and update the permitted segments and the
  tier-to-segment map.
- **Posture** — read the current deployment posture and the recent posture
  events.
- **Segment policy** — generate and download the segmentation policy for a
  chosen platform.

Two properties matter for safe operation:

- **Credentials are write-only.** Controller credentials are stored
  encrypted under the Tier-1 key and are **never returned** by the API. A
  read of an integration reports only that credentials are configured, not
  their value. Updating an integration without resupplying credentials
  preserves the stored ones; it does not blank them.
- **Platform is immutable.** An integration’s platform is fixed when it is
  created. To move to a different platform, the operator deletes the
  integration and creates a new one. Deleting an integration preserves the
  append-only posture-event history (the events’ link to the integration is
  cleared, the events themselves are kept).

Every configuration action is audited by operator and action, recording
whether credentials changed — never their value.

## The network map

The network map is a single document with two parts:

- **Permitted segments** — the CIDRs and addresses FireAlive’s own
  components occupy. This list drives segment-aware admission: a connection
  from outside these segments is refused before authentication.
- **Tier-to-segment map** — which segments host which FireAlive tier. This
  drives segmentation-policy generation: it is the input from which the
  default-deny, least-privilege policy is built, and it is where the
  Tier-1-cannot-reach-Tier-3 invariant is grounded.

An optional record of SD-WAN sites can accompany the map for multi-site
fabrics.

## Deploying

SDN Mode is provisioned like any other non-cloud deployment, with the
controller integration configured after first boot.

1. **Provision a host with a hardware root of trust.** Bare-metal hardware
   with a TPM 2.0, or a VM with a vTPM. This is an ordinary FireAlive host —
   not a container, not a Kubernetes workload.
2. **Install FireAlive.** Run the installer on the host as you would for any
   deployment.
3. **Select SDN mode and host substrate at first boot.** Set the deployment mode to `sdn`
   before the first start (the deployment-mode environment variable), and set
   `FIREALIVE_SDN_SUBSTRATE` to `bare-metal`, `virtualized`, or `cloud` for
   the host this instance runs on; it is required, and the server refuses to
   boot without it. On first boot the server seals both SDN mode and the
   substrate to the hardware root, so neither can be flipped later — the same one-time, sealed choice as bare-metal,
   virtualized, and cloud.
4. **Confirm the anchor pin.** Each Analyst Client and the Global Dashboard
   show the deployment anchor fingerprint on first connection. Confirm the
   pin only if it matches the fingerprint the server printed at boot.
5. **Add the controller integration.** In the MC’s SDN surface, create an
   integration for your fabric: platform, controller endpoint, and read-only
   credentials. Run a probe to confirm it is reachable and authenticates.
6. **Declare the network map.** Set the permitted segments (which drive
   admission) and the tier-to-segment map (which drives policy generation).
7. **Generate, review, and apply the segmentation policy.** Generate the
   policy for your platform, review it, and apply it through your own change
   control. FireAlive does not apply it for you.

Once the integration is configured, the posture scheduler runs on its own
cadence and the admission and fail-safe behaviors are active.

## What SDN Mode does not include

- **Controller writes.** FireAlive never programs, applies, or pushes
  configuration to the SDN controller. Every integration is read-only,
  enforced by the adapter registry and the single pinned HTTPS chokepoint.
  The generated segmentation policy is advisory; the operator applies it.
- **Running as a container or Kubernetes workload.** The FireAlive server is
  a direct host process on a TPM/vTPM host. This is true even when the
  integrated controller is a Kubernetes-native fabric such as Calico,
  Cilium, or Juniper CN2: FireAlive *reads* that fabric’s controller from
  its own host to verify segmentation and to generate native policy, but it
  does not run inside the cluster. Orchestrated containers do not present the
  per-instance TPM the instance anchor requires.
- **A replacement for the fabric’s own enforcement.** SDN Mode verifies
  posture, admits its own surface by segment, and fails safe; the SDN fabric
  is still what actually enforces segmentation on the wire. FireAlive checks
  and advises; it does not become the network’s policy engine.
- **High availability.** SDN Mode runs a single anchored instance.
  Active/passive or active/active failover is a separate capability and is
  out of scope here.

## Quick reference

| Property | SDN Mode |
| --- | --- |
| Server runtime | Direct host process on a TPM 2.0 / vTPM host — never a container or Kubernetes workload |
| Hardware root of trust | Host TPM / vTPM, reusing the deployment anchor; no software fallback |
| Host substrate | SDN only: declared and required via `FIREALIVE_SDN_SUBSTRATE` (bare-metal, virtualized, or cloud); sealed at boot; detection refutes an under-declaration |
| Supported controllers | Cisco ACI, VMware NSX, OpenFlow, Arista CloudVision, Juniper CN2, Calico, Cilium, custom REST |
| Controller access | Read-only, certificate-pinned; structurally incapable of writes |
| Admission | Source segment checked before authentication; loopback always admitted; CIDR or exact match |
| Posture states | Healthy, uncertain, degraded |
| Fail-safe | Degraded — entire `/api/` denied (health included); empty allow-list; fail-secure on read fault; automatic recovery |
| Segmentation policy | Default-deny, least-privilege, per-platform; advisory (operator-applied) |
| Privacy invariant | Tier-1 (management/aggregate) can never reach Tier-3 (analyst-private), by construction |
| Credentials | Write-only; stored under the Tier-1 key; never returned |
| Platform field | Immutable after creation |
| High availability | Out of scope (separate capability) |
