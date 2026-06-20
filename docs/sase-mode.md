# SASE Mode

Operator runbook for running a FireAlive Regional Server behind a SASE/ZTNA
edge — published to analysts only through a sanctioned connector, never
directly reachable — and having FireAlive verify, continuously, that it is
reached the way it is supposed to be. SASE Mode is a deployment mode
alongside bare metal, virtualized, cloud, and SDN. It exists so a SOC that
fronts its tooling with a Zero-Trust edge can have FireAlive confirm two
things, and refuse to serve traffic when either is lost: that it is reachable
only through the connector, and that the edge has not been allowed to break
FireAlive’s own end-to-end authentication.

This document describes shipped behavior. It is written for SOC
administrators and team leads operating the Regional Server and Management
Console (MC).

A note up front, because it is the most common misconception: **SASE Mode
does not turn FireAlive into a web app or a cloud service.** The server is
still a direct host process on bare-metal hardware with a TPM, or a VM with a
vTPM, exactly as in the other modes. It is never a Kubernetes pod or a managed
container, and it does not hand its sessions to the vendor’s edge. SASE Mode
adds a network-overlay posture: FireAlive is published behind a ZTNA
connector, admits only connections that arrive through that connector,
requires the edge to tunnel its traffic rather than terminate it, and fails
safe if either guarantee is lost. The connector is the vendor’s box; it is
never inside FireAlive’s trust boundary.

## Why SASE Mode exists

Publishing a SOC’s internal tooling directly — even behind a VPN — leaves an
attack surface an adversary can find and hammer. A SASE/ZTNA edge improves on
that: the application is dark to the public internet and is reached only
through a connector, after the edge has checked the user’s identity and device
posture. That is a real gain, but it comes with two failure modes that quietly
give back everything it bought:

- The application can be **exposed directly** as well as through the connector
  — a second listener, a misconfigured firewall rule, a forgotten public IP —
  so the edge becomes optional rather than mandatory.
- The edge can be run in a **TLS-terminating, clientless** mode, where it
  decrypts the connection at the edge and forwards a header asserting who the
  user is. That breaks FireAlive’s end-to-end mutual TLS: the strong,
  device-bound client certificate an analyst presents is terminated at the
  vendor’s edge and replaced with the edge’s word for it.

SASE Mode makes FireAlive refuse both. It does three things a plain deployment
cannot:

- It **admits connections only from the sanctioned connector**, by the raw
  network peer, so a directly exposed listener is refused before
  authentication.
- It **requires connector-tunneled passthrough** and refuses a clientless,
  TLS-terminating edge, so the analyst’s mutual TLS reaches FireAlive intact.
- It **latches a lockdown** the instant either boundary is violated, denying
  its own API surface until an operator closes the hole out-of-band.

Crucially, FireAlive never integrates with the SASE provider’s management
plane. It does not read or program the edge. It verifies, at its own front
door, that it is being reached correctly — and refuses service when it is not.

## Supported SASE / ZTNA edges

SASE Mode is designed to sit behind the following edges, each configured in
**connector-tunneled (TCP passthrough)** mode:

- **Zscaler** — Zscaler Private Access (ZPA) with an App Connector.
- **Netskope** — Netskope Private Access with a Publisher.
- **Palo Alto Prisma Access** — Prisma Access with a Service Connection /
  connector.
- **Cato Networks** — the Cato SASE Cloud with a Socket / connector.
- **Cloudflare** — Cloudflare Access / Tunnel (cloudflared) in TCP mode.
- **Fortinet** — FortiSASE with a private-access connector.

The provider is recorded as deployment metadata; it documents the surrounding
edge for operators and audit. It does **not** cause FireAlive to call the
provider’s API. FireAlive’s enforcement does not depend on which provider is
named — it depends on the connection actually arriving through the connector
and on the edge not terminating TLS. An edge not on this list can be used if
it supports a true TCP-passthrough connector; the named set is the set
FireAlive has been validated against.

## What SASE Mode enforces

### Hardware root of trust: unchanged

SASE Mode reuses FireAlive’s instance-anchor design without modification. The
anchor’s private key is sealed to the host’s hardware root of trust — a TPM
2.0 on bare metal, or a vTPM in a virtualized guest — and underpins the
deployment CA, server certificates, analyst-client registrations, and
enrollment tokens, exactly as in every non-cloud mode. No new backend is
introduced, and there is no software-key fallback. A deployment with no
hardware root of trust refuses to start.

This is also why the edge is never allowed to terminate FireAlive’s TLS: the
analyst’s mutual-TLS handshake is anchored to this same root of trust, and an
edge that decrypts and re-originates the connection would sever that anchor.
(See *Connector-tunneled passthrough is required*.)

### Host substrate

Like SDN Mode, SASE Mode composes with a *host substrate*. The bare-metal,
virtualized, and cloud modes are themselves the substrate — they describe the
machine FireAlive runs on. A SASE deployment is a network overlay that can run
on any of the three, so it records its host substrate separately and layers
the matching host defenses on top of its connector networking and admission.

- **SASE on bare metal** — a hardware TPM 2.0 on dedicated hardware. The host
  is not easily copied, so beyond the anchor and SASE admission there is
  nothing further to enforce; this is a pass-through.
- **SASE on a virtualized host** — a vTPM in a VM or hypervisor. A VM is
  trivially snapshotted, paused, and cloned, so the host-presence and
  clock-integrity defenses apply: session-less enrollment and signed device
  actions are refused when the clock cannot be trusted, and an instance that
  looks cloned or rolled back is quarantined before authentication.
- **SASE on cloud** — a confidential VM on AWS, Azure, or GCP with a vTPM root
  of trust. Everything the virtualized substrate enforces applies, plus
  confidential-computing attestation at boot and refusal of spot and
  autoscaled instances, exactly as in cloud mode.

The substrate is **declared by the operator** and is **required**: set
`FIREALIVE_SASE_SUBSTRATE` to `bare-metal`, `virtualized`, or `cloud` before
the first start. If it is absent or invalid the server refuses to boot — there
is no default, because silently under-classifying a copyable host would skip
the very defenses that host needs. As in every mode, detection is used only to
*refute* an unsafe declaration, never to relax one: at boot the server
independently detects the substrate, and if what it detects is stronger
evidence of a copyable host than what was declared, it refuses to start
(anti-downgrade). Over-claiming is allowed and self-corrects. The substrate is
sealed into the anchor-signed deployment record at first boot, alongside the
mode, so neither can be flipped later.

### Connector-tunneled passthrough is required

This is the defining constraint of SASE Mode, and the one most likely to be
set wrong at the edge.

FireAlive requires the ZTNA edge to be configured so that the connector
**relays the raw TCP stream** to FireAlive and FireAlive terminates the
analyst’s mutual TLS itself, end to end, inside the tunnel. In this
arrangement the connector provides exactly two things and no more: dark-app
reachability (FireAlive is not on the public internet; it is published only
through the connector) and the edge’s own device-posture and identity checks
in front of the tunnel. The connector never sees inside FireAlive’s TLS, never
holds FireAlive’s keys, and is never part of FireAlive’s trust boundary.

FireAlive **fails closed** on the opposite arrangement — a **clientless**,
TLS-terminating edge. In clientless mode the edge decrypts the connection and
forwards an HTTP header asserting the authenticated user (for example
`cf-access-authenticated-user-email`, `x-forwarded-user`, or an
`x-auth-request-*` header). FireAlive treats the presence of such a header as a
boundary violation and refuses the connection, because honoring it would mean
trusting the edge’s assertion of identity in place of the analyst’s
device-bound client certificate. There is no configuration switch to accept
it. A weaker authentication path is not offered: there is no weak FireAlive.

Two clarifications operators ask for:

- The ordinary `X-Forwarded-For` header is **not** treated as a
  clientless-identity signal. It is a normal proxy artifact and says nothing
  about who the user is; only the identity-assertion headers above trigger the
  refusal.
- Passthrough does not weaken the edge’s value. The edge still gates
  reachability and still applies its device-posture and identity policy before
  a packet reaches the connector. SASE Mode simply insists that the analyst’s
  cryptographic identity survive the trip.

### Connector-source admission

The operator declares, in the connector-source allow-list, the network
addresses of the sanctioned ZTNA connectors. When SASE Mode is active, an
admission check runs **before authentication** on every inbound connection,
and it makes its decision on the **raw TCP socket peer** — the actual address
the packet arrived from — not on any forwarded or proxy header that could be
spoofed.

- If the socket peer is **not** within the connector-source allow-list, the
  connection is refused and a `direct_exposure_refused` event is recorded. This
  is the signal that FireAlive has been reached around the edge — exposed
  directly — and the boundary has been bypassed.
- If the connection carries a **clientless identity header**, it is refused and
  a `passthrough_violation_refused` event is recorded, as described above.

Both refusals return a 403 and record an event, and either event latches the
deployment into degraded posture. The allow-list is matched by CIDR or exact
address and cached with a short refresh, so updates take effect without a
restart. Loopback and local traffic are **always** admitted, so the host stays
manageable. Admission is enforced only in SASE Mode; in other modes the check
passes through. While no connector sources have been declared yet, admission
passes through rather than locking out a half-configured deployment — the
lockdown is driven by an observed violation, not by an empty config.

### Latching posture

SASE Mode’s posture is **event-driven**, and it differs from SDN Mode in one
deliberate way: it has no *uncertain* debounce band, and it does not recover
on its own.

The reasoning is that the events SASE watches are not flaky probe results —
they are observed boundary violations. A `direct_exposure_refused` means a
real connection actually reached FireAlive from outside the connector. A
`passthrough_violation_refused` means a real connection actually arrived with
a TLS-terminating edge’s identity header. A single such observation is enough
to conclude the boundary is not what the operator believes it is.

So posture **latches**: the deployment is degraded while any boundary-failure
event — `direct_exposure_refused`, `passthrough_violation_refused`, or an
explicit `posture_degraded` — exists in the append-only event log after the
most recent `posture_restored`. One breach is enough to latch; no quantity of
subsequent clean traffic clears it. The latch is cleared **only** by an
explicit, out-of-band `posture_restored` event, recorded by the operator after
they have actually closed the hole — removed the direct listener, or corrected
the edge to passthrough. There is no in-band path and no automatic timeout.
The latch is itself the anti-flap mechanism: rather than debounce an uncertain
signal, SASE Mode treats one confirmed breach as durable until a human asserts
otherwise.

### Assume-breach fail-safe lockdown

The latched posture is not advisory to the running server — it gates it. While
the deployment posture is **degraded**, a fail-safe denies the **entire**
`/api/` surface. The allow-list of endpoints that remain reachable while
degraded is **empty**: health and status endpoints are denied along with
everything else, on purpose, so the lockdown leaks no information about system
state and offers no in-band path to lift it. If the posture state itself
cannot be read, the gate treats that as degraded and denies — it fails secure,
not open.

Because the posture is latched and recovery is out-of-band, there is no
debounce state to pass through and no override endpoint. The operator’s job
during a lockdown is to close the boundary hole and record the restore, not to
talk FireAlive out of the lockdown.

### Read-only posture probe

SASE Mode contributes a `sase` integration-health probe, but it works
differently from the controller probes in SDN Mode, and the difference is
important: **it never dials the provider.** SASE has no controller integration
and makes no outbound call to the edge. The probe is a pure, local state read
— it reports whether SASE Mode is active, whether connector sources have been
declared, and whether posture is currently degraded. A degraded posture
surfaces as unreachable; otherwise the probe reports healthy. The boundary is
enforced at the front door, by admission, not by polling a vendor API.

### Structural privacy: unchanged

SASE Mode changes nothing about FireAlive’s central privacy guarantee.
Management and aggregate data (Tier-1) remain structurally unable to reach
analyst-private data (Tier-3); the separation is enforced in the data model,
independent of deployment mode. A network overlay in front of the server
neither strengthens nor weakens it.

## Configuring SASE

SASE configuration lives behind the MC’s SASE surface and is reachable only by
an administrator, and only when the configuration lock is open. The surface
covers:

- **Connector sources** — the addresses (CIDR or exact) of the sanctioned ZTNA
  connectors. This is the security-critical setting: it drives
  connector-source admission.
- **Provider** — which SASE/ZTNA edge fronts the deployment (Zscaler,
  Netskope, Palo Alto Prisma Access, Cato, Cloudflare, or Fortinet). Metadata
  for operators and audit; it does not cause FireAlive to call the provider.
- **Edge descriptors** — an optional record of the edge endpoint and which
  adjacent services (CASB, SWG, SECaaS, FWaaS) the SOC runs at that edge.
  Documentation of the surrounding deployment; FireAlive does not drive these
  services.
- **Enabled** — a toggle recording whether the SASE overlay is in service.

One property matters above the rest: the **connector-source allow-list is an
allow-list**, not a derived or inferred set. FireAlive admits the connectors
the operator names and nothing else; it does not try to discover the edge’s
egress addresses for them. The connector-source values are validated when
saved, and a malformed entry is rejected rather than silently dropped — an
allow-list that quietly ignores a bad line is worse than one that refuses it.
Every configuration action is audited by operator and action.

## The connector-source allow-list

The connector-source allow-list is the single security-relevant input to SASE
admission. It is the set of network addresses from which FireAlive will accept
a connection at all:

- A connection whose **raw socket peer** falls inside the list is admitted to
  the authentication stage, where the analyst’s mutual TLS and the rest of
  FireAlive’s identity checks still apply in full.
- A connection from **anywhere else** is refused before authentication and
  latches the lockdown.

Because the match is on the raw socket peer, the values should be the
addresses the **connector** presents to FireAlive — the connector’s own source
addresses on the segment FireAlive listens on — not the edge’s public
addresses or the analysts’ addresses. In a correct deployment that is a small,
stable set: the connector PoPs that are allowed to bring traffic to this
server.

## Deploying

SASE Mode is provisioned like any other non-cloud deployment, with the edge
configured to publish FireAlive through a passthrough connector and the
connector-source allow-list declared after first boot.

1. **Provision a host with a hardware root of trust.** Bare-metal hardware
   with a TPM 2.0, or a VM with a vTPM. This is an ordinary FireAlive host —
   not a container, not a Kubernetes workload.
2. **Install FireAlive.** Run the installer on the host as you would for any
   deployment.
3. **Select SASE mode and host substrate at first boot.** Set the deployment
   mode to `sase` before the first start (the deployment-mode environment
   variable), and set `FIREALIVE_SASE_SUBSTRATE` to `bare-metal`,
   `virtualized`, or `cloud` for the host this instance runs on; it is
   required, and the server refuses to boot without it. On first boot the
   server seals both SASE mode and the substrate to the hardware root, so
   neither can be flipped later.
4. **Confirm the anchor pin.** Each Analyst Client and the Global Dashboard
   show the deployment anchor fingerprint on first connection. Confirm the pin
   only if it matches the fingerprint the server printed at boot.
5. **Publish FireAlive through a passthrough connector.** On the SASE/ZTNA
   edge, create a private-access application for FireAlive served by a
   connector in **TCP / passthrough** mode — not a clientless, TLS-terminating
   application. The edge applies its identity and device-posture policy in
   front of the tunnel; FireAlive terminates the analyst’s mutual TLS at the
   end of it. Do not publish FireAlive on any public listener in parallel.
6. **Declare the connector-source allow-list.** In the MC’s SASE surface,
   record the addresses the connector presents to FireAlive, and the provider
   and edge metadata for your deployment.
7. **Verify the boundary.** Confirm an analyst can reach FireAlive through the
   connector, and confirm that a direct connection from outside the connector
   segment is refused. A `direct_exposure_refused` or
   `passthrough_violation_refused` event indicates the boundary is not yet
   correct; correct it and record a `posture_restored` once it is.

Once SASE Mode is active and connector sources are declared, admission and the
fail-safe are live, and the posture reflects any observed boundary violation.

## What SASE Mode does not include

- **Clientless, TLS-terminating ZTNA.** FireAlive refuses an edge that
  terminates its TLS and forwards an identity header. Connector-tunneled
  passthrough is mandatory so the analyst’s mutual TLS reaches FireAlive
  intact. This is by design and is not configurable.
- **Calls to the provider’s management plane.** SASE Mode has no controller
  integration. FireAlive does not read, program, or poll the SASE provider’s
  API; the provider and edge descriptors are metadata only. Enforcement happens
  at FireAlive’s own front door.
- **Secure-web-gateway egress.** SASE Mode is an inbound-reachability overlay.
  FireAlive does not route its own outbound traffic through the SOC’s SWG or
  apply egress policy; the adjacent CASB/SWG/SECaaS/FWaaS services are the
  SOC’s, not FireAlive’s to operate.
- **Running as a container or Kubernetes workload.** The FireAlive server is a
  direct host process on a TPM/vTPM host. A connector in front of it does not
  change that. Orchestrated containers do not present the per-instance TPM the
  instance anchor requires.
- **More than one deployment mode at once.** SASE is one of the mutually
  exclusive modes (bare metal, virtualized, cloud, SDN, SASE), sealed at first
  boot.
- **Global Dashboard SASE.** This mode applies to the Regional Server. Fronting
  the Global Dashboard with its own SASE edge is a separate capability and is
  out of scope here.
- **High availability.** SASE Mode runs a single anchored instance.
  Active/passive or active/active failover is a separate capability and is out
  of scope here.

## Quick reference

| Property | SASE Mode |
| --- | --- |
| Server runtime | Direct host process on a TPM 2.0 / vTPM host — never a container or Kubernetes workload |
| Hardware root of trust | Host TPM / vTPM, reusing the deployment anchor; no software fallback |
| Host substrate | Declared and required via `FIREALIVE_SASE_SUBSTRATE` (bare-metal, virtualized, or cloud); sealed at boot; detection refutes an under-declaration |
| Edge requirement | Connector-tunneled (TCP passthrough); clientless / TLS-terminating edges refused |
| Validated edges | Zscaler, Netskope, Palo Alto Prisma Access, Cato, Cloudflare, Fortinet (metadata; no API integration) |
| Admission | Raw socket peer checked against the connector-source allow-list before authentication; loopback always admitted; CIDR or exact match |
| Passthrough check | Clientless identity headers refused; `X-Forwarded-For` not treated as identity |
| Posture states | Healthy or degraded — latched, no uncertain band |
| Posture model | Event-driven; one observed boundary violation latches degraded; cleared only by an explicit out-of-band restore |
| Fail-safe | Degraded — entire `/api/` denied (health included); empty allow-list; fail-secure on read fault; no automatic recovery |
| Provider API | None — FireAlive never calls the SASE provider; enforcement is at its own front door |
| Egress / SWG | Out of scope — inbound-reachability overlay only |
| Privacy invariant | Tier-1 (management/aggregate) can never reach Tier-3 (analyst-private), unchanged by the overlay |
| Global Dashboard SASE | Out of scope (separate capability) |
| High availability | Out of scope (separate capability) |
