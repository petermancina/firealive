# Data Residency

Data residency controls let you declare where FireAlive's data is allowed to
live, record which government's laws can reach it, and document a legal basis for
every cross-border transfer. The policy is an **allow-list**: you name the
regions each data category may occupy, and anything you have not permitted is
refused. Enforcement runs entirely in FireAlive's own auditable code on the
Regional Server, and the residency subsystem carries none of the burnout,
wellbeing, or Tier-3 identity signals that live elsewhere in the platform — its
audit trail records only the operator who made a change and the jurisdiction
involved.

This is a governance and defence-in-depth control, not a guarantee of legal
compliance. Read **Residency is not sovereignty** and **Shared responsibility**
before you rely on it.

---

## Residency is not sovereignty

Two different questions hide behind the word "location":

- **Residency** — the physical region the bytes sit in (an EU region, a US
  region, on-premises hardware).
- **Sovereignty** — which government's legal process can compel a party to
  produce or alter those bytes.

They are not the same, and conflating them is the most common mistake in
residency planning. Under the US CLOUD Act (2018), US authorities can compel a
US-headquartered provider to produce data it holds **regardless of where that
data is physically stored**. AWS, Microsoft (Azure), and Google are all
US-domiciled. So a backup written to an EU region of one of those providers is
*resident* in the EU but its provider remains subject to US legal process — the
data is not beyond US reach simply because the region label says Frankfurt or
Dublin.

FireAlive makes this explicit rather than hiding it behind a region name. Every
cross-border transfer in the register carries the destination's **provider
domicile** and a plain-language **foreign-law exposure** note (for a US-domiciled
provider, that the US CLOUD Act applies). A destination can be perfectly
compliant on residency and still carry foreign-law exposure; you should see both
and decide accordingly. Genuine sovereignty over the most sensitive data
generally requires either on-premises storage or a provider that is not subject
to the foreign legal regime you are concerned about, combined with
customer-held encryption keys.

---

## What it does and does not enforce

At this release the policy is **enforced for backup destinations** and
**recorded for everything else**.

- **Backup destinations** are gated at config time: creating or enabling a
  destination whose jurisdiction falls outside the permitted regions of an
  enforce-mode category is refused, and the attempt is audited. The cross-border
  transfer register is reconciled on every destination change.
- **The other categories** (audit log, forensic export, snapshot, CEF archive)
  are destination-agnostic today — you declare their permitted regions now, and
  the register records them, but the routing that would carry them to specific
  destinations does not yet exist. It arrives with **Storage Routing** (see
  *What's next*), which will enforce this same policy for those routed types at
  write time. Declaring them now means the policy is ready before the routing
  ships.
- **The live deployment is never blocked.** Its category is `declare-only`: you
  record where the deployment runs, but the platform will not refuse its own
  operation on residency grounds. Blocking the live deployment would be a
  self-inflicted outage, not a control.

---

## The policy model

The policy has three parts.

**Primary residency.** The country your deployment is operated from, declared as
an ISO 3166-1 alpha-2 code (for example `DE`), plus the provider domicile of your
infrastructure (for example `US` for an AWS/Azure/GCP deployment). The primary
residency is the *source* jurisdiction against which cross-border transfers are
measured. In Cloud Mode the detected region is offered as a suggestion (see
**Cloud self-region detection**).

**Per-category permitted regions.** For each data category you set an allow-list
of permitted regions and a mode. A permitted-region token is either an ISO
country code (`DE`, `US`, `GB`) or a bloc shorthand — `EU` (the 27 member
states), `EEA`, `UK`, or `US`. A destination is permitted if its country matches
a listed code or belongs to a listed bloc.

> **An empty permitted list denies everything.** This is deliberate
> default-deny. An allow-list only admits what you have vetted; a blocklist
> silently admits everything you forgot to list. If you enable enforcement for a
> category and leave its permitted list empty, every destination in that category
> is treated as non-compliant until you add the regions you intend to allow.

**Mode**, per category:

- `enforce` — a non-permitted destination is blocked (at config time today;
  at write time once routing exists) and the event is audited.
- `warn` — a non-permitted destination is allowed but flagged in the register
  and audit trail.
- `declare-only` — jurisdiction is recorded but never blocks. This is the only
  mode available to the live-deployment category.

---

## Declaring destination jurisdictions

FireAlive infers a destination's jurisdiction where it safely can:

- An **S3** destination with a standard AWS region maps to that region's country
  with a US provider domicile.
- An **S3-compatible** destination with a custom endpoint is treated as
  unknown-domicile — a third-party S3 API is not AWS, and FireAlive will not
  assume US domicile or any country for it. You declare it.
- **GCS, Azure Blob, SFTP, and local** destinations do not expose a region in
  their connection config, so their jurisdiction is operator-declared.

For any destination you can override or supply the declaration: the **country**,
the **provider domicile**, and the **key custody** arrangement (for example,
customer-managed KMS). Declaring provider domicile is what drives the foreign-law
exposure note, so declare it honestly even when the storage region is in your own
country.

---

## The cross-border transfer register

Whenever an enabled backup destination resolves to a country different from your
primary residency, FireAlive records a row in the cross-border transfer register.
Each row carries the data category, the source and destination jurisdictions, the
provider domicile, the foreign-law exposure, the key custody, and the operator's
**legal transfer mechanism**:

- `adequacy` — an adequacy decision covers the destination country.
- `scc` — Standard Contractual Clauses are in place.
- `bcr` — Binding Corporate Rules apply.
- `derogation` — a specific derogation (for example GDPR Art. 49) is relied on.
- `none` — no mechanism; the transfer is undocumented by choice.
- `unset` — not yet reviewed (the default).

A transfer is **documented** once a real mechanism (`adequacy`, `scc`, `bcr`, or
`derogation`) is recorded, **undocumented** otherwise, and **blocked** when an
enforce-mode category refuses the underlying destination. The register summary
("N transfers, M documented, K blocked") is wired into the cross-border-transfer
compliance check that backs FireAlive's GDPR, APPI, POPIA, and PDPA framework
claims.

Recording a mechanism is your assertion that the legal instrument exists — it
does not create one. See **Shared responsibility**.

---

## Cloud self-region detection

In Cloud Mode, FireAlive reads the deployment's region from the instance metadata
service at boot and on demand (the **Re-check drift** action). If the detected
region's country does not match your declared primary residency, a **HIGH**
`RESIDENCY_REGION_MISMATCH` alert is raised and audited. This catches a
deployment that has drifted — relocated, failed over, or been redeployed — into a
region that no longer matches what you declared. Off-cloud deployments and
deployments with no declared primary residency produce no mismatch.

---

## Shared responsibility

FireAlive structures the policy, enforces it for backup destinations, and keeps
the register honest. It cannot create legal cover for you. The division is:

**FireAlive's responsibility**
- Refuse backup destinations that violate an enforce-mode policy, and audit it.
- Surface provider domicile and foreign-law exposure for every cross-border
  transfer, so sovereignty risk is visible and not hidden by a region label.
- Detect and alert on a deployment region that drifts away from the declared
  residency.
- Default-deny: never silently admit a region you did not permit.

**Your responsibility**
- Execute and maintain the actual legal instruments (sign the SCCs, confirm the
  adequacy decision still stands, keep BCRs current) — recording a mechanism in
  FireAlive asserts it exists; it does not.
- Choose destinations whose residency *and* sovereignty match your obligations,
  not just the region label.
- Arrange key custody. Customer-held keys are often the only practical
  mitigation for foreign-law exposure on a foreign-domiciled provider.
- Reassess on the cadence below.

---

## Reassessment cadence

Legal bases are not permanent. Adequacy decisions are revised and struck down
(the EU–US Privacy Shield was invalidated by *Schrems II* in 2020), SCCs are
superseded, and corporate structures change provider domicile. Treat residency as
a standing control, not a one-time setup:

- Set a **next review** date on each documented transfer and revisit it before
  the date passes.
- Run **Re-check drift** after any infrastructure change — a region migration, a
  failover, a new backup destination, or a provider change.
- Re-confirm provider domicile when a vendor is acquired or restructures.

---

## Audit events

All residency events are pseudonymous: they record the operator who acted and the
jurisdiction involved, never an analyst's identity. The event set is closed:

- `RESIDENCY_CONFIG_UPDATED` — the policy was changed.
- `RESIDENCY_DESTINATION_SET` — a destination's jurisdiction was declared.
- `RESIDENCY_DESTINATION_BLOCKED` — a destination was refused at config time.
- `RESIDENCY_DESTINATION_WARNED` — a non-permitted destination was allowed under
  warn mode.
- `RESIDENCY_TRANSFER_BLOCKED` — a register transfer is blocked by policy.
- `RESIDENCY_TRANSFER_WARNED` — a register transfer is flagged under warn mode.
- `RESIDENCY_TRANSFER_MECHANISM_SET` — a legal mechanism was recorded for a
  transfer.
- `RESIDENCY_REGION_MISMATCH` — the detected deployment region does not match the
  declared primary residency (HIGH).

---

## What's next (Storage Routing)

Storage Routing extends residency enforcement from backup destinations to the
four routed storage types — backup, audit log, forensic export, and
snapshot/CEF archive. When it ships, the permitted-region policy you declare for
those categories now will be enforced at the point data is written to a routed
destination, not only when a backup destination is configured. Declaring the
policy ahead of the routing means the control is in place before the data starts
moving.
