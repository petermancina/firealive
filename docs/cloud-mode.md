# Cloud Mode (Confidential VM)

Operator runbook for running a FireAlive Regional Server in a public cloud on
a confidential virtual machine. Cloud Mode is the third deployment mode,
alongside bare metal and virtualized. It exists so a SOC can run FireAlive on
AWS, Azure, or GCP without trusting the cloud provider — or a co-tenant — with
the contents of the server's memory.

This document describes shipped behavior. It is written for SOC
administrators and team leads operating the Regional Server and Management
Console (MC).

## Why Cloud Mode exists

Bare-metal and virtualized deployments assume the operator controls the
physical host. In a public cloud that assumption does not hold: the hypervisor
belongs to the cloud provider, the physical host is shared with other
tenants, and a snapshot of the running VM's memory could in principle expose
the Tier-1 key, decrypted analyst data, and session secrets.

Cloud Mode closes that gap with **confidential computing**. A confidential VM
encrypts the guest's memory with a key held in the CPU, not by the hypervisor.
The cloud provider can schedule, start, and stop the VM, but cannot read its
memory, and neither can a co-tenant who lands on the same physical host. A
virtual TPM (vTPM) presented to the guest provides the hardware root of trust
FireAlive already depends on for its instance anchor.

Confidential computing is **required** in Cloud Mode, not optional, and it is
**remotely attested at boot**. The server does not take the platform's word
for it: it fetches a CPU-signed attestation report, verifies the signature up
to a hardware-vendor root, and checks that the report is fresh and that the
platform firmware is at or above a pinned floor. If any step fails, the server
refuses to start. There is no downgrade.

## Supported platforms

Cloud Mode supports the clouds that offer a shared-tenancy confidential VM with
a vTPM and a verifiable hardware attestation report:

- **AWS** — an AMD SEV-SNP instance with NitroTPM. NitroTPM presents to the
  guest as a TPM 2.0 device; the SEV-SNP report, signed by an AMD VCEK, is the
  attestation evidence.
- **Azure** — a Confidential VM with Trusted Launch, on **AMD SEV-SNP** or
  **Intel TDX**. Trusted Launch provides the vTPM and secure boot plus
  guest-state disk encryption; the SEV-SNP report or the TDX quote is the
  attestation evidence.
- **GCP** — a Confidential VM with Shielded VM, on **AMD SEV-SNP** or **Intel
  TDX**. Shielded VM provides the vTPM, secure boot, and integrity monitoring.

Both confidential-computing technologies are verified natively: AMD SEV-SNP
through the AMD VCEK-to-ASK-to-ARK certificate chain, and Intel TDX through the
DCAP quote with its PCK certificate chain to the Intel SGX Root CA. No
third-party attestation service is contacted; verification is performed in the
server using the operating system's cryptography and the bundled vendor roots.

Privacy-focused European and Swiss providers (for example Hetzner, OVHcloud,
and Exoscale) are **not** Cloud Mode targets. Strong data residency and
jurisdiction guarantees are valuable, but they are a different property from a
confidential VM: at the time of writing none of those providers offers a
shared-cloud confidential VM with VM-level memory encryption. An operator who
wants one of those providers for sovereignty reasons runs FireAlive on their
dedicated or bare-metal hardware in **bare-metal mode** instead.

## What Cloud Mode enforces

### Remote attestation, verified and fail-closed

At boot, after the instance anchor is established and the deployment mode is
resolved, a cloud deployment performs full remote attestation before it serves
any traffic. The flow is the same shape for both technologies:

1. **Generate a fresh nonce.** The server draws a random 64-byte nonce for
   this boot. The nonce binds the report to this attestation and defeats replay
   of a captured report.
2. **Fetch a CPU-signed report.** Using the Linux `configfs-tsm` interface
   (`/sys/kernel/config/tsm/report`), the server writes the nonce and reads
   back the report the CPU produces over it, together with the certificate
   material the platform supplies. For SEV-SNP the AMD VCEK is recovered from
   the returned certificate table; for TDX the PCK chain rides inside the
   quote.
3. **Verify the signature to a vendor root.** For **SEV-SNP**, the report
   signature is checked with the VCEK (ECDSA P-384), and the VCEK-to-ASK-to-ARK
   certificate chain is verified against the bundled AMD root. For **TDX**, the TD-report
   signature is checked with the in-quote attestation key, that key is bound to
   the Quoting Enclave report, the QE report is checked with the PCK leaf, and
   the PCK leaf-to-intermediate chain is verified against the bundled
   Intel SGX Root CA.
4. **Check freshness.** The report's report-data field must equal the nonce
   from step 1. A report for a different nonce — including a stale one — is
   rejected.
5. **Enforce the firmware floor and the launch measurement.** The reported
   Trusted Computing Base must be at or above the pinned floor, and the launch
   measurement must match the pinned value (see the next two sections).

Detection of which technology is present comes from the same `configfs-tsm`
provider and the guest attestation device the kernel creates only inside a
genuine confidential guest — `/dev/sev-guest` for SEV-SNP or `/dev/tdx_guest`
for TDX. **Device presence alone is not sufficient.** Earlier builds treated
the kernel device as the gate while full attestation was pending; that is no
longer the case. If a signed report cannot be fetched and verified to a vendor
root, the server marks the platform as validation-pending and **does not**
treat it as attested.

AWS Nitro Enclaves (`/dev/nitro_enclaves`) are **not** an attestation source
for Cloud Mode. A Nitro Enclave attestation describes a carved-out enclave
*within* the instance, not the whole VM that runs the Regional Server, so its
presence does not verify the server's own memory-encrypted environment. The
AWS path attests through the instance's SEV-SNP report.

### Trusted Computing Base floor (anti-rollback)

A confidential VM's attestation report carries the version of the platform
firmware — the Trusted Computing Base, or TCB — that produced it. A rolled-back
or downgraded firmware can reintroduce fixed vulnerabilities while still
producing a validly signed report, so a signature check alone is not enough.

At provisioning, FireAlive records the platform's current TCB as a **floor**.
On every subsequent boot the reported TCB must be **at or above** that floor;
a report from older firmware is refused. The floor is **monotonic** — it only
ever moves upward. When the platform firmware is legitimately updated, the
operator (or the boot path, once confirmed) raises the floor to the new level;
it can never be lowered, so an attacker cannot quietly downgrade the platform
under a sealed deployment. For SEV-SNP the floor is compared component by
component (bootloader, TEE, SNP, microcode); for TDX it is compared across the
TCB security-version bytes.

### Launch measurement pinning (TOFU)

The attestation report also carries a **launch measurement**: a hash over the
initial state the CPU measured when the confidential guest started (the
SEV-SNP measurement, or the TDX MRTD). Two boots of the same image on the same
platform produce the same measurement; a tampered or substituted image does
not.

FireAlive pins the launch measurement on a **trust-on-first-use** basis. The
measurement seen at provisioning is recorded, and every later boot must
present the **same** measurement. A mismatch halts the boot: it means the guest
that started is not the one the deployment was sealed against. The pin is
recorded once and is never silently overwritten.

### Guest CPU side-channel mitigations

Memory encryption protects the guest from the hypervisor, but a guest kernel
still has to be configured to mitigate CPU side-channel vulnerabilities
(Spectre v2, MDS, L1TF, Retbleed, and related transient-execution issues). A
confidential VM that has left one of these families unmitigated weakens the
protection the platform is supposed to provide.

At boot, FireAlive reads the kernel's own mitigation reporting under
`/sys/devices/system/cpu/vulnerabilities/` for the in-scope families. If any
in-scope family reports **Vulnerable**, the server **fails closed** and exits.
A family the kernel does not report (unknown) is tolerated by default and noted
for audit; an operator running in a strict posture can require every in-scope
family to be explicitly mitigated. Where an operator has an out-of-band reason
to accept a specific family, an **audited override** records that decision
rather than hiding it.

### Dedicated tenancy (optional)

By default Cloud Mode trusts memory encryption to isolate the guest from
co-tenants, so shared hardware is acceptable. An operator with a stricter
requirement can additionally require **single-tenant** hardware. When that
requirement is set, the boot path reads instance metadata and refuses to
continue unless the instance is on dedicated hardware: AWS `dedicated` or
`host` tenancy, an Azure dedicated host group, or a GCP sole-tenant node.
Shared or unknown tenancy is refused. The requirement is off unless the
operator turns it on at provisioning.

### Periodic re-attestation

Attestation is not only a boot-time check. While the server runs, it
re-verifies the platform on a periodic schedule: it re-fetches and re-verifies
the report, re-confirms the launch measurement, and re-checks the guest
mitigations. A periodic re-attestation that regresses is recorded as a loss of
attested status for operators to act on, rather than abruptly terminating a
live server on a transient read; the authoritative fail-closed decision is made
at boot and at provisioning.

### Refusal of spot and autoscaled instances

Cloud Mode is designed for a long-lived, single, dedicated server. It actively
**refuses** to seal on a spot or preemptible instance, or on an instance that
is part of an autoscaling group or scale set. Those instances can be
terminated or multiplied by the cloud platform outside the operator's control,
which is incompatible with a single anchored identity. The boot gate reads the
instance metadata service and halts if it sees a spot or autoscaled instance.

### Hardware root of trust: the instance vTPM

Cloud Mode reuses FireAlive's existing instance-anchor design unchanged. The
anchor's private key is sealed to the platform hardware root of trust; in a
confidential VM that root is the vTPM, which presents as a TPM 2.0 device. No
new backend is introduced. The same anchor underpins the deployment CA, the
server keys and certificates, analyst-client registrations, and enrollment
tokens, exactly as on bare metal.

### Tier-1 key custody and recovery

The Tier-1 key-encryption key (KEK) stays sealed to the instance vTPM. It does
not move to the cloud KMS. Because a confidential VM can be stopped and its
underlying host replaced, the operator must keep the **recovery code** issued
at first boot: if the instance and its vTPM state are lost, the recovery code
re-establishes access. The cloud KMS is used only for the backup tier (below),
never for the Tier-1 KEK.

### Backup key posture

The v2 backup engine wraps each backup's data key with a configured KEK. In
Cloud Mode the backup KEK **must** come from the cloud KMS or a Vault transit
engine (`aws-kms`, `azure-keyvault`, `gcp-kms`, or `hashicorp-vault`). An
environment-variable backup KEK is **refused** when creating a new backup in
cloud mode, because an environment variable lives in the same process memory
that the confidential VM is meant to protect, and a snapshot or
misconfiguration could expose it. Restoring an existing backup is unaffected —
any scheme can be unwrapped — so backups created before the deployment moved to
cloud mode remain recoverable.

## Addressing and certificates

A cloud instance's IP address can change on a stop/start, and it usually sits
behind a load balancer or operator DNS name. FireAlive handles this with a
**stable DNS name** plus certificate-SAN reconciliation:

- The operator points a stable DNS record (for example `soc.example.com`) at
  the instance. This operator DNS name is the **primary** certificate subject
  alternative name (SAN).
- The instance's current IP, read from metadata, is a **secondary** SAN.
- At boot, the server reconciles the certificate SAN against the stable
  hostname and the current IP. If the address set changed, it re-issues the
  server certificate **under the stable anchor** and serves the new
  certificate. If nothing changed, the existing certificate is kept.

This is safe because Analyst Clients and the Global Dashboard **pin the
deployment anchor fingerprint, not the leaf certificate**. Re-issuing the leaf
on a cloud stop/start or a load-balancer address change does not break the
trust pin: clients still verify the same anchor. The anchor fingerprint an
operator confirms out of band on first contact does not change when the
address does.

## Deploying

The Management Console's Cloud tab walks through Cloud Mode and links to the
signed Infrastructure-as-Code generator. The flow is:

1. **Provision a confidential VM** on AWS, Azure, or GCP. Use an on-demand
   instance only — spot, autoscaled, and ephemeral-fleet instances are
   refused. If single-tenant hardware is required, provision dedicated tenancy
   (AWS dedicated/host, an Azure dedicated host group, or a GCP sole-tenant
   node).
2. **Generate and apply the IaC bundle.** The MC's signed IaC generator
   produces a bundle for the chosen platform and format whose templates emit a
   confidential VM with a vTPM and stamp `deployment_mode = cloud`.
3. **Point stable DNS at the instance.** Create an A/AAAA record (operator
   DNS). It becomes the primary certificate SAN; the instance IP is secondary.
4. **Set the backup KEK to the cloud KMS or Vault.** An environment-variable
   backup KEK is refused in cloud mode.
5. **Start FireAlive and seal cloud mode.** On first boot the server attests
   the confidential VM — fetching and verifying a CPU-signed report to a vendor
   root — refuses to continue if attestation fails, refuses spot and autoscaled
   instances, and seals the mode to the instance vTPM. At the seal it pins the
   platform's launch measurement and records the current TCB as the floor for
   later boots. Capture the recovery code and store it offline.
6. **Confirm the anchor pin.** Each Analyst Client and the Global Dashboard
   show the deployment anchor fingerprint on first connection. Confirm the pin
   only if it matches the fingerprint the server printed at boot.

The IaC templates fetch the Tier-1 key and JWT secret from the cloud secret
store using the instance's own identity (IAM role, managed identity, or
service account). Secrets are never placed in instance user data in cleartext,
because the confidential-VM threat model assumes the provider can read instance
metadata but not guest memory.

## Validation status

The attestation verifiers and the boot and provisioning gates are implemented
and are exercised end-to-end in CI against synthetic SEV-SNP reports and TDX
quotes signed by throwaway certificate chains, covering valid evidence, tamper,
wrong root, stale nonce, TCB-floor pass/fail, and measurement match/mismatch.

The CPU-vendor **root certificates** that anchor the chains on real silicon —
the AMD ARK (per product) and the Intel SGX Root CA — are added during hardware
validation on genuine SEV-SNP and TDX instances. Until those roots are in place
and confirmed against live hardware, the chain cannot complete on a real
confidential VM, so attestation reports as not-yet-verified
(validation-pending) and Cloud Mode stays **fail-closed**: the server declines
to seal or boot a cloud deployment rather than trust an unverified platform.
This is the intended staged posture for a pre-release platform, not a gap to be
worked around.

## What Cloud Mode does not include

- **High availability.** Cloud Mode runs a single anchored instance.
  Active/passive or active/active failover and per-mode HA tuning are a
  separate capability and are out of scope here.
- **Software-defined networking.** SDN integration is a separate deployment
  concern.
- **Container orchestration.** FireAlive does not run as a Kubernetes, Fargate,
  Cloud Run, or Container Instances workload. Those managed-container services
  do not provide a vTPM or VM-level memory encryption, which Cloud Mode
  requires. The single server image runs on the confidential VM itself.

## Quick reference

| Property | Cloud Mode |
| --- | --- |
| Hardware root of trust | Instance vTPM (TPM 2.0), reusing the deployment anchor |
| Confidential computing | Required; remotely attested at boot; fail-closed |
| Attestation evidence | AMD SEV-SNP report (VCEK to ARK) or Intel TDX quote (PCK to SGX Root CA), fetched via configfs-tsm, nonce-bound |
| Supported platforms | AWS (SEV-SNP + NitroTPM), Azure (SEV-SNP or TDX + Trusted Launch), GCP (SEV-SNP or TDX + Shielded VM) |
| Firmware floor | TCB recorded at provisioning; monotonic; older firmware refused |
| Launch measurement | Pinned on first use (TOFU); a changed measurement halts boot |
| Guest mitigations | `/sys` side-channel families checked; a Vulnerable family fails closed; audited overrides |
| Dedicated tenancy | Optional; when required, shared/unknown tenancy is refused |
| Re-attestation | Periodic re-verification of report, measurement, and mitigations |
| Instance types refused | Spot / preemptible, autoscaled / scale-set, ephemeral fleet |
| Tier-1 KEK | Sealed to the instance vTPM; recovery code for instance loss |
| Backup KEK | Cloud KMS or Vault required; environment-variable KEK refused |
| Addressing | Stable operator DNS (primary SAN) + instance IP (secondary SAN) |
| Certificate on address change | Re-issued under the stable anchor; clients pin the anchor, not the leaf |
| High availability | Out of scope (separate capability) |
