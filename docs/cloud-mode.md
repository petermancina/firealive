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
**attested at boot**. If the server cannot confirm it is running inside a
confidential guest, it refuses to start. There is no downgrade.

## Supported platforms

Cloud Mode supports the three clouds that offer a shared-tenancy confidential
VM with a vTPM:

- **AWS** — an AMD SEV-SNP instance with NitroTPM. NitroTPM presents to the
  guest as a TPM 2.0 device.
- **Azure** — a Confidential VM (AMD SEV-SNP) with Trusted Launch, which
  provides the vTPM and secure boot, plus VM guest-state disk encryption.
- **GCP** — a Confidential VM (AMD SEV-SNP) with Shielded VM, which provides
  the vTPM, secure boot, and integrity monitoring.

Privacy-focused European and Swiss providers (for example Hetzner, OVHcloud,
and Exoscale) are **not** Cloud Mode targets. Strong data residency and
jurisdiction guarantees are valuable, but they are a different property from a
confidential VM: at the time of writing none of those providers offers a
shared-cloud confidential VM with VM-level memory encryption. An operator who
wants one of those providers for sovereignty reasons runs FireAlive on their
dedicated or bare-metal hardware in **bare-metal mode** instead.

## What Cloud Mode enforces

### Confidential computing, attested and fail-closed

At boot, after the instance anchor is established and the deployment mode is
resolved, a cloud deployment verifies that a confidential-computing guest is
present. Detection looks for the guest attestation device the kernel creates
only inside a genuine confidential guest — `/dev/sev-guest` for SEV-SNP,
`/dev/tdx_guest` for TDX, or `/dev/nitro_enclaves` for Nitro. If none is
present, the server logs the reason and exits. Full remote attestation (report
fetch and CPU-vendor certificate-chain verification) is platform-validation
pending and lands as the hardware path matures; the kernel device signal is
the in-phase gate.

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
   refused.
2. **Generate and apply the IaC bundle.** The MC's signed IaC generator
   produces a bundle for the chosen platform and format whose templates emit a
   confidential VM with a vTPM and stamp `deployment_mode = cloud`.
3. **Point stable DNS at the instance.** Create an A/AAAA record (operator
   DNS). It becomes the primary certificate SAN; the instance IP is secondary.
4. **Set the backup KEK to the cloud KMS or Vault.** An environment-variable
   backup KEK is refused in cloud mode.
5. **Start FireAlive and seal cloud mode.** On first boot the server attests
   confidential computing, refuses to continue if it is absent, refuses spot
   and autoscaled instances, and seals the mode to the instance vTPM. Capture
   the recovery code and store it offline.
6. **Confirm the anchor pin.** Each Analyst Client and the Global Dashboard
   show the deployment anchor fingerprint on first connection. Confirm the pin
   only if it matches the fingerprint the server printed at boot.

The IaC templates fetch the Tier-1 key and JWT secret from the cloud secret
store using the instance's own identity (IAM role, managed identity, or
service account). Secrets are never placed in instance user data in cleartext,
because the confidential-VM threat model assumes the provider can read instance
metadata but not guest memory.

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
| Confidential computing | Required; attested at boot; fail-closed |
| Supported platforms | AWS (SEV-SNP + NitroTPM), Azure (Confidential VM + Trusted Launch), GCP (Confidential VM + Shielded VM) |
| Instance types refused | Spot / preemptible, autoscaled / scale-set, ephemeral fleet |
| Tier-1 KEK | Sealed to the instance vTPM; recovery code for instance loss |
| Backup KEK | Cloud KMS or Vault required; environment-variable KEK refused |
| Addressing | Stable operator DNS (primary SAN) + instance IP (secondary SAN) |
| Certificate on address change | Re-issued under the stable anchor; clients pin the anchor, not the leaf |
| High availability | Out of scope (separate capability) |
