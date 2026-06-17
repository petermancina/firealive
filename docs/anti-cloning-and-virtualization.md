# Anti-Cloning, Virtualization, Restore, and Migration

Operator runbook for how a FireAlive deployment proves it is authentic, how
clones are caught, how the suite behaves under a hypervisor, and how to
restore a client or migrate an entire deployment without tripping the
anti-cloning defenses.

This document describes shipped behavior. It is written for SOC
administrators and team leads operating the Regional Server and Management
Console (MC).

## The two identity layers

FireAlive's authenticity rests on two independent, hardware-rooted identity
layers. A clone has to defeat both, and cannot defeat either.

### 1. Instance-level identity (the deployment anchor)

Each deployment mints a single instance anchor at first boot. The anchor's
private key is sealed to the host's hardware root of trust: a TPM 2.0 on
Linux and Windows, or the Secure Enclave on macOS. The sealed key does not
unseal on different hardware.

The anchor underpins the rest of the instance identity: the deployment
certificate authority (CA), the server keys and certificates, analyst-client
device registrations, and outstanding enrollment tokens.

This layer is fail-closed. If no hardware root of trust is available, the
server refuses to start and establish an identity; there is no software
fallback. Provision a TPM or Secure Enclave and restart.

### 2. Per-client device identity (analyst clients)

Every Analyst Client registers its own device signing key on first run,
bound to that machine's hardware where present (ECDSA P-256 in the TPM or
Secure Enclave). Each key carries a monotonic ratchet counter. The server
tracks the high-water ratchet value, so a key presented with a rolled-back
counter is rejected.

Analyst data is encrypted under a user-bound key unwrapped by the analyst's
hardware passkey (WebAuthn PRF), not by any machine-bound key. That is why
data survives a hardware change while identity does not migrate.

## What catches a clone, layer by layer

- Copying a deployment's disk or VM image to new hardware does not yield a
  working clone: the anchor key was sealed to the original hardware root and
  will not unseal elsewhere, so the copy cannot act as the instance.
- A clone made from a compromised analyst machine fails too: the device key
  is hardware-bound and will not unseal off-machine, and even a copied key
  is caught by the ratchet high-water check or revoked during teardown.
- Running two copies of the same identity at once is caught as concurrent
  duplication by the observer / instance-registry path, independent of the
  hardware seal.
- Rolling a virtual machine back to an earlier snapshot is caught by clock-
  integrity monitoring (see below).
- A clone presenting no valid hardware root simply cannot establish or load
  an identity (fail-closed).

## Deployment modes: bare-metal, virtualized, and cloud

The deployment mode is chosen once, at install / first boot, before any
identity is established, via the FIREALIVE_DEPLOYMENT_MODE environment
variable. The chosen mode is hardware-sealed; thereafter the sealed value is
authoritative and a divergent environment variable is ignored and logged.

All virtualization behavior below is additive and applies in both virtualized
mode and cloud mode: the relocation and clock-integrity gates treat a cloud
instance like a virtualized one. Bare-metal deployments are unaffected. Cloud
mode adds its own confidential-computing requirements, summarized in the cloud
mode subsection below and documented in full in docs/cloud-mode.md.

### vMotion / live migration versus a clone

In virtualized mode the anchor (a virtual TPM) moving to a new host is
treated as an authorized relocation and is audited. A bare-metal host change
for the same identity is flagged instead. Classic live migration preserves
the guest's network identity at the hypervisor layer, so relocation does not
by itself look like duplication. In cloud mode the same rule applies to a
stopped instance that restarts on a new host or address: it is an authorized
relocation, not a clone. Concurrent duplication remains a clone via the
observer path; this only tracks sequential relocation.

### Clock integrity (snapshot-rollback defense)

A virtual machine can be rolled back to an earlier snapshot, which would
also roll back the database and any single-use state in it. FireAlive
monitors wall-clock time against a monotonic clock and detects divergence.
In virtualized mode, a detected backward jump makes time untrusted and the
following operations fail closed until time re-stabilizes:

- privileged MC device actions (recovery teardown / reprovision / approve /
  reject) return 503 and audit MC_DEVICE_ACTION_CLOCK_UNTRUSTED;
- enrollment and break-glass authentication return 503 and audit
  ENROLL_AUTH_CLOCK_UNTRUSTED.

Bare-metal deployments are never gated on clock divergence.

### Backup independence under virtualization

In virtualized mode the server refuses to create a backup destination that
writes to local storage, because a VM snapshot or clone would capture those
local backups along with the data. Use an external destination (SFTP, S3,
Azure Blob, or GCS). All backups are signed and KEK-wrapped regardless of
mode.

### Cloud mode (confidential VM)

Cloud mode runs the Regional Server on a confidential VM in a public cloud
(AWS, Azure, or GCP). It reuses the deployment anchor unchanged: the anchor's
private key is sealed to the instance vTPM, which a confidential VM presents
as a TPM 2.0 device. No new identity backend is introduced.

Cloud mode adds three enforcement points on top of the relocation and
clock-integrity behavior above:

- **Confidential computing is required and attested at boot.** The server
  verifies a confidential-computing guest is present (the SEV-SNP, TDX, or
  Nitro guest attestation device) and refuses to start if it is absent. There
  is no downgrade.
- **Spot and autoscaled instances are refused.** A single anchored identity is
  incompatible with an instance the cloud platform can terminate or multiply,
  so the boot gate halts on a spot, preemptible, autoscaled, or scale-set
  instance.
- **The backup KEK must come from the cloud KMS or Vault.** An
  environment-variable backup KEK is refused for new backups, because it would
  live in the process memory the confidential VM protects. Restoring an
  existing backup under any scheme is unaffected.

Because a cloud instance's address can change, the server reconciles its
certificate SAN at boot against a stable operator DNS name (the primary SAN)
and the instance IP from metadata (a secondary SAN), re-issuing the leaf under
the stable anchor when the address set changes. Clients pin the anchor
fingerprint, not the leaf, so re-issuing on a stop/start or a load-balancer
change does not break the trust pin. The Tier-1 KEK stays sealed to the
instance vTPM; keep the recovery code issued at first boot, since a replaced
host means a new vTPM. The full runbook is docs/cloud-mode.md.

## Restoring a single client (not a clone)

A restored Analyst Client (replaced or wiped machine) is distinguished from a
clone by authorization and identity freshness, never by the data.

Procedure:

1. At the MC, run the recovery teardown for the affected analyst. This
   revokes the old device key and certificates, so any clone made from the
   old machine is killed.
2. Issue a single-use re-provision token (MFA step-up required at the MC).
3. On the new or wiped machine, the analyst completes re-provisioning with
   their hardware passkey. The client mints a fresh device identity with a
   fresh ratchet.
4. The analyst's data unwraps with their passkey on the new hardware; the
   data key is user-bound, so no data is lost.

The server sees a new authorized enrollment, not an old key with a rolled-
back counter, so no clone alarm fires and the ratchet reset is correct.

## Migrating an entire deployment (FA-MIG1)

Use a deployment migration to move a whole FireAlive instance to new
hardware or a new host (hardware refresh, bare-metal to VM, data-center
move). A migration deliberately does NOT restore the source's instance
identity verbatim, because verbatim identity restore is indistinguishable
from cloning. Instead it carries the data forward and re-establishes a fresh
identity on the target.

### What a migration moves

A migration separates the imported bundle into three layers:

- Instance-level identity (CA, server keys, analyst-client device keys,
  issued certificates, enrollment): re-established FRESH on the target. The
  source identity is never carried. Analyst clients re-bind afterward through
  the re-provision ceremony above.
- Analyst-level keys (per-analyst burnout keys and recovery wraps):
  preserved. They are user-bound and stay recoverable through the offline
  recovery code, so they survive the identity reset.
- Data (audit, forensic, and legal-hold chains, team and system config,
  sealed history, training and helper-pay records): preserved.

### The FA-MIG1 bundle

A bundle is a self-contained directory holding a signed manifest, the
golden-baseline configuration capture, and a signed, KEK-wrapped full-suite
backup. The manifest binds both components by SHA-256 and is signed with the
source deployment's Ed25519 backup signing key.

### Procedure

Migration is an admin operation, gated by the config lock and MFA step-up.
Unlock configuration on both deployments before starting.

On the SOURCE deployment:

1. MC -> Settings -> Data & Backup -> Deployment Migration -> Export
   (MFA step-up). This composes the FA-MIG1 bundle on the server.
2. Note the source's backup signing key fingerprint (shown with the bundle
   and in the backup signing key settings).
3. Collect the bundle directory from the server and transfer it to the
   target host (for example with scp).

On the TARGET deployment (a fresh install on the new hardware):

4. Place the bundle directory under the target's migration-bundles root (the
   MIGRATION_BUNDLE_DIR directory, default data/migration-bundles). The
   importer accepts only a bundle path inside that root.
5. Register the source's backup signing key as a trusted verification key,
   confirming the fingerprint out of band against the value from step 2. An
   unregistered key is refused.
6. MC -> Settings -> Data & Backup -> Deployment Migration -> Import. Enter
   the bundle directory path and run Preview (dry run). Review the
   reconciliation plan: confirm the source key shows as trusted, the bundle
   is proceedable, and the three layers read as expected.
7. Run Apply (MFA step-up, confirmation required). The target verifies the
   bundle, restores the data through the same EDR-scanned swap used by
   external restore (a pre-import snapshot is taken automatically), then
   re-establishes instance identity fresh and re-baselines configuration.
8. Restart the target deployment to refresh process-lifetime caches and to
   run any schema migrations.
9. Re-provision the analyst clients against the target using the per-client
   restore procedure above. Each client re-binds to the new identity.

### Security properties

- The bundle is refused unless its signatures verify against the registered
  trusted source key, so a tampered or unauthorized bundle cannot be applied.
- The restored database bytes are malware-scanned before they replace the
  live database; the apply fails closed if no scanner is configured, if a
  threat is found, or if the scan is inconclusive.
- The pre-import snapshot is the rollback path if anything goes wrong.
- The importer confines the supplied bundle path to the migration-bundles
  root; a path that resolves outside it is rejected, so the import cannot be
  pointed at an arbitrary location on the server.
- Because identity is re-minted rather than copied, the migrated deployment
  is a distinct authentic instance, not a clone, and the source (once
  decommissioned) leaves no usable duplicate.

## Notes and limitations

- Cross-version migration (bundle and target on different builds) is
  surfaced as a warning in the preview; align versions where possible and
  rely on the post-apply restart to complete schema migration.
- Decommission the source deployment after a successful migration so two
  instances do not run concurrently.
- Container / Kubernetes specifics (pod rescheduling and certificate SAN
  handling on reschedule) are addressed separately under Container Mode.

