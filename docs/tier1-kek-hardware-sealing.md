# Tier-1 KEK Hardware Sealing

FireAlive encrypts server-side secrets at rest under a single AES-256-GCM key,
the **Tier-1 key-encryption-key (KEK)**. Under decision D26 that key is
**hardware-sealed and fail-closed**: the value carried in `TIER1_ENCRYPTION_KEY`
is no longer a raw hex key but an opaque wrapper that only the host's TPM 2.0
(Linux, Windows) or Secure Enclave (macOS) can unseal. A copied disk or cloned
virtual machine cannot unseal it, so the secrets it protects stay inert anywhere
but the original hardware. This document describes what the Tier-1 KEK protects,
how sealing works, how to provision it, and — most importantly — the recovery
doctrine you must follow so that a hardware failure is survivable.

**Both servers do this, independently.** The Regional Server and the Global
Dashboard Server are separate trust realms with separate hardware roots, and each
seals its own Tier-1 KEK to its own host. Everything below describes the Regional
Server and its `TIER1_ENCRYPTION_KEY`. The **Global Dashboard Server** section near
the end covers `GD_ENCRYPTION_KEY`, which follows the same model with its own
scripts and its own recovery code.

## Why this exists

- **A raw key in the environment is exactly what a clone copies.** When the KEK
  is a hex string in an environment variable, anyone who copies the deployment
  (a disk image, a snapshot, a stolen VM) copies the key with it and can decrypt
  every server-side secret. Sealing the key to hardware removes it from anything
  a clone can carry away.
- **TPM 2.0 and the Secure Enclave are the SOC-standard root of trust.** Anything
  weaker is an exposure SOC operators will not accept. FireAlive requires a
  hardware root on Linux, Windows, and macOS.
- **Fail-closed, with no software path.** If the hardware cannot unseal the key,
  the server refuses to use the Tier-1 path rather than falling back to a weaker
  key. A downgrade path would reintroduce the very exposure sealing removes.

## What the Tier-1 KEK protects

At rest in the database, the Tier-1 KEK encrypts:

- **Integration credentials** — the secrets for connected SOAR, chat, ticketing,
  and notification systems.
- **Every signing-key private key** — report signing, the audit chain, backup
  signing, GD push, the abuse vault chain, and the certificate authority.
- **Other operator-entered secrets** — SMS auth tokens, IAM/LDAP bind passwords,
  and similar.

It does **not** protect analyst signal data. That is **Tier-3**, encrypted under a
separate key (`TIER3_ENCRYPTION_KEY`) and slated to become user-bound
(passkey-PRF) in a later phase. A Tier-1 hardware failure therefore never touches
analyst data; what it affects is the server's own key material and the
operator-entered credentials, all of which are regenerable or re-enterable.

## How sealing works

`TIER1_ENCRYPTION_KEY` holds a wrapper beginning `fa-tier1-hwseal:v1:`. The key
chokepoint unseals it on the host hardware and caches the result in process
memory, so the hardware is touched once per process rather than per operation.
Two code paths consume the key through one resolver: the just-in-time
`encryptConfig` / `decryptConfig` path used throughout the server, and the backup
engine's env-var key-wrapping provider — so backups are wrapped under the same
hardware-bound key. The cross-platform keystore seam uses sealing primitives
common to TPM 2.0 and the Secure Enclave; the KEK itself is a 32-byte AES-256-GCM
key.

## Provisioning

Run once, on the host that will run FireAlive, before first start:

```
node scripts/provision-tier1-kek.js
```

It generates the KEK, seals it to this host's hardware, and prints two things:

1. the value to set as `TIER1_ENCRYPTION_KEY` (the `fa-tier1-hwseal:v1:`
   wrapper), and
2. a one-time **recovery code** (beginning `fa-tier1-recovery:v1:`).

You choose a recovery passphrase of at least 12 characters, prompted for without
echo, or supplied non-interactively via `FIREALIVE_RECOVERY_PASSPHRASE`. The raw
key never leaves the process and is zeroed after use.

> Re-running provisioning generates a **new** key that cannot decrypt anything
> encrypted under the previous one. Only run it for initial setup.

## The recovery doctrine (essential)

Because the KEK is sealed to the hardware, it dies with the hardware. **Two
things are both required to recover a deployment, and neither alone is
sufficient:**

1. **A backup of the server**, taken regularly.
2. **The offline recovery code** from provisioning.

A backup is encrypted *under* the Tier-1 KEK — it does not contain the KEK, and
restoring requires the same key. If the hardware is lost and you have only a
backup, the backup cannot be opened. If you have only the recovery code, there is
nothing to restore. Keep both: back up the server regularly, and store the
recovery code **offline** — a password manager's secure note, a sealed envelope,
or an HSM-backed secret — never on the server itself, where a clone could copy
it.

## Recovery on new hardware

On a replacement host, after the original TPM or Secure Enclave is lost:

```
node scripts/recover-tier1-kek.js
```

Provide the recovery code (or `FIREALIVE_RECOVERY_CODE`) and its passphrase (or
`FIREALIVE_RECOVERY_PASSPHRASE`). The script re-establishes the identical key,
re-seals it to the new hardware, and prints the new `TIER1_ENCRYPTION_KEY`
wrapper to set. Then restore the server from your most recent backup — now
decryptable, because the key is re-established. The recovered key is identical to
the original, so your existing recovery code remains valid; keep it stored
offline.

## Fail-closed behavior

The server refuses to operate on the Tier-1 path when:

- no hardware root of trust is present,
- `TIER1_ENCRYPTION_KEY` is unset, a placeholder, or a raw (non-sealed) key, or
- the sealed wrapper cannot be unsealed on this hardware (wrong or changed
  hardware).

Each fails with a clear message pointing at provisioning or recovery. There is no
software fallback: a failure surfaces visibly rather than silently degrading to a
weaker key.

Continuous integration is unaffected. The CI workflow lints the config-lock
coverage and packages the desktop apps; it never boots the regional server, so it
never establishes identity or resolves the Tier-1 KEK, and fail-closed hardware
enforcement cannot break the build.

## Relationship to cloud KMS and Vault

**A key-wrapping provider is not an alternative to the recovery code.** That is
worth stating first, because the arrangement invites the opposite reading.

A provider wraps the **per-backup ephemeral data key** — the 256-bit AES-GCM key
that encrypts one backup archive. It does not wrap the Tier-1 KEK, and no provider
escrows the Tier-1 KEK anywhere. The env-var provider is the default and resolves
the hardware-sealed Tier-1 KEK in order to do its wrapping; an operator who prefers
managed custody can point the provider at AWS KMS, Azure Key Vault, GCP KMS, or the
HashiCorp Vault transit engine instead.

Doing that changes where the archive key lives — FIPS 140-2 Level 3 custody in
eligible regions, provider-side rotation and audit, an organizational policy that
backup keys never sit in process memory. It does **not** change what a restore
needs. A v2 archive is the SQLite database file, and restore swaps that file in
verbatim; nothing is re-encrypted or re-keyed. The secret columns inside it — every
signing-key private key, the certificate-authority key, the integration credentials
— are Tier-1 ciphertext sealed to the hardware that is gone. Open the archive with
a KMS-held key on replacement hardware and you have a database whose audit-chain
signing key, CA, and credentials you cannot read.

**The offline recovery code is required under every provider.** Recovering a
deployment is always the same sequence: re-establish the Tier-1 KEK from the
recovery code, seal it to the new hardware, then restore.

### Why the KEK itself is not escrowed to a KMS

Escrowing the Tier-1 KEK to a cloud KMS *would* make a deployment recoverable
without the offline code. It would also hand back exactly the exposure sealing
removes. A key that an IAM principal can unwrap over the network is a key that a
compromised deployment, or a compromised role, can unwrap over the network; the
anti-clone property would then be worth whatever the cloud IAM policy is worth
rather than what the TPM is worth, and the guarantee asserted under **Security
model** below would no longer hold. The recovery code is already an escrow of the
same bytes — with no online unwrap oracle, and with no third party's jurisdiction
attached to it. That is the trade, and it is deliberate.

## Security model

- **Anti-clone.** A copied disk or VM lacks the host's TPM or Secure Enclave and
  cannot unseal the KEK, so it cannot decrypt any Tier-1 secret or open any
  backup.
- **The recovery code never lives on the running server.** It is shown once at
  provisioning and stored offline, so it does not widen the surface a clone
  copies.
- **Residual risk.** An attacker who obtains both the offline recovery code *and*
  a backup can stand up a working copy. That requires compromising an offline
  secret store — a materially higher bar than copying a running disk, and the
  same trade-off as any key-escrow or seed-phrase scheme.

## The Global Dashboard Server

The GD Server holds no analyst data, but it does hold its own key material — every
GD signing-key private key, the GD certificate-authority key, and the credentials
for the systems it monitors itself with. Those are encrypted at rest under the
**GD Tier-1 KEK**, carried in `GD_ENCRYPTION_KEY`.

The model is identical to the Regional Server's, and the code is a twin.
`GD_ENCRYPTION_KEY` holds a wrapper beginning `fa-gd-tier1-hwseal:v1:`, unsealed on
the GD host's own TPM 2.0 or Secure Enclave and cached in process memory. A raw hex
key is **refused**, and the former `GD_JWT_SECRET`-derived KEK fallback is retired
outright: there is no software path and no weaker source.

The two KEKs are different keys on different hardware. Compromising one trust realm
does not yield the other. Store their recovery codes separately.

### Provisioning the GD

Run once, on the host that will run the GD Server, before first start:

```
node scripts/gd-provision-tier1-kek.js
```

It prints the `GD_ENCRYPTION_KEY` wrapper to set, and a one-time **recovery code**
beginning `fa-gd-tier1-recovery:v1:`. You choose a recovery passphrase of at least
12 characters, prompted for without echo, or supplied non-interactively via
`FIREALIVE_GD_RECOVERY_PASSPHRASE`. The raw key never leaves the process.

**In Cloud Mode, run it on the confidential VM**, so the key seals to that
instance's vTPM. This supersedes the earlier posture of supplying a raw
`GD_ENCRYPTION_KEY` from a cloud secret store — no raw key is ever placed in the GD
environment.

> Re-running provisioning generates a **new** key that cannot decrypt anything
> encrypted under the previous one. Only run it for initial setup.

### Recovering the GD on new hardware

```
node scripts/gd-recover-tier1-kek.js
```

Provide the recovery code (or `FIREALIVE_GD_RECOVERY_CODE`) and its passphrase (or
`FIREALIVE_GD_RECOVERY_PASSPHRASE`). The script re-establishes the identical key,
re-seals it to the new hardware, and prints the new `GD_ENCRYPTION_KEY` to set.
Then restore the GD from its most recent backup — now decryptable, because the key
is re-established.

The recovery doctrine is the same on both servers, and for the same reason: a GD
backup is encrypted under the GD Tier-1 KEK and does not contain it. A GD backup
and the offline GD recovery code are both required, and neither alone is
sufficient.

### One asymmetry, and what it is not

The GD has a single key-wrapping scheme, `gd-tier1` — every GD backup data key is
wrapped under the GD Tier-1 KEK — and no provider registry. So the managed-custody
options the Regional Server offers for its **archive key** (AWS KMS, Azure Key
Vault, GCP KMS, HashiCorp Vault) have no GD equivalent today.

That is a custody and compliance gap — no FIPS 140-2 Level 3 option, no
provider-side rotation for GD backup data keys — and not a recovery gap. As the
section above explains, a key-wrapping provider never made the recovery code
optional on the Regional Server either.

### High Availability

A GD standby cannot simply be handed the active's key; that would defeat the
sealing. At pairing, the shared key material is wrapped to the standby's own
hardware-bound X25519 key, whose private half is itself sealed under a key derived
from that node's GD Tier-1 KEK. The standby stores the material sealed, holds it
inert while it is passive, and unseals it only at promotion, on its own hardware. A
node holding no sealed material refuses to promote rather than coming up unable to
read the Tier-1 columns the former active wrote. See `docs/gd-high-availability.md`.

## Related documents

- `docs/full-suite-backup.md` — the canonical server backup, encrypted under the
  Tier-1 KEK.
- `docs/incremental-differential-chains.md` — the v2 backup engine and its
  key-wrapping schemes.
- `docs/two-person-restore.md` — the approval workflow for restoring a backup.
- `docs/client-recovery.md` — the analogous per-client recovery and its recovery
  code.
- `docs/gd-high-availability.md` — the GD standby's wrapped-key exchange and the
  promotion unseal.
- `docs/gd-restore.md` — restoring the GD Server from a backup.
