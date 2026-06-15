# Export Encryption at Rest (FA-ENC1)

This document is for **CISOs**, **VPs of Security**, **operators**, and **auditors** who need to understand how FireAlive protects forensic-export and legal-hold-export artifacts while they sit on disk, what that protection does and does not cover, and how a produced package is still independently verified. It describes the at-rest encryption layer added in the FA-ENC1 format; it does **not** change how an export is requested, authorized, signed, or verified — those are covered in `docs/forensic-export-architecture.md`, `docs/legal-hold-export.md`, and `docs/forensic-export-verifier-guide.md`.

## What this protects

A completed forensic export or legal hold is written to the server's filesystem as a gzipped tar archive plus a JSON manifest. Before this layer, those files sat in cleartext: anyone who could read the bytes — a stolen disk, an exfiltrated backup, a snapshot copied off the host, a misconfigured volume mount — could open the archive and read the exported audit, incident, and access records, and the manifest's case metadata.

With at-rest encryption, every export artifact is written as an encrypted, self-describing FA-ENC1 file. The plaintext is recoverable only with the deployment's key-encrypting key (KEK), which never lives in the export file and, on a properly provisioned deployment, never lives on disk in usable form at all. Reading the raw bytes off the filesystem yields ciphertext.

## Scope

The layer covers both export families, on both servers:

- **Forensic exports** and **legal holds** on the **Regional (MC) server**.
- **Forensic exports** and **legal holds** on the **Global Dashboard (GD) server**.

For each artifact, **both** the gzipped tar archive **and** its `.manifest.json` sidecar are sealed. The manifest is sealed because it carries the case identifier, the custodian/scope filter, and retention metadata — material that should not sit in cleartext either.

This layer does **not** cover the abuse-vault two-person legal-hold export (`docs/abuse-vault-legal-hold-export.md`), which is a reviewer-device flow whose case file is produced and protected client-side.

## Threat model

**Defended.** The confidentiality of export artifacts against an adversary who obtains the *bytes at rest* but not the KEK:

- A lost or stolen disk, or a decommissioned drive that was not wiped.
- A copied filesystem snapshot, volume image, or container layer.
- An exfiltrated host backup that sweeps up the export directory.
- A process or operator that can read the export files but cannot resolve the KEK (for example, a backup agent, or a compromised account without the hardware root of trust).

**Not defended.** This is at-rest protection, not secrecy from the platform itself:

- An adversary who holds the KEK (or can make the running server resolve it) can decrypt. The KEK's protection is the subject of `docs/tier1-kek-hardware-sealing.md`; on a provisioned deployment the Tier-1 KEK is sealed to a hardware root of trust (TPM 2.0 or the Secure Enclave) and is fail-closed.
- Live process memory: while an export is being built or downloaded, plaintext exists transiently in the server's memory by necessity.
- The authorization and separation-of-duties controls (who may create, download, delete, or release an export) are unchanged and are documented elsewhere; encryption at rest is orthogonal to them.

The integrity and provenance of an export continue to rest on its **Ed25519 manifest signature** and its optional **Cosign signature**, both unchanged by this layer (see below).

## The FA-ENC1 file format

Each sealed artifact is a single, self-describing file. It carries everything needed to identify and unwrap it except the KEK:

```
offset 0    magic       6 bytes    ASCII "FAENC1"
offset 6    version     1 byte     0x01
offset 7    role        1 byte     0x01 = archive, 0x02 = manifest
offset 8    headerLen   4 bytes    uint32, big-endian
offset 12   header      headerLen  UTF-8 JSON (see below)
offset ...  ciphertext  remainder  AES-256-GCM ciphertext
```

The header JSON records the algorithm, the artifact's role and export id, the GCM nonce and tag, and the wrapped data key:

```json
{
  "alg": "aes-256-gcm",
  "role": "archive",
  "export_id": "<id>",
  "iv": "<base64, 12 bytes>",
  "tag": "<base64, 16 bytes>",
  "kek": { /* wrap envelope, or null for a keyless test frame */ }
}
```

**Per-artifact data key.** Each artifact is encrypted under a fresh, random 256-bit AES-GCM data key. That data key is then *wrapped* (encrypted) under the deployment KEK and stored — wrapped — in the header's `kek` field. The raw data key is zeroed after use and never persists.

**Authenticated associated data.** The GCM additional authenticated data is the ASCII string

```
FAENC1|v1|<role>|<export_id>
```

so the tag binds each ciphertext to its role and its export id. An archive cannot be passed off as a manifest, and an artifact from one export cannot be substituted for the artifact of another — the tag check fails. A wrong data key fails the same check.

## Key management

The per-artifact data key is wrapped differently on each server, reflecting each server's existing key infrastructure. **The two servers keep entirely independent KEKs.**

**Regional (MC) server.** The data key is wrapped through the shared backup key-wrapping registry — the same audited path the platform already uses for backup key wrapping. The default scheme is `env-var` with the reference `TIER1_ENCRYPTION_KEY`, which resolves the Tier-1 KEK through the hardware sealing described in `docs/tier1-kek-hardware-sealing.md`. Because it is the shared registry, the cloud-KMS schemes (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault) are available to the export path by the same mechanism, with no export-specific key code — appropriate when export artifacts are legal evidence whose key custody must live in a managed KMS. The header `kek` envelope on the regional side carries `{ v, scheme, ref, wrapped }`.

**Global Dashboard (GD) server.** The GD has no key-wrapping-providers registry. Its data key is wrapped under the GD's own derived Tier-1 KEK via the GD configuration-encryption module (scheme `gd-tier1`); the header `kek` envelope carries `{ v: 1, scheme: "gd-tier1", wrapped: <envelope string> }`. The GD KEK is independent of the MC KEK: a key from one server cannot open an artifact sealed by the other.

## What stays in cleartext, and why

Three things are deliberately *not* encrypted:

- **`archive_sha256`** and **`size_bytes`** in the database row are the hash and length of the *delivered plaintext* archive — the bytes a recipient receives and verifies. They are recorded over the plaintext so that the delivered package, its hash, and its size are byte-identical to the pre-encryption behavior, and so the existing verifier guide continues to apply unchanged.
- **The detached `.manifest.sig`** (Ed25519 over the manifest) and **`.cosign.sig`** (Cosign over the archive) are *signatures* — they carry no confidential content, and they are computed over the plaintext. They remain plaintext sidecars so that signature verification works exactly as before.

Cosign signs the plaintext archive: during creation the plaintext is written transiently so the cosign tool can read it, the signature is produced, and the file is then overwritten in place by its FA-ENC1 ciphertext using a temp-and-rename so no partial file is ever observable.

## Delivery: decrypt on read

Encryption at rest is invisible to anyone downloading an export. A download or manifest fetch peeks at the first six bytes of the file; if it is an FA-ENC1 artifact, the server buffers it, verifies the full GCM tag, opens it under the KEK, and sends the decrypted plaintext. The delivered bytes are therefore identical to what the endpoint returned before this layer existed. A legacy plaintext artifact (one not yet re-sealed — see migration) streams as before. Either way the recipient receives the same standard `tar.gz` and manifest, and verifies the Ed25519 and Cosign signatures using the steps in `docs/forensic-export-verifier-guide.md`.

## Migration and the at-rest posture columns

Two nullable columns on each export table record the posture per artifact:

- **`at_rest_scheme`** — the KEK scheme that protects the artifact (`env-var` on the regional server, `gd-tier1` on the GD). A **NULL** value is the canonical signal of a *legacy plaintext* artifact written before this layer existed.
- **`at_rest_kek_ref`** — the KEK reference (`TIER1_ENCRYPTION_KEY` on the regional server; NULL for `gd-tier1`, whose KEK is derived rather than referenced by name).

At startup each server runs an **idempotent migration** that finds rows whose `at_rest_scheme` is NULL and that have an archive on record, seals the archive and the manifest sidecar in place if either is still plaintext, and records the posture. It is safe to re-run: a row whose columns are set is skipped, and an already-sealed file is never re-sealed (so a crash that sealed a file but missed the column update is reconciled without double-sealing). Each row is isolated, and a transient failure (for example, a KEK that is briefly unavailable) is logged and retried on the next boot. This is a pre-release convenience; there is no operator step.

## Recovery and key loss

Because the data key is wrapped under the KEK, **the KEK is the recovery dependency**: with it, every artifact opens; without it, the sealed archives are unrecoverable ciphertext. This is the intended property — it is what makes a stolen disk useless — but it makes KEK custody operationally critical:

- On a provisioned deployment the Tier-1 KEK is sealed to the host's hardware root of trust and is fail-closed; back it up and manage its lifecycle per `docs/tier1-kek-hardware-sealing.md`.
- For legal-evidence custody, configure a cloud-KMS scheme (regional) so the KEK lives in a managed, auditable, recoverable key service rather than on the host.
- The MC and GD KEKs are independent; plan custody for each.

An auditor or recipient never needs the KEK: they verify the *delivered, decrypted* package, whose signatures and hash are over the plaintext.

## Cross-references

- `docs/tier1-kek-hardware-sealing.md` — how the Tier-1 KEK is sealed and resolved.
- `docs/forensic-export-architecture.md` — forensic export creation and structure.
- `docs/legal-hold-export.md` — legal-hold export and custody chain.
- `docs/forensic-export-verifier-guide.md` — how a recipient verifies a produced package.
