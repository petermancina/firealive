# EU-Sovereign Backup Destinations and Key Wrapping

This document covers configuring FireAlive backups to use EU-sovereign cloud providers and self-hosted HashiCorp Vault for key wrapping. It complements [`two-person-restore.md`](./two-person-restore.md), which covers the approval-gate side of restore operations.

## Why EU-sovereign matters

For European deployments, a backup pipeline that puts data in US-jurisdiction services creates concrete legal and operational risk:

- **Schrems II (CJEU C-311/18, July 2020)** invalidated the EU-US Privacy Shield. Personal data exports to US-located services require Standard Contractual Clauses plus supplementary technical measures, which the European Data Protection Board's recommendations effectively interpret as "the data must be unreadable to the US provider in the clear."
- **Cloud Act (US, 2018)** lets US authorities compel disclosure of data held by US providers regardless of where the bytes physically reside, including in EU regions of US providers (AWS Frankfurt, Azure West Europe, GCP europe-west).
- **NIS 2 (EU 2022/2555, transposition deadline October 2024)** classifies SOC tooling for in-scope sectors as "important entity" infrastructure with operational continuity and supply-chain due-diligence obligations.
- **DORA (EU 2022/2554, in force January 2025)** adds ICT third-party risk requirements for financial-services SOCs specifically.

The mitigation pattern this document supports is "EU-sovereign across all three layers":

```
backup data       in EU-jurisdiction storage          (Hetzner / OVH / Scaleway)
key encryption    on a self-hosted EU-located KMS     (HashiCorp Vault)
key custody       under EU-corporate operator         (your deployment)
```

With all three in place, no US-jurisdiction provider has access to the encrypted backup bytes OR the keys that decrypt them. A US-Cloud-Act order to FireAlive's American competitors would not produce readable analyst data.

This is **not legal advice**. Specific compliance posture depends on your sector, member state, and DPA's interpretation. This document is a recipe; talk to your DPO before relying on it.

## Architecture

```
                                                         ┌─────────────────┐
                                                         │  Wrap KEK       │
                                                         │  (Vault transit │
                                                         │   engine)       │
                                                         └────────▲────────┘
                                                                  │ wrap/unwrap DEK
                                                                  │ (HTTPS, Vault-auth)
  ┌──────────────┐    ┌─────────────────────────┐    ┌────────────┴────────┐
  │  FireAlive   │───▶│  services/backup.js     │───▶│ backup-key-wrapping │
  │  scheduler   │    │  generates ephemeral DEK│    │ dispatcher          │
  └──────────────┘    └────────────┬────────────┘    └─────────────────────┘
                                   │
                                   │ encrypt archive with DEK,
                                   │ then write wrapped DEK + manifest
                                   ▼
                      ┌────────────────────────────────────┐
                      │  destination-adapter-s3.js         │
                      │  (S3-compatible: Hetzner / OVH /   │
                      │   Scaleway, EU regions)            │
                      └────────────┬───────────────────────┘
                                   │ HTTPS S3 PutObject
                                   ▼
                            ┌──────────────┐
                            │  EU object   │
                            │  storage     │
                            └──────────────┘
```

The destination adapters and key-wrapping providers are the only modules that directly contact cloud services. Configuration of which providers to use is in the database (`backup_destinations` and `kms_providers` tables), modifiable via admin endpoints, never hardcoded.

## Hetzner Object Storage

Hetzner is a German hosting provider with EU-only infrastructure (Falkenstein, Nürnberg, Helsinki). Their object storage is S3-compatible and inexpensive (€0.0066/GB/month at the time of writing, no egress fees within Hetzner network).

### Setup

1. In Hetzner Cloud Console, create an Object Storage bucket in `eu-central` (Falkenstein) or `eu-helsinki1`.
2. Generate S3 credentials: Cloud Console → Security → S3 Credentials → Generate.
3. Note the access key ID, secret access key, endpoint URL (`https://<region>.your-objectstorage.com`), and bucket name.

### Configure in FireAlive

```http
POST /api/backup-destinations
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{
  "name": "hetzner-fsn-primary",
  "adapter_type": "s3",
  "config": {
    "endpoint": "https://fsn1.your-objectstorage.com",
    "region": "eu-central",
    "bucket": "firealive-backups",
    "force_path_style": true,
    "object_lock_mode": "COMPLIANCE",
    "object_lock_retention_days": 365
  },
  "credentials": {
    "access_key_id": "<from Hetzner console>",
    "secret_access_key": "<from Hetzner console>"
  },
  "enabled": true
}
```

`force_path_style: true` is required — Hetzner's S3 implementation does not support virtual-host-style addressing.

`object_lock_mode: "COMPLIANCE"` enables Hetzner's WORM (write-once-read-many) feature, the equivalent of S3 Object Lock. This prevents an attacker who compromises FireAlive's credentials from deleting prior backups, even with admin permissions on the bucket. **Critical** for ransomware resilience: it means the attacker cannot delete the backups on their way out.

`object_lock_retention_days: 365` sets the WORM retention period. Pick this to match your incident-response window — long enough that you'd notice an attack and want to roll back, short enough that storage costs don't compound. Twelve months is a reasonable default.

### Quirks

- Hetzner doesn't support S3 versioning when Object Lock is enabled (mutually exclusive on their service). Object Lock alone is sufficient for FireAlive's threat model — the per-backup directories are immutable; we don't overwrite prior backups with new versions.
- S3 multipart upload works but the lib-storage `Upload` helper defaults to 8 MB parts; consider raising to 32 MB via `partSize: 32 * 1024 * 1024` to reduce request count for large database backups.
- Hetzner CDN is not available for object storage; private-bucket access is fine for backup workflows.

### Cost ballpark (1 TB stored, 100 GB monthly add)

- Storage: 1 TB × €0.0066/GB/mo = ~€7/mo
- Egress to your EU servers: free
- Egress to non-Hetzner: €1/TB
- API requests: free up to 100 M/month

## OVHcloud Object Storage

OVHcloud is a French provider with EU and global regions. Their object storage is S3-compatible with native versioning + Object Lock support.

### Setup

1. In OVH Public Cloud panel, choose a project, then Object Storage → Create container in region `GRA`, `SBG`, `RBX`, `BHS`, `WAW` (Warsaw — useful for Polish deployments under Polish-jurisdictional preferences). For EU sovereignty, pick `GRA` (Gravelines), `SBG` (Strasbourg), or `RBX` (Roubaix).
2. Choose Storage Class: `Standard` or `Archive`. For backups, Standard is appropriate (Archive's hour-scale retrieval latency conflicts with restore RTOs).
3. Generate S3 credentials: Public Cloud → Object Storage → Users → Add user → Generate access key.

### Configure in FireAlive

```http
POST /api/backup-destinations
{
  "name": "ovh-gra-primary",
  "adapter_type": "s3",
  "config": {
    "endpoint": "https://s3.gra.io.cloud.ovh.net",
    "region": "gra",
    "bucket": "firealive-backups",
    "force_path_style": false,
    "object_lock_mode": "COMPLIANCE",
    "object_lock_retention_days": 365
  },
  "credentials": {
    "access_key_id": "<from OVH user creation>",
    "secret_access_key": "<from OVH user creation>"
  },
  "enabled": true
}
```

OVH supports virtual-host-style addressing, so `force_path_style: false` is correct.

### Quirks

- OVH's "Storage Standard" is the right tier; "High Performance" is for hot workloads and isn't needed for backups.
- OVH bills per GB hour, not per GB month — costs are similar but the granularity matters if you cycle through buckets.
- Free egress within EU regions; €0.011/GB for inter-region (if you replicate from `gra` to `sbg`, for instance).

### Cost ballpark (same volume as Hetzner)

- Storage: 1 TB × €7/mo ≈ €7/mo
- Egress within EU: free
- API requests: free

## Scaleway Object Storage

Scaleway is a French provider (Iliad subsidiary) with EU regions. S3-compatible with Object Lock.

### Setup

1. Scaleway Console → Object Storage → Create bucket in `fr-par` (Paris), `nl-ams` (Amsterdam), or `pl-waw` (Warsaw). Object Lock must be enabled at bucket-creation time; you cannot retrofit it onto an existing bucket.
2. IAM → API Keys → Generate new credentials. Scaleway uses access/secret pair.

### Configure in FireAlive

```http
POST /api/backup-destinations
{
  "name": "scaleway-par-primary",
  "adapter_type": "s3",
  "config": {
    "endpoint": "https://s3.fr-par.scw.cloud",
    "region": "fr-par",
    "bucket": "firealive-backups",
    "force_path_style": false,
    "object_lock_mode": "COMPLIANCE",
    "object_lock_retention_days": 365
  },
  "credentials": {
    "access_key_id": "SCW...",
    "secret_access_key": "<from Scaleway IAM>"
  },
  "enabled": true
}
```

### Quirks

- Scaleway's S3 Object Lock requires `s3:BypassGovernanceRetention` IAM permission to be **absent** from your application user — make sure the user's policy explicitly lacks that permission so a compromised credential cannot bypass retention.
- Scaleway's Multi-AZ storage class is "Standard"; "Single-AZ" is cheaper but loses datacenter-failure resilience. For backups, Standard.
- Scaleway introduces strict bucket-naming requirements (lowercase, no underscores, 3-63 chars).

### Cost ballpark

- Storage: ~€10/TB/mo (Standard, multi-AZ)
- Egress within Scaleway: free
- API requests: included up to a generous limit

## HashiCorp Vault (key wrapping)

Vault is the SOC-grade choice for self-hosted EU-sovereign key wrapping. The transit secrets engine wraps and unwraps DEKs without ever exposing the underlying KEK to FireAlive's process — the KEK lives only in the Vault server's memory, encrypted with Vault's own master key.

### Setup

1. Deploy Vault on EU-located infrastructure. Cloud-managed: HashiCorp Cloud Platform Vault Dedicated in `eu-central-1` (Frankfurt). Self-hosted: any EU server with sufficient hardening (Vault's [Production Hardening Guide](https://developer.hashicorp.com/vault/tutorials/operations/production-hardening)).
2. Enable the transit engine:
   ```
   vault secrets enable transit
   ```
3. Create a key for FireAlive backups:
   ```
   vault write -f transit/keys/firealive-backup-kek
   ```
4. Create an AppRole for FireAlive to authenticate as:
   ```
   vault auth enable approle
   vault policy write firealive-backup - <<EOF
     path "transit/encrypt/firealive-backup-kek" {
       capabilities = ["update"]
     }
     path "transit/decrypt/firealive-backup-kek" {
       capabilities = ["update"]
     }
   EOF
   vault write auth/approle/role/firealive-backup token_policies="firealive-backup" token_ttl=1h token_max_ttl=4h
   vault read auth/approle/role/firealive-backup/role-id
   vault write -f auth/approle/role/firealive-backup/secret-id
   ```
5. Note the role_id, secret_id, Vault address, and key name.

### Configure in FireAlive

```http
POST /api/kms-providers
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{
  "name": "vault-prod",
  "provider_type": "hashicorp-vault",
  "config": {
    "address": "https://vault.example.com:8200",
    "namespace": "firealive",
    "key_name": "firealive-backup-kek",
    "transit_mount": "transit",
    "tls_skip_verify": false,
    "request_timeout_ms": 5000
  },
  "credentials": {
    "auth_method": "approle",
    "role_id": "<from vault read auth/approle/role/.../role-id>",
    "secret_id": "<from vault write auth/approle/role/.../secret-id>"
  },
  "enabled": true
}
```

The `probe` field defaults to `true` for cloud schemes, so the create call will perform a round-trip wrap/unwrap with Vault before persisting the row. A misconfigured Vault address, wrong role_id/secret_id, or missing transit policy surfaces here as a `PROVIDER_PROBE_FAILED` (HTTP 422) rather than letting a bad row sit in the table.

After the row is created, switch to it as the default:

```http
POST /api/kms-providers/<row-id>/set-default
```

The seed `env-var-default` row remains in place but loses the default flag — restored backups that were wrapped under env-var still unwrap correctly because the dispatcher uses the manifest's `scheme` and `ref` fields to route, not the current default.

### Operational notes

- **Token TTL vs request frequency.** AppRole tokens default to 1 hour TTL. The Vault provider lazily re-authenticates when the token expires; pulse-frequency wraps (sub-minute) reuse the same token within its TTL. If your backup cadence is daily and Vault tokens are 1-hour, every backup will issue a fresh login. That's fine.
- **Sealed Vault.** If Vault is sealed (e.g. after a restart), wrap/unwrap fail with `PROVIDER_PROBE_FAILED` whose detail includes the underlying Vault `*sealed*` error. Operators should monitor Vault's seal status separately and surface alerts in the SOC's main monitoring stack — FireAlive will fall over silently otherwise (backups simply fail to wrap).
- **Key rotation.** Rotate the transit key with `vault write -f transit/keys/firealive-backup-kek/rotate`. New backups wrap under the new key version automatically; old backups continue to unwrap under their original version because Vault retains all versions until you explicitly trim with `vault write transit/keys/firealive-backup-kek/config min_decryption_version=N`.
- **Disaster recovery.** Vault snapshots are not encrypted by default; if you snapshot Vault for DR, store the snapshots in the same EU object storage as backups, with their own separate KEK (do not snapshot Vault using Vault to wrap the snapshot — circular dependency).

## Combining: full EU-sovereign stack

```http
POST /api/kms-providers
{
  "name": "vault-prod",
  "provider_type": "hashicorp-vault",
  "config": { "address": "https://vault.eu.example.com:8200", "key_name": "firealive-backup-kek", ... },
  "credentials": { "auth_method": "approle", ... },
  "enabled": true
}
POST /api/kms-providers/<vault-row-id>/set-default

POST /api/backup-destinations
{
  "name": "hetzner-fsn-primary",
  "adapter_type": "s3",
  "config": { "endpoint": "https://fsn1.your-objectstorage.com", "bucket": "firealive-backups", "object_lock_mode": "COMPLIANCE", ... },
  "credentials": { ... },
  "enabled": true
}
```

After both rows are configured and the Vault row is default:

- New backups: ephemeral DEK generated locally → wrapped via Vault transit engine (KEK never leaves Vault) → encrypted archive + wrapped DEK + manifest written to Hetzner with Object Lock retention
- Restore: read from Hetzner → verify manifest signature locally → unwrap DEK via Vault → decrypt archive locally
- The plaintext DEK exists only in FireAlive's process memory during the wrap and unwrap operations
- The KEK never leaves Vault's process memory
- Hetzner sees only opaque ciphertext + opaque wrapped-DEK
- Vault sees only the wrap/unwrap operations, never the plaintext data

A US Cloud Act order served to AWS / Azure / GCP / Cloudflare cannot produce data that exists only in this stack.

## What each provider doesn't have

| Capability                              | Hetzner | OVH | Scaleway | HCP Vault EU | Self-hosted Vault |
|-----------------------------------------|---------|-----|----------|--------------|-------------------|
| EU-only datacenter operations           | Yes     | Yes | Yes      | Yes          | Operator's choice |
| Non-EU corporate ownership              | No      | No  | No       | US (HashiCorp) | n/a              |
| Standard Contractual Clauses available  | n/a     | n/a | n/a      | Yes          | n/a               |
| Object Lock / WORM                      | Yes     | Yes | Yes      | n/a          | n/a               |
| ISO 27001 certified                     | Yes     | Yes | Yes      | Yes          | Operator's burden |
| SOC 2 Type II                           | No      | Yes | Yes      | Yes          | Operator's burden |
| Customer-managed encryption keys (CMEK) | No (use Vault for KEK)  | No  | No       | n/a          | n/a               |
| FIPS 140-2 / 140-3 hardware             | No      | No  | No       | Yes (HCP)    | Yes (HSM-backed)  |

The "non-EU corporate ownership" row matters for HCP Vault: HashiCorp is a US company, so HCP Vault remains subject to the US Cloud Act in principle even when the bytes are in Frankfurt. This is why **self-hosted Vault on EU infrastructure** is the strictest-sovereignty choice. If you accept some US-corporate exposure for the operational simplicity of HCP, document that in your DPIA.

## Migration paths

### From AWS to Hetzner + Vault

1. Stand up Vault, configure transit engine, register as kms_provider, set-default
2. Add Hetzner as a new backup_destination, enabled=true
3. Mark AWS S3 destination as `enabled=false` (do not delete — old backups still need it for restore)
4. New backups use Hetzner + Vault automatically
5. After your operational retention window passes, delete the AWS S3 destination and the AWS KMS kms_provider row only when no extant backup references them

### From env-var KEK to Vault

1. Configure Vault as above
2. POST `/api/kms-providers` with `is_default: true` to atomically swap default
3. New backups wrap under Vault. Old backups stay env-var-wrapped and unwrap fine (manifest tells the dispatcher which to use)
4. Do NOT delete the env-var-default seed row — it's the safety fallback if Vault is unreachable

## Compliance notes

These deployments help with — but do not by themselves achieve — compliance with:

- **GDPR Art. 32** (security of processing): encryption at rest + in transit covered when both the transport (TLS to S3 endpoints, TLS to Vault) and at-rest (DEK-encrypted archive, KEK-wrapped DEK) layers are configured.
- **GDPR Art. 28-29** (processor obligations): the Standard Contractual Clauses (SCCs) in your DPA with Hetzner/OVH/Scaleway are the binding instrument; this technical configuration supports the "supplementary technical measures" required after Schrems II.
- **NIS 2** (operational resilience): Object Lock + multi-region replication address availability requirements; Vault unsealing procedures address recovery requirements; the audit log + restore-approval gate (see `two-person-restore.md`) address integrity.
- **DORA Art. 28-30** (third-party risk): the kms_providers + backup_destinations tables make the third-party inventory explicit and queryable; the audit log records every change.

For each, document the configuration in your ISMS Statement of Applicability and the operational evidence in your audit-trail extract scripts.

## See also

- [`two-person-restore.md`](./two-person-restore.md) — the approval-gate side of restore operations.
- `services/destination-adapter-s3.js` — the S3 adapter implementation used by all three EU object-storage providers.
- `services/destination-adapter-azure-blob.js` — Azure Blob (Microsoft Cloud Germany / EU regions).
- `services/destination-adapter-gcs.js` — GCS (Google Cloud EU regions).
- `services/key-wrapping-providers/hashicorp-vault.js` — the Vault provider implementation.
- `services/key-wrapping-providers/aws-kms.js`, `azure-keyvault.js`, `gcp-kms.js` — alternatives for non-sovereignty-strict deployments.
- `routes/backup-destinations.js`, `routes/kms-providers.js` — admin endpoints used by the recipes above.
- The [European Data Protection Board's recommendations on supplementary measures](https://www.edpb.europa.eu/our-work-tools/our-documents/recommendations/recommendations-012020-measures-supplement-transfer_en).
- The [HashiCorp Vault Transit Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/transit).

## Threat model summary

This configuration mitigates:

1. **Cloud Act access to encrypted archives.** US authorities cannot compel a US provider to disclose data the US provider does not have.
2. **Cloud-credential compromise leading to backup deletion.** Object Lock retention prevents the attacker from deleting prior backups even with full bucket-admin access.
3. **Cloud-credential compromise leading to backup readability.** The wrapped DEK is unreadable without Vault access; even an attacker with full storage access sees only ciphertext.
4. **Vault token compromise.** Limited-TTL AppRole tokens cap the exposure window; the policy restricts the token to wrap/unwrap on one specific transit key.
5. **Cross-region snooping during transfer.** TLS to both S3 endpoint and Vault endpoint.

It does **not** mitigate:

- Compromise of the FireAlive process itself during a wrap or unwrap (plaintext DEK transiently in process memory).
- Compromise of the Vault server (KEK in process memory; recover from Vault snapshot, rotate transit key, re-wrap any backups still in retention).
- Coordinated compromise of FireAlive admin account + Vault AppRole credentials + a member of the approval gate (defense-in-depth across the layers — see `two-person-restore.md`).
- Operator error (wrong region, wrong bucket, expired credentials forgotten in env vars). Operational rigor and the kms_providers probe-on-create are the mitigations.

For these residual risks, the broader hardening guidance in your deployment runbook applies.
