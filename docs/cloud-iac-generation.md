# Cloud & IaC Bundle Generation

FireAlive ships a server-side cloud-deployment-bundle generator that produces signed, SBOM-attested infrastructure-as-code packages for three cloud providers (AWS, Azure, and GCP) across five IaC formats. This document describes the architecture, the signing pipeline, the operating procedures, and the offline verification workflow.

## Why this exists

Operators deploying FireAlive into a new cloud environment historically faced three problems:

- **Template drift.** Hand-written Terraform, Pulumi, or CloudFormation files in random GitHub gists rarely match the version of FireAlive being deployed. Operators paste a config from a year ago and silently lose a security control that the current server expects.
- **No supply-chain attestation.** Downloading an IaC bundle from a vendor's website is a download without provenance. There is no way to verify that the bundle was produced by the operator's own FireAlive instance versus altered in transit by a CDN compromise or man-in-the-middle.
- **No software bill of materials.** Operators applying a bundle have no machine-readable inventory of what's inside — which package versions, which transitive dependencies — and therefore cannot answer the question "is my deployment vulnerable to CVE-XXXX-YYYY?".

The cloud-iac-bundle generator resolves all three by rendering bundles server-side, attaching a Syft-generated SPDX-JSON SBOM, signing the archive with a server-managed Sigstore Cosign key, and persisting the manifest hash to an audited database row. The bundle a CISO downloads on Monday is the same bytes the auditor verifies on Tuesday, and the signing key fingerprint matches the one published on the FireAlive instance.

## Architecture overview

The generator lives at two architectural locations:

- **MC-side:** `server/services/cloud-iac-generator.js` (the orchestrator), plus 5 template renderer modules under `server/services/cloud-iac-templates/`, plus `server/services/sbom-generator.js`, `server/services/cosign-signer.js`, and `server/services/cloud-iac-signing-keys.js`. Routes are at `server/routes/cloud.js` mounted at `/api/cloud`.
- **GD-side:** `packages/global-dashboard-server/services/cloud-iac-bundle.js` (a consolidated single-file module containing the equivalent orchestrator + 9 renderers + signing-key helpers), plus `packages/global-dashboard-server/services/gd-encryption.js` for the Tier-1 KEK-wrap of stored signing keys. Routes are inlined into `packages/global-dashboard-server/index.js` at `/api/cloud`.

Both sides expose the same `/api/cloud/*` route surface:

```
GET  /api/cloud/providers                  list providers + secrets mapping
POST /api/cloud/package                    generate a bundle
GET  /api/cloud/packages                   list 100 most recent
GET  /api/cloud/packages/:id               row + parsed install snapshot
GET  /api/cloud/packages/:id/download      stream bundle.tar.gz
GET  /api/cloud/packages/:id/public-key    verifier PEM
POST /api/cloud/signing-keys/rotate        operator-triggered rotation
```

The two surfaces differ only in deployment target: MC bundles provision a confidential VM running the Regional Server (port 4000, env vars `JWT_SECRET` + `TIER1_ENCRYPTION_KEY`); GD bundles provision one running the GD Server (port 4001, env vars `GD_JWT_SECRET` + `GD_ENCRYPTION_KEY`). The shape difference is documented inline in each side's bundle module and is centralized in a single `DEPLOY_SHAPE` constant per side.

## The provider × IaC-tool matrix

Three providers, five IaC formats, nine combinations:

| Provider | Terraform | Pulumi | CloudFormation | Bicep | gcp-dm |
|----------|-----------|--------|----------------|-------|--------|
| aws      | ✓         | ✓      | ✓              | —     | —      |
| azure    | ✓         | ✓      | —              | ✓     | —      |
| gcp      | ✓         | ✓      | —              | —     | ✓      |

Provider-specific formats — CloudFormation on AWS, Bicep on Azure, gcp-dm on GCP — produce the cloud-native template format that operators using that cloud's official tooling expect. Terraform and Pulumi produce portable templates that work across all three providers with the same FireAlive deployment.

Every template provisions FireAlive on a **confidential VM** with a vTPM hardware root of trust — an AMD SEV-SNP instance with NitroTPM on AWS, an Azure Confidential VM with Trusted Launch, or a GCP Confidential VM with Shielded VM — and stamps `deployment_mode = cloud`. Confidential computing is required by Cloud Mode and attested at boot. Managed-container compute (ECS Fargate, Azure Container Instances, Cloud Run, Kubernetes, Helm) and the privacy-focused European and Swiss providers (Hetzner, OVHcloud, Exoscale) are no longer emitted by the Regional Server generator: managed-container services do not provide a vTPM or VM-level memory encryption, and no shared-cloud confidential VM is offered by those providers. See docs/cloud-mode.md.

The matrix above describes the MC (Regional Server) generator. The Global Dashboard server runs its own generator; pruning it to this same confidential-VM set is a planned fast-follow, so until then the GD generator still offers the prior provider and format set.

## The signing pipeline

Every generated bundle passes through five stages:

1. **Install snapshot capture.** The server reads the live FireAlive instance's state — version, fuse counter, build id, count of active SIEM integrations, count of active SOAR integrations, configured backup destinations, count of analysts — and serializes it into `version-manifest.json` inside the bundle. The snapshot is for operator reference and as input to the deploy template's placeholder values.

2. **Template rendering.** The orchestrator calls the appropriate `cloud-iac-templates/<tool>.js` renderer with `(provider, snapshot)` and receives a string containing the rendered IaC text. Renderers are pure functions of input — no shell-outs, no filesystem reads, no clock-dependent behavior beyond the snapshot's `captured_at`. This makes bundle output reproducible: given the same FireAlive state, the same `(provider, tool)` produces byte-identical templates.

3. **SBOM attestation.** `sbom-generator.js` shells out to Syft (`syft . -o spdx-json=sbom.spdx.json`). If Syft is not installed on the FireAlive host, the generator throws `SyftNotInstalledError` and the route handler maps it to **HTTP 503 with code `SYFT_NOT_INSTALLED`** and an actionable install command in the error message. There is no soft-fail path — a bundle without an SBOM is rejected by design. This implements the "SBOM-or-503" decision from R3k phase planning.

4. **Cosign signature.** `cosign-signer.js` shells out to Cosign with a server-managed signing key from `cloud_iac_signing_keys`. The signature is written to `bundle.tar.gz.sig`. Like Syft, a missing Cosign installation produces **HTTP 503 with code `COSIGN_NOT_INSTALLED`** — no soft-fail. The signing key is Sigstore-compatible and verifies offline with the standard `cosign verify-blob` command (see below).

5. **Bundle assembly and persistence.** The orchestrator tars the IaC file + README + `version-manifest.json` + `sbom.spdx.json` into `bundle.tar.gz`, signs it (step 4), computes SHA-256 hashes for the manifest, SBOM, and signature, and inserts a row into the `cloud_packages` table. The row records every hash, the path to the archive on disk, the signing key fingerprint, the size, and a JSON serialization of the install snapshot. Operators can list past bundles via `GET /api/cloud/packages` and re-download or re-verify any historical package.

## Signing-key lifecycle

The `cloud_iac_signing_keys` table holds the Sigstore-format private keys (Ed25519) used to sign bundles. Each row has:

- `id` (16-hex-char unique id)
- `algorithm` (currently always `Ed25519`)
- `public_key_pem` (the verifier key, distributed alongside bundles)
- `private_key_wrapped` (the signing key, AES-256-GCM-wrapped by the Tier-1 KEK)
- `status` (`active`, `rotated`, or `revoked`)
- `created_at`, `rotated_at`

At most one row has `status='active'` at any time. New bundles use the active key. Rotated and revoked keys remain in the table indefinitely so historical bundles remain verifiable — the `GET /api/cloud/packages/:id/public-key` endpoint resolves the key id stored on each `cloud_packages` row regardless of current status.

### Rotation procedure

```
POST /api/cloud/signing-keys/rotate
Authorization: Bearer <admin JWT>
```

Atomic via SQLite transaction:

1. Mark the current `active` row as `status='rotated'`, set `rotated_at=now()`.
2. Insert a new row with a freshly-generated Ed25519 keypair, `status='active'`.
3. Return `{rotated: true, oldId, newId}`.

Audit event: `CLOUD_SIGNING_KEY_ROTATED` with both ids in the detail.

Operators should rotate the signing key:

- On a regular schedule (annual or per the org's KMS rotation policy).
- Immediately after any suspicion of key compromise (host breach, audit-log anomaly, suspicious bundle downloads).
- Before publishing a bundle externally (rotate so an external party validating a historical bundle doesn't also implicitly trust later bundles).

There is no "revoke" command in the route surface — revocation is intentionally manual. A CISO who suspects key compromise should rotate (which marks the old key `rotated`), then directly UPDATE the row to `status='revoked'` via the database CLI after confirming the compromise. The `revoked` status is reserved for keys an operator wants downloaders to actively distrust.

## Offline bundle verification

A bundle.tar.gz is verifiable without contacting the FireAlive instance that produced it. The verifier needs three artifacts:

- `bundle.tar.gz` (the bundle itself)
- `bundle.tar.gz.sig` (the Cosign signature, included in the bundle alongside the IaC file at the top level)
- `public-key.pem` (the verifier key, fetched once from `/api/cloud/packages/:id/public-key`)

```bash
cosign verify-blob \
  --key public-key.pem \
  --signature bundle.tar.gz.sig \
  bundle.tar.gz
```

If the signature is valid, `cosign` exits 0 and prints `Verified OK`. If the bundle has been altered in transit, the signature is replaced, or the wrong public key is provided, `cosign` exits non-zero and the verification fails.

An offline auditor can also extract the SBOM independently:

```bash
tar -xzOf bundle.tar.gz sbom.spdx.json | jq '.packages[] | .name + "@" + .versionInfo'
```

This lists every package and version inside the bundle without applying it.

## Operating the feature

### From the MC frontend

The Cloud & IaC tab (under the Infrastructure section) presents a two-card workflow:

1. Select **Cloud Provider** from the 6-option dropdown.
2. Select **IaC Format** from the dropdown filtered by your provider (7 universal formats + 1 provider-specific where applicable).
3. Click **Generate Bundle**. The button disables and displays "Generating bundle..." for the duration of the server pipeline (typically 1-5 seconds depending on host).
4. On success, a result card appears with the package id, size, manifest SHA-256, signing key fingerprint, **Download bundle.tar.gz** button, and **View public key** button.
5. On failure (503 from Syft or Cosign not being installed), the result card surfaces the error code and the install command. Install the missing binary on the FireAlive host and retry.

### From the GD frontend

The Cloud & IaC tab in the global dashboard exposes the same workflow against the GD-server (rather than the MC-server). Bundles generated here target the GD deployment shape (the GD Server, port 4001, env vars `GD_JWT_SECRET` + `GD_ENCRYPTION_KEY`). The CISO uses this tab when deploying or relocating the global dashboard itself.

Note that GD's `api.post` helper drops the response JSON body on non-OK HTTP status, so the failure card surfaces only `r.statusText` rather than the structured `code` + `message`. This is a known limitation of the GD frontend's helper, documented in the C40 commit.

### From the API directly

```bash
curl -X POST https://<firealive-host>/api/cloud/package \
  -H "Authorization: Bearer <admin JWT>" \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "iac_tool": "terraform"}'
```

Success response:

```json
{
  "id": "9c8d3f2e1a7b6c5d",
  "provider": "aws",
  "iac_tool": "terraform",
  "generated_at": "2026-05-17T12:00:00Z",
  "bundle_archive_path": "/path/to/data/cloud-packages/9c8d3f2e.../bundle.tar.gz",
  "manifest_sha256": "abc123...",
  "sbom_sha256": "def456...",
  "signature_sha256": "789xyz...",
  "size_bytes": 524288,
  "signing_key_id": "1234abcd5678efgh",
  "signing_key_fingerprint": "SHA256:..."
}
```

Failure response (503 example):

```json
{
  "error": "Syft not installed",
  "message": "Install Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0",
  "code": "SYFT_NOT_INSTALLED"
}
```

## Audit trail

Every bundle generation writes one of two audit events to `audit_log`:

- `CLOUD_PACKAGE_GENERATED` (severity `info`) on success, detail `id=<pkg> provider=<p> iac_tool=<t> size=<bytes> manifestSha=<first16hex>`.
- `CLOUD_PACKAGE_FAILED` (severity `warning`) on failure, detail `provider=<p> iac_tool=<t> error=<first200chars>`.

Signing-key rotation events:

- `CLOUD_SIGNING_KEY_ROTATED` (severity `info`) on rotation, detail `oldId=<id> newId=<id>`.

These events are queryable from the standard audit log surface and persist for the configured audit retention period.

## Storage and retention

Generated bundles live under `data/cloud-packages/<id>/` on the FireAlive host:

```
data/cloud-packages/
  9c8d3f2e1a7b6c5d/
    bundle.tar.gz          ← signed archive
    bundle.tar.gz.sig      ← Cosign signature (also embedded in archive)
    public-key.pem         ← copy of the signing key's public PEM (also retrievable via API)
```

The `bundle_archive_path` column on `cloud_packages` is an absolute filesystem path. If an operator manually deletes a bundle's directory, the row remains in the database (preserving audit history) but the download endpoint returns **HTTP 410 Gone** with `error: "bundle archive no longer on disk"`.

There is no automatic retention policy applied to cloud bundles — they are operator-curated artifacts. The recommended operational pattern is to retain bundles indefinitely for audit and reproducibility, but operators with strict storage constraints can periodically clear `data/cloud-packages/<id>/` directories for bundles older than their internal retention threshold.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Bundle altered in transit (CDN compromise, MITM) | Cosign signature verifies offline against the published public key |
| Server-side template tampering | Templates are pure functions of the install snapshot; SBOM captures every package |
| Signing key compromise | Rotate via `POST /api/cloud/signing-keys/rotate`; revoke compromised keys via direct DB UPDATE; old bundles signed by the revoked key fail verification with the revoked PEM |
| Stolen bundle replay | Each bundle has a unique manifest SHA-256 and is bound to a specific install snapshot; the version-manifest.json identifies the source FireAlive instance |
| Missing SBOM (operator can't audit deps) | SBOM is mandatory; missing Syft fails generation with 503 rather than producing an unattested bundle |
| Missing signature (operator can't verify) | Signature is mandatory; missing Cosign fails generation with 503 rather than producing an unsigned bundle |

## Related documents

- `docs/cicd-generation.md` — sibling feature for CI/CD pipeline generation (same signing model, different output)
- `docs/full-suite-backup.md` — sibling feature for full-suite backup archives (overlapping signing infrastructure)
- `docs/two-person-restore.md` — the destructive-operation gate that protects against restoring an arbitrary backup over the live database
