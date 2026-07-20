# CI/CD Pipeline Generation

FireAlive ships a server-side CI/CD pipeline generator that produces SOC-grade pipeline files for four platforms (GitHub Actions, GitLab CI, Jenkins, CircleCI). Each generated pipeline embeds SLSA L3 provenance build, Sigstore Cosign signing, Syft SBOM, Trivy CVE scanning, and the fuse-counter monotonicity check that defends against rollback attacks. This document describes the architecture, the embedded pipeline stages, the webhook reporting model, and the operating procedures.

## Why this exists

Three operator problems motivate the feature:

- **Pipeline drift.** Hand-copied CI YAML from random GitHub gists or vendor blog posts rapidly diverges from what the FireAlive server expects. An operator who customized their pipeline two years ago has no way to know which security stages have been added, removed, or hardened since.
- **No build attestation.** A FireAlive image produced by a downstream fork's CI pipeline has no provenance chain back to a known-good source. Operators who deploy from public registries cannot answer "was this image built with the SLSA L3 settings my threat model assumes?".
- **No fuse-counter enforcement at build time.** R3 introduced the package.json `fuseCounter` field as an anti-rollback control checked at process startup. A CI pipeline that publishes images without verifying that the counter is monotonically advanced from main can silently introduce a rollback window: an attacker who pushes a fork with a lower counter still passes downstream registry checks if those checks rely on tags rather than counter discipline.

The cicd-bundle generator resolves all three by rendering pipeline files server-side from the current FireAlive instance's snapshot, embedding the canonical security stages with no operator option to omit them, and forcing the fuse-counter monotonicity check into every pipeline.

## Architecture overview

The generator lives at two architectural locations:

- **MC-side:** `server/services/cicd-generator.js` (the orchestrator + 4 platform renderers). Routes at `server/routes/cicd.js` mounted at `/api/cicd`.
- **GD-side:** `packages/global-dashboard-server/services/cicd-bundle.js` (consolidated single-file orchestrator + 4 platform renderers, matching the C29 monolithic convention). Routes inlined into `packages/global-dashboard-server/index.js` at `/api/cicd`.

Both sides expose the same `/api/cicd/*` route surface:

```
GET  /api/cicd/platforms                   list platforms + purposes + filenames
POST /api/cicd/generate                    generate a pipeline config
GET  /api/cicd/configs                     list 100 most recent
GET  /api/cicd/configs/:id                 row + parsed install snapshot
GET  /api/cicd/configs/:id/download        stream the pipeline file
POST /api/cicd/runs                        webhook receiver for CI run status
GET  /api/cicd/runs                        list runs
GET  /api/cicd/runs/:id                    row + parsed step results
```

The two surfaces differ in deployment target and in webhook authentication. See "Webhook reporting" below for the auth divergence.

## Supported platforms

Four platforms locked at R3k phase planning (Q4 decision):

| Platform        | Canonical filename                          | Notes                                       |
|-----------------|---------------------------------------------|---------------------------------------------|
| github-actions  | `.github/workflows/firealive-ci.yml`        | Sigstore keyless OIDC default               |
| gitlab-ci       | `.gitlab-ci.yml`                            | Inline Cosign image stage                   |
| jenkins         | `Jenkinsfile`                               | Groovy DSL; declarative pipeline            |
| circleci        | `.circleci/config.yml`                      | Orbs avoided; explicit `run:` steps for portability |

Platform identifiers are kebab-case verbatim — this is the same string used throughout the route surface, the database `platform` column on `cicd_configs`, the webhook receiver's idempotency check, and the frontend tile labels.

## Two operator purposes

Each pipeline is generated for one of two purposes locked at R3k planning:

- **custom-build** — a fork tailored to the operator's organization. Stages embed the operator's deployment placeholders (image registry, secret names) and the pipeline reports run status back to the originating FireAlive instance via webhook.
- **upstream-contribution** — a pipeline targeting the public FireAlive GitHub repo. Reports are not sent back to a private FireAlive instance; the pipeline is suitable for inclusion in a community fork's PR.

The purpose value flows into the rendered pipeline's header comment and influences placeholder names. Future renderers can branch on purpose to apply more substantial differences.

## Embedded pipeline stages

### MC-side: 11 stages

The MC-side pipeline embeds an inline regression-runner invocation (stage 3) that POSTs to the originating MC's `/api/regression/run` endpoint as a build-time integration test:

```
1.  Lint                       ESLint, fails on any error
2.  Test                       npm test
3.  Regression test            curl POST /api/regression/run on the originating MC
4.  npm audit                  --audit-level=moderate (warn-not-fail)
5.  Snyk                       --severity-threshold=high (fail on any HIGH+)
6.  SBOM                       Syft -> SPDX-JSON artifact uploaded
7.  Dep-pin verify             confirm package-lock.json present, deterministic install
8.  Build (SLSA L3)            electron-builder installer; SLSA L3 build provenance
9.  Sign                       Cosign keyless OIDC default; key-based via
                               COSIGN_KEY_MODE=key-based + COSIGN_PRIVATE_KEY
10. CVE scan                   Trivy with HIGH,CRITICAL exit 1
11. Fuse-counter check         compare package.json.fuseCounter against origin/main;
                               fail if rolled back
12. Deploy                     commented placeholder for operator customization
13. Webhook reporter           POST /api/cicd/runs on the originating MC
                               (api-key + cicd:webhook scope)
```

### GD-side: 10 stages

The GD-side pipeline omits the inline regression-runner invocation (stage 3 in MC) because GD's regression runner lives inline in `packages/global-dashboard-server/index.js` rather than as a `require()`-able module — embedding it in CI YAML would require a one-off CLI wrapper that doesn't yet exist. Operators wanting GD regression coverage in CI must run it as a deployed-instance smoke test rather than a build-stage check. A future refactor can extract GD's regression runner into a module and add the stage; deferred.

The fuse-counter check, SBOM, Cosign signature, and SLSA L3 provenance are all present on both sides.

## Webhook reporting

The generated pipeline can POST run status back to the originating FireAlive instance:

```bash
curl -X POST <firealive-url>/api/cicd/runs \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "external_run_id": "<CI platform run id>",
    "platform": "github-actions",
    "config_id": "<optional id from /api/cicd/configs>",
    "status": "passed",
    "started_at": "<ISO 8601>",
    "finished_at": "<ISO 8601>",
    "commit_sha": "<sha>",
    "branch": "<branch>",
    "step_results": [{"stage": "lint", "status": "passed"}, ...],
    "ci_metadata": {"runner": "ubuntu-latest", ...}
  }'
```

### Idempotency

The receiver enforces UNIQUE on `(platform, external_run_id)` in the `cicd_runs` table. On retry (CI platforms commonly retry webhook POSTs on receiver 5xx), the insert catches `SQLITE_CONSTRAINT_UNIQUE`, looks up the existing row, and returns:

```json
{"received": true, "idempotent": true, "run_id": 42, "received_at": "2026-05-17T12:00:00Z"}
```

This makes the webhook receiver safe to retry without producing duplicate rows or duplicate audit events.

### Auth divergence: MC vs GD

**MC-side** uses the existing dual-auth pattern from `middleware/auth.js`:

- Admin JWT for human-facing endpoints (POST /generate, GET /configs, GET /configs/:id, GET /configs/:id/download, GET /runs, GET /runs/:id).
- API-key with `cicd:webhook` scope for the webhook receiver (POST /runs). This is the only endpoint that accepts api-keys — every other endpoint rejects api-keys at the route handler via `requireJwtAdmin`.

API-keys are managed via the existing `/api/api-keys` CRUD surface. Operators create a dedicated api-key with only the `cicd:webhook` scope, configure their CI platform secrets to send it as the `Authorization: Bearer <key>` header, and rotate it on the org's standard cadence.

**GD-side** has no general api-key infrastructure (the "api keys" on `management_consoles.api_key` are MC-to-GD ingest body fields, not header auth for arbitrary endpoints). Rather than build api-key + scope infrastructure for one webhook receiver, GD uses a shared-secret header model:

```
X-CICD-Webhook-Secret: <secret>
```

The secret is auto-generated on first `/api/cicd/webhook-secret` reveal, stored in the `config` table as `cicd_webhook_secret`, and constant-time-compared on every POST /runs request. CISO can reveal the current secret (`GET /api/cicd/webhook-secret`) or rotate it (`POST /api/cicd/webhook-secret/rotate`). Rotation invalidates the old secret immediately; CI pipelines must be re-issued with the new value.

The two auth models produce identical user-facing behavior — a CI pipeline configured with the right credential POSTs to `/api/cicd/runs` and the run lands in `cicd_runs`. The choice of model matches each side's existing auth posture rather than expanding it.

## Operating the feature

### From the MC frontend

The CI/CD tab (under the Infrastructure section) shows a workflow:

1. Click one of the **4 platform tiles**: GitHub Actions, GitLab CI, Jenkins, CircleCI.
2. Select **Purpose**: custom-build or upstream-contribution.
3. Click **Generate Pipeline**. Server pipeline runs (typically <1 second).
4. On success, a result card appears with the config id, the canonical pipeline path in your repo (e.g. `.github/workflows/firealive-ci.yml`), and a **Download pipeline file** button.
5. Two reference cards below explain (a) the 11 embedded stages and (b) the webhook reporting contract.

### From the GD frontend

Same workflow under GD's Cloud & IaC tab → CI/CD Pipeline card. Bundles target the GD-server image rather than the MC-server image. 10 stages rather than 11 (no inline regression-runner invocation).

### From the API directly

```bash
curl -X POST https://<firealive-host>/api/cicd/generate \
  -H "Authorization: Bearer <admin JWT>" \
  -H "Content-Type: application/json" \
  -d '{"platform": "github-actions", "purpose": "custom-build"}'
```

Success response:

```json
{
  "id": "abc123def456",
  "platform": "github-actions",
  "purpose": "custom-build",
  "pipeline_path": "/path/to/data/cicd-configs/abc123.../firealive-ci.yml",
  "pipeline_relative_path": ".github/workflows/firealive-ci.yml",
  "readme_path": "/path/to/data/cicd-configs/abc123.../README.md",
  "bundle_dir": "/path/to/data/cicd-configs/abc123.../",
  "generated_at": "2026-05-17T12:00:00Z",
  "install_snapshot": { ... }
}
```

The operator commits the file at `pipeline_relative_path` to their repo, configures the required CI secrets per the README, and triggers the pipeline. The webhook reporter automatically POSTs status to `/api/cicd/runs` if the operator has configured the optional `FIREALIVE_WEBHOOK_URL` + `FIREALIVE_WEBHOOK_TOKEN` (MC) or `FIREALIVE_GD_WEBHOOK_URL` + `FIREALIVE_GD_WEBHOOK_TOKEN` (GD) secrets.

## Audit trail

| Event | Severity | Detail |
|-------|----------|--------|
| `CICD_CONFIG_GENERATED` | info | `id=<config> platform=<p> purpose=<u>` |
| `CICD_CONFIG_FAILED` | warning | `platform=<p> purpose=<u> error=<first200chars>` |
| `CICD_WEBHOOK_SECRET_REVEALED` (GD-only) | info | `CISO revealed CICD webhook secret` |
| `CICD_WEBHOOK_SECRET_ROTATED` (GD-only) | info | `CISO rotated CICD webhook secret` |

Webhook receiver inserts into `cicd_runs` but does not write an `audit_log` row — runs are voluminous and are queryable from `cicd_runs` directly.

## Storage and retention

Generated pipelines live under `data/cicd-configs/<id>/` on the FireAlive host:

```
data/cicd-configs/
  abc123def456.../
    firealive-ci.yml       ← the platform-canonical filename
    README.md              ← deploy path, required CI secrets, embedded stage docs
```

The `generated_yaml_path` column on `cicd_configs` is an absolute filesystem path. If the file is manually deleted, the row remains (preserving history) but the download endpoint returns **HTTP 410 Gone**.

`cicd_runs` rows accumulate as CI pipelines report status. There is no automatic pruning; operators can manually DELETE old runs via direct DB access if storage pressure warrants. The composite UNIQUE on `(platform, external_run_id)` makes deduplication automatic during ingest.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Operator omits security stages | Stages are baked into the renderer; operators cannot configure them away |
| Operator pushes rolled-back commit | Fuse-counter check fails the pipeline on any decrement |
| Stolen webhook credential floods `cicd_runs` | api-key scope is `cicd:webhook` only (cannot do anything else); GD's shared secret is rotatable in O(1); composite UNIQUE prevents duplicate rows |
| CI runner compromise produces unsigned image | Cosign sign stage fails the pipeline if the runner doesn't have the key; image cannot be pushed without a signature |
| CVE introduced in build | Trivy stage fails the pipeline on HIGH/CRITICAL |
| Lateral movement via webhook auth | Webhook endpoint accepts only valid scope/secret; rejects everything else with 403 |

## Related documents

- `docs/cloud-iac-generation.md` — sibling feature for cloud deployment bundles (same SBOM + Cosign infrastructure)
- `docs/full-suite-backup.md` — sibling feature for full-suite backup archives
