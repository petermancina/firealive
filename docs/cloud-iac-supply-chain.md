# Cloud & IaC Generation — Supply-Chain Prerequisites

This document lists the supply-chain tooling the Cloud & IaC generator depends
on, the exact pinned versions FireAlive expects, and how to install them. It is
the reference pointed to by the `SYFT_NOT_INSTALLED` and `COSIGN_NOT_INSTALLED`
error messages raised by `server/services/sbom-generator.js` and
`server/services/cosign-signer.js`.

FireAlive treats the software supply chain as a hard requirement, not a
best-effort add-on. Two principles drive everything below:

- **No soft-fallback.** A generated bundle must carry a real Syft SBOM and a
  real Sigstore (Cosign) signature. If either tool is absent, the request fails
  closed with an actionable HTTP 503 rather than emitting a weaker or unsigned
  artifact.
- **Pinned, immutable versions.** Every tool is pinned to a specific release —
  never `releases/latest` or a `main`-branch install script — so a build is
  reproducible and the install surface cannot shift underneath an operator.

## Pinned versions

| Tool   | Version  | Where it runs                    | Purpose                          |
|--------|----------|----------------------------------|----------------------------------|
| Syft   | v1.44.0  | FireAlive host (runtime)         | SBOM generation (SPDX JSON)      |
| Cosign | v3.0.6   | FireAlive host (runtime)         | Sigstore signature on the bundle |
| Grype  | v0.110.0 | Generated CI/CD pipeline         | CVE scan of the SBOM             |

Syft and Cosign run on the FireAlive host at request time. Grype runs inside the
CI/CD pipeline that the generator emits, not on the FireAlive host itself.

## FireAlive host prerequisites (runtime)

These two binaries must be installed on the host running the FireAlive server
and present on its `PATH`. Both are invoked with `execFileSync` and a fixed
argument vector (no shell), and each is gated by a `which` probe so a missing
tool produces a clean 503 instead of a runtime crash.

### Syft v1.44.0 — SBOM generation

`sbom-generator.js` shells out to Syft to produce an SPDX-JSON SBOM
(`syft . -o spdx-json=<path>`). There is no soft-fail path: a bundle without an
SBOM is rejected by design ("SBOM-or-503"). If `which syft` fails, the generator
throws `SyftNotInstalledError`, which the route handler maps to **HTTP 503 with
code `SYFT_NOT_INSTALLED`**.

Install (pinned):

```
curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0
```

### Cosign v3.0.6 — Sigstore signature

`cosign-signer.js` calls `signBlob()` during bundle assembly to produce a
Sigstore-compatible signature over the output archive. The service refuses to
fall back to any non-Sigstore signing path. If `which cosign` fails, it throws
`CosignNotInstalledError`, mapped to **HTTP 503 with code
`COSIGN_NOT_INSTALLED`**.

Install (pinned):

```
curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign
```

## Generated CI/CD pipeline tools

The pipeline configurations emitted by the Cloud & IaC generator (GitHub
Actions, GitLab CI, Jenkins, and CircleCI) run their own pinned supply-chain
steps: Syft (SBOM), Grype (CVE scan of that SBOM), and Cosign (attestation).
These run in CI, so they are installed by the generated pipeline rather than
provisioned on the FireAlive host.

CVE scanning is standardized on Grype, which pairs directly with the Syft SBOM
already produced in the pipeline — one coherent Anchore toolchain with no
third-party scanning action in the path. The generated steps pin every tool to
an immutable version, with no `main`, `@master`, or `:latest` references.

Grype (pinned), as emitted for script-based runners:

```
curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0
```

For container-based runners the generator pins the image instead:

```
anchore/grype:v0.110.0
```

## Verifying an installation

After installing the host tools, confirm both resolve on `PATH` and report the
expected versions:

```
which syft && syft version
which cosign && cosign version
```

If a generated bundle request returns `503 SYFT_NOT_INSTALLED` or
`503 COSIGN_NOT_INSTALLED`, the corresponding binary is either not installed or
not on the `PATH` of the FireAlive server process — re-check using the commands
above under the same user and environment the server runs as.

## Why pinning matters

Pinning to immutable release versions (rather than `releases/latest` or a
`main`-branch install script) keeps builds reproducible and prevents the install
surface from changing without an explicit, reviewed version bump. When upgrading
a tool, change the version in one place per generator and in the host install
commands above, then re-verify end to end.
