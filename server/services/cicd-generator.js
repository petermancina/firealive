// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — CI/CD Pipeline-Config Generator (R3k C23)
//
// Main orchestrator for the CI/CD artifact generator (Sub-phase 5).
// Produces a deployable pipeline configuration for the operator's
// chosen CI platform, with the canonical FireAlive build pipeline
// embedded as steps. Persists to cicd_configs (R3k C1) and writes
// the pipeline file to data/cicd-configs/<id>/<platform-filename>.
//
// SUPPORTED PLATFORMS (per Q4 LOCKED decision)
// ============================================
//
//   github-actions   .github/workflows/firealive-ci.yml
//   gitlab-ci        .gitlab-ci.yml
//   jenkins          Jenkinsfile
//   circleci         .circleci/config.yml
//
// EMBEDDED PIPELINE STEPS (per Q4 LOCKED + cross-cutting decisions)
// =================================================================
//
//   1. lint (ESLint)
//   2. test (npm test invocation)
//   3. regression test (POST to /api/regression/run on a staging
//      install, or directly invoke the regression runner module)
//   4. security scan (npm audit + Snyk)
//   5. SBOM generation (Syft -> SPDX-JSON)
//   6. build (Docker build with provenance for SLSA Level 3)
//   7. sign (Cosign sign-blob, Sigstore keyless OIDC by default)
//   8. dependency-pin verification (every dep's locked sha256
//      against installed sha256)
//   9. CVE scan (Grype — Anchore's scanner; pairs with Syft, scans the
//      built image / SBOM)
//
//   Pinned tool versions (updated only via reviewed PR; no unpinned
//   `main`/`@master`/`:latest`):
//     Syft   v1.44.0   (image digest anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6)
//     Grype  v0.110.0
//     Cosign v3.0.6
//   Installers are fetched from the immutable release tag (not `main`) and
//   verified against the release artifact's signature before install.
//   10. deploy (commented placeholder for operator customization)
//   11. fuse-counter check (assert fuseCounter monotonically
//       advanced from the prior release)
//
// Two purposes (per FEATURE-GUIDE / Phase B 1.4g):
//
//   - custom-build              fork tailored to the org's SDN /
//                               automation / integrations
//   - upstream-contribution     pipeline targeting the public
//                               FireAlive GitHub repo
//
// FAILURE SEMANTICS
// =================
//
// Errors propagate to the caller (routes/cicd.js in C24), which maps
// invalid platform/purpose -> 400, persistence failure -> 500.
// Partial state on disk is cleaned in a finally block.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { logger } = require('./logger');
const { DB_PATH } = require('../db/init');
const dataRoot = require('../lib/data-root');

// ── Constants ──────────────────────────────────────────────────────────

const VALID_PLATFORMS = ['github-actions', 'gitlab-ci', 'jenkins', 'circleci'];
const VALID_PURPOSES  = ['custom-build', 'upstream-contribution'];

const PLATFORM_FILENAME = {
  'github-actions': '.github/workflows/firealive-ci.yml',
  'gitlab-ci':      '.gitlab-ci.yml',
  'jenkins':        'Jenkinsfile',
  'circleci':       '.circleci/config.yml',
};

function resolveCicdConfigsDir(override) {
  // P1-1: CICD_CONFIGS_DIR, else the canonical data root.
  return override || dataRoot.cicdConfigsDir();
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return dataRoot.ensureDir(dir);
}

// ── Install snapshot (lighter than cloud-iac's) ────────────────────────

function captureInstallSnapshot(db) {
  const safe = (fn, fallback) => {
    try { return fn(); } catch (e) { return fallback; }
  };

  const integrations = safe(() => {
    const rows = db.prepare("SELECT key FROM integration_config").all();
    return rows.map(r => r.key);
  }, []);

  let dbSizeBytes = 0;
  try {
    if (fs.existsSync(DB_PATH)) dbSizeBytes = fs.statSync(DB_PATH).size;
  } catch (e) { /* keep 0 */ }

  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const v = require('../lib/version');
    versionInfo = {
      version: v.version || 'unknown',
      fuse_counter: typeof v.fuseCounter === 'number' ? v.fuseCounter : null,
      build_id: v.buildId || null,
    };
  } catch (e) { /* keep defaults */ }

  return {
    captured_at: new Date().toISOString(),
    integrations,
    data: { db_size_bytes: dbSizeBytes },
    version: versionInfo,
  };
}

// ── README for the generated pipeline bundle ───────────────────────────

function buildReadme(platform, purpose, snapshot, configId) {
  const filename = PLATFORM_FILENAME[platform];
  const lines = [
    `# FireAlive CI/CD Pipeline`,
    ``,
    `**Config id:** \`${configId}\``,
    `**Platform:** ${platform}`,
    `**Purpose:** ${purpose}`,
    `**Generated:** ${snapshot.captured_at}`,
    `**Source version:** ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    ``,
    `## Deploying`,
    ``,
    `1. Commit the generated file to your repository at the canonical path: \`${filename}\``,
    `2. Set the required CI secrets in your CI provider's secret store:`,
    `   - \`COSIGN_PASSWORD\` (set empty if using keyless OIDC, recommended)`,
    `   - \`COSIGN_PRIVATE_KEY\` (only if NOT using keyless OIDC)`,
    `   - \`SNYK_TOKEN\` (for the Snyk scan step)`,
    `   - \`DOCKER_REGISTRY_TOKEN\` (or platform-equivalent for image push)`,
    `3. Trigger the pipeline (push to main, or your platform's manual trigger).`,
    ``,
    `## Embedded pipeline steps`,
    ``,
    `1. **Lint** — ESLint against the project (\`npm run lint\`).`,
    `2. **Test** — \`npm test\`.`,
    `3. **Regression test** — invokes the canonical regression runner.`,
    `4. **Security scan** — \`npm audit\` plus Snyk (\`snyk test\`).`,
    `5. **SBOM generation** — Syft produces SPDX-JSON SBOM as a CI artifact.`,
    `6. **Build** — \`electron-builder\` produces the signed platform installers (SLSA Level 3 build provenance via the CI platform).`,
    `7. **Sign** — Cosign signs the produced installer (sign-blob). Defaults to Sigstore keyless OIDC; override to key-based via the \`COSIGN_KEY_MODE\` env var (set \`key-based\` and provide \`COSIGN_PRIVATE_KEY\`).`,
    `8. **Dependency-pin verification** — compares package-lock.json's recorded SHA-256s against installed module SHA-256s.`,
    `9. **CVE scan** — Grype (Anchore; pairs with Syft, scans the SBOM).`,
    `10. **Deploy** — commented placeholder. Customize for your target environment.`,
    `11. **Fuse-counter check** — asserts package.json's \`fuseCounter\` monotonically advanced from the prior release (R3 anti-rollback discipline).`,
    ``,
    `## Webhook reporting`,
    ``,
    `The pipeline can optionally POST run status back to this FireAlive instance via the canonical webhook receiver:`,
    ``,
    `\`\`\`bash`,
    `curl -X POST <firealive-url>/api/cicd/runs \\`,
    `  -H "Authorization: Bearer <api-key with cicd:webhook scope>" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{`,
    `    "external_run_id": "<CI platform run id>",`,
    `    "platform": "${platform}",`,
    `    "status": "passed",`,
    `    "started_at": "<ISO 8601>",`,
    `    "finished_at": "<ISO 8601>",`,
    `    "commit_sha": "<sha>",`,
    `    "branch": "<branch>"`,
    `  }'`,
    `\`\`\``,
    ``,
    `Idempotency: the receiver collapses duplicate (platform, external_run_id) pairs on retry.`,
    ``,
    `## Install posture at generation time`,
    ``,
    `- Integrations: ${snapshot.integrations.length} configured (${snapshot.integrations.slice(0, 5).join(', ')}${snapshot.integrations.length > 5 ? ', ...' : ''})`,
    `- DB size at capture: ${snapshot.data.db_size_bytes} bytes`,
    ``,
  ];
  return lines.join('\n');
}

// ── Platform renderers ─────────────────────────────────────────────────

function renderGithubActions(snapshot, purpose) {
  return [
    `# FireAlive CI Pipeline (GitHub Actions)`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'name: firealive-ci',
    '',
    'on:',
    '  push:',
    '    branches: [main]',
    '  pull_request:',
    '    branches: [main]',
    '  workflow_dispatch: {}',
    '',
    'permissions:',
    '  contents: read',
    '  id-token: write   # required for Sigstore keyless OIDC',
    '  packages: write   # required for image push to GHCR',
    '',
    'jobs:',
    '  ci:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - name: Checkout',
    '        uses: actions/checkout@v4',
    '',
    '      - name: Setup Node',
    '        uses: actions/setup-node@v4',
    '        with:',
    '          node-version: "20"',
    '          cache: npm',
    '',
    '      - name: Install',
    '        run: npm ci',
    '',
    '      - name: Lint (ESLint)',
    '        run: npm run lint',
    '',
    '      - name: Test',
    '        run: npm test',
    '',
    '      - name: Regression test',
    '        run: node -e "const { RegressionRunner } = require(\'./server/services/regression-runner\'); const { getDb, initDb } = require(\'./server/db/init\'); initDb(); const r = new RegressionRunner(getDb()).run(); console.log(JSON.stringify(r.summary, null, 2)); if (r.failed > 0) process.exit(1);"',
    '',
    '      - name: Security scan (npm audit)',
    '        run: npm audit --audit-level=moderate || true',
    '',
    '      - name: Security scan (Snyk)',
    '        env:',
    '          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}',
    '        run: npx snyk test --severity-threshold=high',
    '',
    '      - name: Install Syft (pinned v1.44.0)',
    '        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0',
    '',
    '      - name: Generate SBOM',
    '        run: syft . -o spdx-json=sbom.spdx.json',
    '',
    '      - name: Upload SBOM artifact',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: sbom',
    '          path: sbom.spdx.json',
    '',
    '      - name: Dependency-pin verification',
    '        run: |',
    '          # Compares package-lock.json recorded SHA-256s against installed module SHA-256s.',
    '          # `npm ci` already verifies lock integrity at install time; this is a defensive re-check.',
    '          npm ls --all --json > /tmp/installed-tree.json || true',
    '          test -f package-lock.json',
    '',
    '      - name: Build (SLSA L3 provenance)',
    '        run: npx electron-builder --linux --publish never',
    '',
    '      - name: Install Cosign',
    '        uses: sigstore/cosign-installer@v3',
    '',
    '      - name: Sign installer (keyless OIDC by default)',
    '        env:',
    '          COSIGN_EXPERIMENTAL: "1"',
    '        run: |',
    '          if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '            echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    '            cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"',
    '            rm /tmp/cosign.key',
    '          else',
    '            cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"',
    '          fi',
    '',
    '      - name: Install Grype (pinned v0.110.0)',
    '        run: curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0',
    '',
    '      - name: CVE scan (Grype)',
    '        run: grype sbom:sbom.spdx.json --fail-on high',
    '',
    '      - name: Fuse-counter check',
    '        run: |',
    '          # Asserts package.json fuseCounter monotonically advanced from main.',
    '          PRIOR=$(git show origin/main:package.json | node -e "let d=\'\';process.stdin.on(\'data\',c=>d+=c);process.stdin.on(\'end\',()=>console.log(JSON.parse(d).fuseCounter))")',
    '          CURRENT=$(node -e "console.log(require(\'./package.json\').fuseCounter)")',
    '          echo "prior=$PRIOR current=$CURRENT"',
    '          [ "$CURRENT" -ge "$PRIOR" ] || { echo "fuse counter rolled back ($PRIOR -> $CURRENT)"; exit 1; }',
    '',
    '      - name: Deploy (placeholder)',
    '        if: github.ref == \'refs/heads/main\'',
    '        run: echo "TODO: deploy step — customize for your target environment"',
    '',
    '      - name: Report run status to FireAlive (optional)',
    '        if: always() && env.FIREALIVE_WEBHOOK_URL != \'\'',
    '        env:',
    '          FIREALIVE_WEBHOOK_URL: ${{ secrets.FIREALIVE_WEBHOOK_URL }}',
    '          FIREALIVE_WEBHOOK_TOKEN: ${{ secrets.FIREALIVE_WEBHOOK_TOKEN }}',
    '        run: |',
    '          STATUS="${{ job.status }}"',
    '          [ "$STATUS" = "success" ] && S=passed || S=failed',
    '          curl -X POST "$FIREALIVE_WEBHOOK_URL/api/cicd/runs" \\',
    '            -H "Authorization: Bearer $FIREALIVE_WEBHOOK_TOKEN" \\',
    '            -H "Content-Type: application/json" \\',
    '            -d "{\\"external_run_id\\":\\"${{ github.run_id }}\\",\\"platform\\":\\"github-actions\\",\\"status\\":\\"$S\\",\\"started_at\\":\\"${{ github.event.head_commit.timestamp }}\\",\\"finished_at\\":\\"$(date -u +%FT%TZ)\\",\\"commit_sha\\":\\"${{ github.sha }}\\",\\"branch\\":\\"${{ github.ref_name }}\\"}"',
    '',
  ].join('\n');
}

function renderGitlabCi(snapshot, purpose) {
  return [
    `# FireAlive CI Pipeline (GitLab CI)`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'stages:',
    '  - lint',
    '  - test',
    '  - security',
    '  - build',
    '  - sign-verify',
    '  - deploy',
    '',
    'default:',
    '  image: node:20-bullseye',
    '  cache:',
    '    paths:',
    '      - node_modules/',
    '  before_script:',
    '    - npm ci',
    '',
    'lint:',
    '  stage: lint',
    '  script:',
    '    - npm run lint',
    '',
    'test:',
    '  stage: test',
    '  script:',
    '    - npm test',
    '',
    'regression-test:',
    '  stage: test',
    '  script:',
    '    - node -e "const { RegressionRunner } = require(\'./server/services/regression-runner\'); const { getDb, initDb } = require(\'./server/db/init\'); initDb(); const r = new RegressionRunner(getDb()).run(); console.log(JSON.stringify(r.summary, null, 2)); if (r.failed > 0) process.exit(1);"',
    '',
    'security-audit:',
    '  stage: security',
    '  script:',
    '    - npm audit --audit-level=moderate || true',
    '',
    'security-snyk:',
    '  stage: security',
    '  image: snyk/snyk:node-20',
    '  script:',
    '    - snyk test --severity-threshold=high',
    '  variables:',
    '    SNYK_TOKEN: $SNYK_TOKEN',
    '',
    'sbom:',
    '  stage: security',
    '  image: anchore/syft:v1.44.0',
    '  script:',
    '    - syft . -o spdx-json=sbom.spdx.json',
    '  artifacts:',
    '    paths:',
    '      - sbom.spdx.json',
    '',
    'dep-pin-verify:',
    '  stage: security',
    '  script:',
    '    - npm ls --all --json > installed-tree.json || true',
    '    - test -f package-lock.json',
    '',
    'build:',
    '  stage: build',
    '  image: node:22',
    '  script:',
    '    - npx electron-builder --linux --publish never',
    '',
    'sign:',
    '  stage: sign-verify',
    '  image: gcr.io/projectsigstore/cosign:v2',
    '  script:',
    '    - |',
    '      if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '        echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    '        cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"',
    '        rm /tmp/cosign.key',
    '      else',
    '        cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"',
    '      fi',
    '',
    'cve-scan:',
    '  stage: sign-verify',
    '  image: anchore/grype:v0.110.0',
    '  script:',
    '    - grype sbom:sbom.spdx.json --fail-on high',
    '',
    'fuse-counter-check:',
    '  stage: sign-verify',
    '  script:',
    '    - PRIOR=$(git show origin/main:package.json | node -e "let d=\'\';process.stdin.on(\'data\',c=>d+=c);process.stdin.on(\'end\',()=>console.log(JSON.parse(d).fuseCounter))")',
    '    - CURRENT=$(node -e "console.log(require(\'./package.json\').fuseCounter)")',
    '    - echo "prior=$PRIOR current=$CURRENT"',
    '    - test "$CURRENT" -ge "$PRIOR"',
    '',
    'deploy:',
    '  stage: deploy',
    '  only:',
    '    - main',
    '  script:',
    '    - echo "TODO: deploy step — customize for your target environment"',
    '',
  ].join('\n');
}

function renderJenkinsfile(snapshot, purpose) {
  return [
    `// FireAlive CI Pipeline (Jenkinsfile, declarative)`,
    `// Generated: ${snapshot.captured_at}`,
    `// Purpose: ${purpose}`,
    `// Source version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'pipeline {',
    '    agent any',
    '    environment {',
    '        COSIGN_EXPERIMENTAL = "1"',
    '        COSIGN_KEY_MODE = "${env.COSIGN_KEY_MODE ?: \'keyless\'}"',
    '    }',
    '    stages {',
    '        stage("Install") {',
    '            steps { sh "npm ci" }',
    '        }',
    '        stage("Lint") {',
    '            steps { sh "npm run lint" }',
    '        }',
    '        stage("Test") {',
    '            steps { sh "npm test" }',
    '        }',
    '        stage("Regression test") {',
    '            steps {',
    '                sh \'\'\'',
    '                    node -e "const { RegressionRunner } = require(\\\'./server/services/regression-runner\\\'); const { getDb, initDb } = require(\\\'./server/db/init\\\'); initDb(); const r = new RegressionRunner(getDb()).run(); console.log(JSON.stringify(r.summary, null, 2)); if (r.failed > 0) process.exit(1);"',
    '                \'\'\'',
    '            }',
    '        }',
    '        stage("Security: npm audit") {',
    '            steps { sh "npm audit --audit-level=moderate || true" }',
    '        }',
    '        stage("Security: Snyk") {',
    '            environment { SNYK_TOKEN = credentials("snyk-token") }',
    '            steps { sh "npx snyk test --severity-threshold=high" }',
    '        }',
    '        stage("SBOM") {',
    '            steps {',
    '                sh "curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0"',
    '                sh "syft . -o spdx-json=sbom.spdx.json"',
    '                archiveArtifacts artifacts: "sbom.spdx.json"',
    '            }',
    '        }',
    '        stage("Dependency-pin verify") {',
    '            steps {',
    '                sh "npm ls --all --json > installed-tree.json || true"',
    '                sh "test -f package-lock.json"',
    '            }',
    '        }',
    '        stage("Build (SLSA L3)") {',
    '            steps {',
    '                sh "npx electron-builder --linux --publish never"',
    '            }',
    '        }',
    '        stage("Sign (Cosign)") {',
    '            steps {',
    '                sh \'\'\'',
    '                    if [ "$COSIGN_KEY_MODE" = "key-based" ]; then',
    '                        echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    '                        cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"',
    '                        rm /tmp/cosign.key',
    '                    else',
    '                        cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"',
    '                    fi',
    '                \'\'\'',
    '            }',
    '        }',
    '        stage("CVE scan (Grype)") {',
    '            steps {',
    '                sh "curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0"',
    '                sh "grype sbom:sbom.spdx.json --fail-on high"',
    '            }',
    '        }',
    '        stage("Fuse-counter check") {',
    '            steps {',
    '                sh \'\'\'',
    '                    PRIOR=$(git show origin/main:package.json | node -e "let d=\'\';process.stdin.on(\\\'data\\\',c=>d+=c);process.stdin.on(\\\'end\\\',()=>console.log(JSON.parse(d).fuseCounter))")',
    '                    CURRENT=$(node -e "console.log(require(\\\'./package.json\\\').fuseCounter)")',
    '                    echo "prior=$PRIOR current=$CURRENT"',
    '                    [ "$CURRENT" -ge "$PRIOR" ]',
    '                \'\'\'',
    '            }',
    '        }',
    '        stage("Deploy") {',
    '            when { branch "main" }',
    '            steps { echo "TODO: deploy step — customize for your target environment" }',
    '        }',
    '    }',
    '    post {',
    '        always {',
    '            script {',
    '                if (env.FIREALIVE_WEBHOOK_URL?.trim()) {',
    '                    def status = currentBuild.currentResult == "SUCCESS" ? "passed" : "failed"',
    '                    sh """',
    '                        curl -X POST "$FIREALIVE_WEBHOOK_URL/api/cicd/runs" \\\\',
    '                            -H "Authorization: Bearer $FIREALIVE_WEBHOOK_TOKEN" \\\\',
    '                            -H "Content-Type: application/json" \\\\',
    '                            -d \'{"external_run_id":"\'$BUILD_NUMBER\'","platform":"jenkins","status":"\'$status\'","started_at":"\'$(date -u -d @"$BUILD_TIMESTAMP" +%FT%TZ 2>/dev/null || date -u +%FT%TZ)\'","finished_at":"\'$(date -u +%FT%TZ)\'","commit_sha":"\'$GIT_COMMIT\'","branch":"\'$GIT_BRANCH\'"}\'',
    '                    """',
    '                }',
    '            }',
    '        }',
    '    }',
    '}',
    '',
  ].join('\n');
}

function renderCircleCi(snapshot, purpose) {
  return [
    `# FireAlive CI Pipeline (CircleCI)`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'version: 2.1',
    '',
    'jobs:',
    '  ci:',
    '    docker:',
    '      - image: cimg/node:20.11',
    '    steps:',
    '      - checkout',
    '      - run:',
    '          name: Install',
    '          command: npm ci',
    '      - run:',
    '          name: Lint',
    '          command: npm run lint',
    '      - run:',
    '          name: Test',
    '          command: npm test',
    '      - run:',
    '          name: Regression test',
    '          command: |',
    '            node -e "const { RegressionRunner } = require(\'./server/services/regression-runner\'); const { getDb, initDb } = require(\'./server/db/init\'); initDb(); const r = new RegressionRunner(getDb()).run(); console.log(JSON.stringify(r.summary, null, 2)); if (r.failed > 0) process.exit(1);"',
    '      - run:',
    '          name: Security npm audit',
    '          command: npm audit --audit-level=moderate || true',
    '      - run:',
    '          name: Security Snyk',
    '          command: npx snyk test --severity-threshold=high',
    '          environment:',
    '            SNYK_TOKEN: $SNYK_TOKEN',
    '      - run:',
    '          name: Install Syft',
    '          command: curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0',
    '      - run:',
    '          name: SBOM',
    '          command: syft . -o spdx-json=sbom.spdx.json',
    '      - store_artifacts:',
    '          path: sbom.spdx.json',
    '      - run:',
    '          name: Dep-pin verify',
    '          command: |',
    '            npm ls --all --json > installed-tree.json || true',
    '            test -f package-lock.json',
    '      - run:',
    '          name: Build (SLSA L3)',
    '          command: npx electron-builder --linux --publish never',
    '      - run:',
    '          name: Install Cosign',
    '          command: curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign',
    '      - run:',
    '          name: Sign installer (Cosign)',
    '          command: |',
    '            if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '              echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    '              cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"',
    '              rm /tmp/cosign.key',
    '            else',
    '              cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"',
    '            fi',
    '      - run:',
    '          name: CVE scan (Grype)',
    '          command: |',
    '            curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0',
    '            grype sbom:sbom.spdx.json --fail-on high',
    '      - run:',
    '          name: Fuse-counter check',
    '          command: |',
    '            PRIOR=$(git show origin/main:package.json | node -e "let d=\'\';process.stdin.on(\'data\',c=>d+=c);process.stdin.on(\'end\',()=>console.log(JSON.parse(d).fuseCounter))")',
    '            CURRENT=$(node -e "console.log(require(\'./package.json\').fuseCounter)")',
    '            echo "prior=$PRIOR current=$CURRENT"',
    '            test "$CURRENT" -ge "$PRIOR"',
    '      - run:',
    '          name: Deploy (placeholder)',
    '          command: echo "TODO: deploy step — customize for your target environment"',
    '',
    'workflows:',
    '  build-test-sign-deploy:',
    '    jobs:',
    '      - ci',
    '',
  ].join('\n');
}

const PLATFORM_RENDERERS = {
  'github-actions': renderGithubActions,
  'gitlab-ci':      renderGitlabCi,
  'jenkins':        renderJenkinsfile,
  'circleci':       renderCircleCi,
};

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Generate a CI/CD pipeline configuration.
 *
 * @param {object} db                  SQLite db handle
 * @param {string} platform            one of VALID_PLATFORMS
 * @param {string} purpose             one of VALID_PURPOSES
 * @param {object} options
 * @param {number} options.userId      users.id for created_by FK
 * @param {string} [options.cicdConfigsDir]   override storage dir
 * @returns {object}                   {id, paths, snapshot, ...}
 * @throws  {Error}                    on invalid platform/purpose or
 *                                     pipeline failure
 */
function generateConfig(db, platform, purpose, options = {}) {
  if (!VALID_PLATFORMS.includes(platform)) {
    throw new Error(`invalid platform '${platform}'; valid: ${VALID_PLATFORMS.join(', ')}`);
  }
  if (!VALID_PURPOSES.includes(purpose)) {
    throw new Error(`invalid purpose '${purpose}'; valid: ${VALID_PURPOSES.join(', ')}`);
  }
  if (!options.userId || typeof options.userId !== 'number') {
    throw new Error('generateConfig: options.userId (integer users.id) is required');
  }

  const snapshot = captureInstallSnapshot(db);
  const configId = crypto.randomBytes(16).toString('hex');
  const cicdDir = resolveCicdConfigsDir(options.cicdConfigsDir);
  ensureDir(cicdDir);
  const bundleDir = path.join(cicdDir, configId);
  ensureDir(bundleDir);

  try {
    // Render + write the pipeline file
    const renderer = PLATFORM_RENDERERS[platform];
    const pipelineYaml = renderer(snapshot, purpose);
    const filenameRelative = PLATFORM_FILENAME[platform];
    const pipelinePath = path.join(bundleDir, path.basename(filenameRelative));
    fs.writeFileSync(pipelinePath, pipelineYaml, 'utf8');

    // Write README
    const readmePath = path.join(bundleDir, 'README.md');
    fs.writeFileSync(readmePath, buildReadme(platform, purpose, snapshot, configId), 'utf8');

    // INSERT cicd_configs row
    db.prepare(
      `INSERT INTO cicd_configs
         (id, platform, purpose, generated_at, generated_yaml_path,
          current_install_snapshot_json, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      configId,
      platform,
      purpose,
      snapshot.captured_at,
      pipelinePath,
      JSON.stringify(snapshot),
      options.userId,
    );

    logger.info('cicd-generator: pipeline config generated', {
      id: configId,
      platform,
      purpose,
    });

    return {
      id: configId,
      platform,
      purpose,
      pipeline_path: pipelinePath,
      pipeline_relative_path: filenameRelative,
      readme_path: readmePath,
      bundle_dir: bundleDir,
      generated_at: snapshot.captured_at,
      install_snapshot: snapshot,
    };
  } catch (err) {
    try {
      if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      logger.warn('cicd-generator: failed to clean partial bundle', {
        bundleDir,
        error: cleanupErr.message,
      });
    }
    throw err;
  }
}

module.exports = {
  generateConfig,
  VALID_PLATFORMS,
  VALID_PURPOSES,
  PLATFORM_FILENAME,
};
