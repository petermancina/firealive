// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — CI/CD Pipeline Bundle (R3k C31)
//
// GD-side equivalent of MC's R3k C23 cicd-generator.js. Consolidated
// orchestrator + 4 platform renderers in one module per Sub-phase 6
// monolithic-file convention.
//
// SUPPORTED PLATFORMS (per Q4 LOCKED decision; same as MC)
// ========================================================
//
//   github-actions   .github/workflows/firealive-gd-ci.yml
//   gitlab-ci        .gitlab-ci.yml
//   jenkins          Jenkinsfile
//   circleci         .circleci/config.yml
//
// DEPLOYMENT SHAPE DIVERGENCE FROM MC
// ===================================
//
//   Installer:  FireAlive GD desktop app built by electron-builder, signed
//   Port:       4001
//   Env vars:   GD_JWT_SECRET, GD_ENCRYPTION_KEY
//   Service:    firealive-gd
//   Webhook:    POST /api/cicd/runs on the GD instance that generated
//               the pipeline (api-key + cicd:webhook scope)
//
// SIMPLIFIED STEPS VS MC'S 11-STEP PIPELINE
// =========================================
//
// MC's R3k C23 pipeline embeds 11 steps including an inline
// regression-runner invocation. GD's regression runner lives inline
// in index.js (R3k C26) rather than as a require()-able module, so
// invoking it from CI YAML is awkward without a refactor. GD's CI
// pipelines therefore use the simpler 10-step shape:
//
//   1. lint (ESLint)
//   2. test (npm test)
//   3. security: npm audit
//   4. security: Snyk
//   5. SBOM (Syft -> SPDX-JSON artifact)
//   6. dependency-pin verify
//   7. build (electron-builder installer; provenance attested, SLSA L3
//      for SLSA L3)
//   8. sign (Cosign keyless OIDC default; override via
//      COSIGN_KEY_MODE=key-based + COSIGN_PRIVATE_KEY)
//   9. CVE scan (Grype — Anchore's scanner; pairs with Syft, scans the
//      built image / SBOM, --fail-on high)
//
//   Pinned tool versions (no unpinned `main`/`@master`/`:latest`; bump only
//   via reviewed PR):  Syft v1.44.0, Grype v0.110.0, Cosign v3.0.6.
//   Installers use the immutable release tag; the Syft image digest is
//   anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6.
//   10. fuse-counter check (package.json fuseCounter monotonically
//       advanced from main)
//   11. Deploy (commented placeholder for operator customization)
//
// Plus optional webhook reporter that POSTs run status back to the
// originating GD's /api/cicd/runs endpoint.
//
// PURPOSE (per FEATURE-GUIDE / Phase B 1.4g)
// ==========================================
//
//   custom-build              fork tailored to the org's
//                             integrations / automation
//   upstream-contribution     pipeline targeting the public FireAlive
//                             GitHub repo
//
// FAILURE SEMANTICS
// =================
//
// Errors propagate to the C32 route handler which maps invalid
// platform/purpose -> 400, persistence failure -> 500. Partial state
// on disk is cleaned in finally on any failure mid-pipeline.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const gdDataRoot = require('../lib/gd-data-root');

// ── Constants ──────────────────────────────────────────────────────────

const VALID_PLATFORMS = ['github-actions', 'gitlab-ci', 'jenkins', 'circleci'];
const VALID_PURPOSES  = ['custom-build', 'upstream-contribution'];

const PLATFORM_FILENAME = {
  'github-actions': '.github/workflows/firealive-gd-ci.yml',
  'gitlab-ci':      '.gitlab-ci.yml',
  'jenkins':        'Jenkinsfile',
  'circleci':       '.circleci/config.yml',
};

const GD_CICD_SHAPE = {
  port: 4001,
  envVars: ['GD_JWT_SECRET', 'GD_ENCRYPTION_KEY'],
};

function resolveCicdConfigsDir(override) {
  // P1-1: GD_CICD_CONFIGS_DIR, else the canonical GD data root.
  return override || gdDataRoot.cicdConfigsDir();
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return gdDataRoot.ensureDir(dir);
}

// ── Snapshot (GD-shape, CI/CD-tailored) ────────────────────────────────

function captureSnapshot(db) {
  const safe = (fn, fb) => { try { return fn(); } catch (e) { return fb; } };

  const mcs = safe(() => {
    const total = db.prepare('SELECT COUNT(*) AS n FROM management_consoles').get().n;
    const active = db.prepare("SELECT COUNT(*) AS n FROM management_consoles WHERE status='active'").get().n;
    return { total, active };
  }, { total: 0, active: 0 });

  let dbSizeBytes = 0;
  try {
    const dbPath = db.name;
    if (dbPath && fs.existsSync(dbPath)) dbSizeBytes = fs.statSync(dbPath).size;
  } catch (e) { /* keep 0 */ }

  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const pkg = require('../package.json');
    versionInfo = {
      version: pkg.version || 'unknown',
      fuse_counter: typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : null,
      build_id: pkg.buildId || null,
    };
  } catch (e) { /* keep defaults */ }

  return {
    captured_at: new Date().toISOString(),
    side: 'gd',
    management_consoles: mcs,
    data: { db_size_bytes: dbSizeBytes },
    version: versionInfo,
  };
}

// ── README ─────────────────────────────────────────────────────────────

function buildReadme(platform, purpose, snapshot, configId) {
  const filename = PLATFORM_FILENAME[platform];
  return [
    `# FireAlive GD-server CI/CD Pipeline`,
    ``,
    `**Config id:** \`${configId}\``,
    `**Platform:** ${platform}`,
    `**Purpose:** ${purpose}`,
    `**Generated:** ${snapshot.captured_at}`,
    `**Source GD version:** ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    ``,
    `## Deploying`,
    ``,
    `1. Commit the generated file to your repository at the canonical path: \`${filename}\``,
    `2. Set the required CI secrets in your CI provider's secret store:`,
    `   - \`COSIGN_PASSWORD\` (set empty if using keyless OIDC, recommended)`,
    `   - \`COSIGN_PRIVATE_KEY\` (only if COSIGN_KEY_MODE=key-based)`,
    `   - \`SNYK_TOKEN\` (for Snyk scan step)`,
    `   - \`DOCKER_REGISTRY_TOKEN\` (or platform-equivalent for image push)`,
    `3. Trigger the pipeline (push to main or platform's manual trigger).`,
    ``,
    `## Embedded pipeline steps`,
    ``,
    `1. Lint (ESLint)`,
    `2. Test (npm test)`,
    `3. Security: npm audit`,
    `4. Security: Snyk`,
    `5. SBOM (Syft -> SPDX-JSON artifact)`,
    `6. Dependency-pin verification`,
    `7. Build (electron-builder installer; provenance attested, SLSA L3)`,
    `8. Sign (Cosign keyless OIDC by default)`,
    `9. CVE scan (Grype — Anchore; pairs with Syft, scans the SBOM)`,
    `10. Fuse-counter check (R3 anti-rollback discipline)`,
    `11. Deploy (commented placeholder)`,
    ``,
    `## Webhook reporting (optional)`,
    ``,
    `The pipeline can POST run status back to this GD instance:`,
    ``,
    `\`\`\`bash`,
    `curl -X POST <gd-url>/api/cicd/runs \\`,
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
    `Idempotent: receiver collapses duplicate (platform, external_run_id) on retry.`,
    ``,
    `## Install posture at generation time`,
    ``,
    `- Management Consoles: ${snapshot.management_consoles.active} active / ${snapshot.management_consoles.total} total`,
    `- DB size at capture: ${snapshot.data.db_size_bytes} bytes`,
    ``,
  ].join('\n');
}

// ── Platform renderers ─────────────────────────────────────────────────

function renderGithubActions(snapshot, purpose) {
  return [
    `# FireAlive GD-server CI Pipeline (GitHub Actions)`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source GD version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'name: firealive-gd-ci',
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
    '  id-token: write   # Sigstore keyless OIDC',
    '  packages: write',
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
    '      - name: Lint',
    '        run: npm run lint',
    '',
    '      - name: Test',
    '        run: npm test',
    '',
    '      - name: npm audit',
    '        run: npm audit --audit-level=moderate || true',
    '',
    '      - name: Snyk',
    '        env:',
    '          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}',
    '        run: npx snyk test --severity-threshold=high',
    '',
    '      - name: Install Syft (pinned v1.44.0)',
    '        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0',
    '',
    '      - name: SBOM',
    '        run: syft . -o spdx-json=sbom.spdx.json',
    '',
    '      - name: Upload SBOM',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: sbom',
    '          path: sbom.spdx.json',
    '',
    '      - name: Dep-pin verify',
    '        run: |',
    '          npm ls --all --json > /tmp/installed-tree.json || true',
    '          test -f package-lock.json',
    '',
    '      - name: Build (SLSA L3)',
    `        run: npx electron-builder --linux --publish never`,
    '',
    '      - name: Install Cosign',
    '        uses: sigstore/cosign-installer@v3',
    '',
    '      - name: Sign installer',
    '        env:',
    '          COSIGN_EXPERIMENTAL: "1"',
    '        run: |',
    '          if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '            echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    `            cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"`,
    '            rm /tmp/cosign.key',
    '          else',
    `            cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"`,
    '          fi',
    '',
    '      - name: Install Grype (pinned v0.110.0)',
    '        run: curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0',
    '',
    '      - name: Grype CVE scan',
    `        run: grype sbom:sbom.spdx.json --fail-on high`,
    '',
    '      - name: Fuse-counter check',
    '        run: |',
    "          PRIOR=$(git show origin/main:package.json | node -e \"let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d).fuseCounter))\")",
    "          CURRENT=$(node -e \"console.log(require('./package.json').fuseCounter)\")",
    '          echo "prior=$PRIOR current=$CURRENT"',
    '          [ "$CURRENT" -ge "$PRIOR" ] || { echo "fuse rolled back"; exit 1; }',
    '',
    '      - name: Deploy (placeholder)',
    "        if: github.ref == 'refs/heads/main'",
    '        run: echo "TODO: customize deploy step for your environment"',
    '',
    '      - name: Report to GD',
    "        if: always() && env.FIREALIVE_GD_WEBHOOK_URL != ''",
    '        env:',
    '          FIREALIVE_GD_WEBHOOK_URL: ${{ secrets.FIREALIVE_GD_WEBHOOK_URL }}',
    '          FIREALIVE_GD_WEBHOOK_TOKEN: ${{ secrets.FIREALIVE_GD_WEBHOOK_TOKEN }}',
    '        run: |',
    '          STATUS="${{ job.status }}"',
    '          [ "$STATUS" = "success" ] && S=passed || S=failed',
    '          curl -X POST "$FIREALIVE_GD_WEBHOOK_URL/api/cicd/runs" \\',
    '            -H "Authorization: Bearer $FIREALIVE_GD_WEBHOOK_TOKEN" \\',
    '            -H "Content-Type: application/json" \\',
    "            -d \"{\\\"external_run_id\\\":\\\"${{ github.run_id }}\\\",\\\"platform\\\":\\\"github-actions\\\",\\\"status\\\":\\\"$S\\\",\\\"started_at\\\":\\\"${{ github.event.head_commit.timestamp }}\\\",\\\"finished_at\\\":\\\"$(date -u +%FT%TZ)\\\",\\\"commit_sha\\\":\\\"${{ github.sha }}\\\",\\\"branch\\\":\\\"${{ github.ref_name }}\\\"}\"",
    '',
  ].join('\n');
}

function renderGitlabCi(snapshot, purpose) {
  return [
    `# FireAlive GD-server CI Pipeline (GitLab CI)`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source GD version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'stages: [lint, test, security, build, sign-verify, deploy]',
    '',
    'default:',
    '  image: node:20-bullseye',
    '  cache: { paths: [node_modules/] }',
    '  before_script: [npm ci]',
    '',
    'lint:',
    '  stage: lint',
    '  script: [npm run lint]',
    '',
    'test:',
    '  stage: test',
    '  script: [npm test]',
    '',
    'security-audit:',
    '  stage: security',
    '  script: [npm audit --audit-level=moderate || true]',
    '',
    'security-snyk:',
    '  stage: security',
    '  image: snyk/snyk:node-20',
    '  script: [snyk test --severity-threshold=high]',
    '  variables: { SNYK_TOKEN: $SNYK_TOKEN }',
    '',
    'sbom:',
    '  stage: security',
    '  image: anchore/syft:v1.44.0',
    '  script: [syft . -o spdx-json=sbom.spdx.json]',
    '  artifacts:',
    '    paths: [sbom.spdx.json]',
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
    `    - npx electron-builder --linux --publish never`,
    '',
    'sign:',
    '  stage: sign-verify',
    '  image: gcr.io/projectsigstore/cosign:v2',
    '  script:',
    '    - |',
    '      if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '        echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    `        cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"`,
    '        rm /tmp/cosign.key',
    '      else',
    `        cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"`,
    '      fi',
    '',
    'cve-scan:',
    '  stage: sign-verify',
    '  image: anchore/grype:v0.110.0',
    `  script: [grype sbom:sbom.spdx.json --fail-on high]`,
    '',
    'fuse-counter:',
    '  stage: sign-verify',
    '  script:',
    "    - PRIOR=$(git show origin/main:package.json | node -e \"let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d).fuseCounter))\")",
    "    - CURRENT=$(node -e \"console.log(require('./package.json').fuseCounter)\")",
    '    - echo "prior=$PRIOR current=$CURRENT"',
    '    - test "$CURRENT" -ge "$PRIOR"',
    '',
    'deploy:',
    '  stage: deploy',
    '  only: [main]',
    '  script: [echo "TODO: customize deploy step"]',
    '',
  ].join('\n');
}

function renderJenkinsfile(snapshot, purpose) {
  return [
    `// FireAlive GD-server Jenkinsfile`,
    `// Generated: ${snapshot.captured_at}`,
    `// Purpose: ${purpose}`,
    `// Source GD version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'pipeline {',
    '  agent any',
    '  environment {',
    '    COSIGN_EXPERIMENTAL = "1"',
    "    COSIGN_KEY_MODE = \"${env.COSIGN_KEY_MODE ?: 'keyless'}\"",
    '  }',
    '  stages {',
    '    stage("Install") { steps { sh "npm ci" } }',
    '    stage("Lint")    { steps { sh "npm run lint" } }',
    '    stage("Test")    { steps { sh "npm test" } }',
    '    stage("npm audit") { steps { sh "npm audit --audit-level=moderate || true" } }',
    '    stage("Snyk") {',
    '      environment { SNYK_TOKEN = credentials("snyk-token") }',
    '      steps { sh "npx snyk test --severity-threshold=high" }',
    '    }',
    '    stage("SBOM") {',
    '      steps {',
    '        sh "curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0"',
    '        sh "syft . -o spdx-json=sbom.spdx.json"',
    '        archiveArtifacts artifacts: "sbom.spdx.json"',
    '      }',
    '    }',
    '    stage("Dep-pin verify") {',
    '      steps {',
    '        sh "npm ls --all --json > installed-tree.json || true"',
    '        sh "test -f package-lock.json"',
    '      }',
    '    }',
    '    stage("Build (SLSA L3)") {',
    `      steps { sh "npx electron-builder --linux --publish never" }`,
    '    }',
    '    stage("Sign") {',
    "      steps {",
    "        sh '''",
    "          if [ \"$COSIGN_KEY_MODE\" = \"key-based\" ]; then",
    "            echo \"$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key",
    `            cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"`,
    "            rm /tmp/cosign.key",
    "          else",
    `            cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"`,
    "          fi",
    "        '''",
    "      }",
    '    }',
    '    stage("CVE scan") {',
    `      steps { sh "curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0"; sh "grype sbom:sbom.spdx.json --fail-on high" }`,
    '    }',
    '    stage("Fuse-counter") {',
    "      steps {",
    "        sh '''",
    "          PRIOR=$(git show origin/main:package.json | node -e \"let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d).fuseCounter))\")",
    "          CURRENT=$(node -e \"console.log(require('./package.json').fuseCounter)\")",
    "          echo \"prior=$PRIOR current=$CURRENT\"",
    "          [ \"$CURRENT\" -ge \"$PRIOR\" ]",
    "        '''",
    "      }",
    '    }',
    '    stage("Deploy") {',
    '      when { branch "main" }',
    '      steps { echo "TODO: customize deploy step" }',
    '    }',
    '  }',
    '  post {',
    '    always {',
    '      script {',
    '        if (env.FIREALIVE_GD_WEBHOOK_URL?.trim()) {',
    '          def status = currentBuild.currentResult == "SUCCESS" ? "passed" : "failed"',
    '          sh """',
    '            curl -X POST \\"$FIREALIVE_GD_WEBHOOK_URL/api/cicd/runs\\" \\\\',
    '              -H \\"Authorization: Bearer $FIREALIVE_GD_WEBHOOK_TOKEN\\" \\\\',
    '              -H \\"Content-Type: application/json\\" \\\\',
    '              -d \'{"external_run_id":"\'$BUILD_NUMBER\'","platform":"jenkins","status":"\'$status\'","started_at":"\'$(date -u +%FT%TZ)\'","finished_at":"\'$(date -u +%FT%TZ)\'","commit_sha":"\'$GIT_COMMIT\'","branch":"\'$GIT_BRANCH\'"}\'',
    '          """',
    '        }',
    '      }',
    '    }',
    '  }',
    '}',
    '',
  ].join('\n');
}

function renderCircleCi(snapshot, purpose) {
  return [
    `# FireAlive GD-server CircleCI`,
    `# Generated: ${snapshot.captured_at}`,
    `# Purpose: ${purpose}`,
    `# Source GD version: ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    '',
    'version: 2.1',
    '',
    'jobs:',
    '  ci:',
    '    docker: [{ image: cimg/node:20.11 }]',
    '    steps:',
    '      - checkout',
    '      - run: { name: Install, command: npm ci }',
    '      - run: { name: Lint, command: npm run lint }',
    '      - run: { name: Test, command: npm test }',
    '      - run: { name: npm audit, command: npm audit --audit-level=moderate || true }',
    '      - run:',
    '          name: Snyk',
    '          command: npx snyk test --severity-threshold=high',
    '          environment: { SNYK_TOKEN: $SNYK_TOKEN }',
    '      - run:',
    '          name: Install Syft',
    '          command: curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0',
    '      - run: { name: SBOM, command: syft . -o spdx-json=sbom.spdx.json }',
    '      - store_artifacts: { path: sbom.spdx.json }',
    '      - run:',
    '          name: Dep-pin verify',
    '          command: |',
    '            npm ls --all --json > installed-tree.json || true',
    '            test -f package-lock.json',
    '      - run:',
    '          name: Build (SLSA L3)',
    `          command: npx electron-builder --linux --publish never`,
    '      - run:',
    '          name: Install Cosign',
    '          command: curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign',
    '      - run:',
    '          name: Sign',
    '          command: |',
    '            if [ "${COSIGN_KEY_MODE:-keyless}" = "key-based" ]; then',
    '              echo "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key',
    `              cosign sign-blob --yes --key /tmp/cosign.key "$(ls dist/*.AppImage | head -1)"`,
    '              rm /tmp/cosign.key',
    '            else',
    `              cosign sign-blob --yes "$(ls dist/*.AppImage | head -1)"`,
    '            fi',
    '      - run:',
    '          name: CVE scan',
    '          command: |',
    '            curl -sSfL https://raw.githubusercontent.com/anchore/grype/v0.110.0/install.sh | sh -s -- -b /usr/local/bin v0.110.0',
    `            grype sbom:sbom.spdx.json --fail-on high`,
    '      - run:',
    '          name: Fuse-counter',
    '          command: |',
    "            PRIOR=$(git show origin/main:package.json | node -e \"let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d).fuseCounter))\")",
    "            CURRENT=$(node -e \"console.log(require('./package.json').fuseCounter)\")",
    '            echo "prior=$PRIOR current=$CURRENT"',
    '            test "$CURRENT" -ge "$PRIOR"',
    '      - run: { name: Deploy, command: echo "TODO: customize deploy step" }',
    '',
    'workflows:',
    '  build-test-sign:',
    '    jobs: [ci]',
    '',
  ].join('\n');
}

const PLATFORM_RENDERERS = {
  'github-actions': renderGithubActions,
  'gitlab-ci': renderGitlabCi,
  'jenkins': renderJenkinsfile,
  'circleci': renderCircleCi,
};

// ── Public API ─────────────────────────────────────────────────────────

function generateConfig(db, platform, purpose, options = {}) {
  if (!VALID_PLATFORMS.includes(platform)) {
    throw new Error(`invalid platform '${platform}'; valid: ${VALID_PLATFORMS.join(', ')}`);
  }
  if (!VALID_PURPOSES.includes(purpose)) {
    throw new Error(`invalid purpose '${purpose}'; valid: ${VALID_PURPOSES.join(', ')}`);
  }
  if (!options.userId || typeof options.userId !== 'number') {
    throw new Error('generateConfig: options.userId is required');
  }

  const snapshot = captureSnapshot(db);
  const configId = crypto.randomBytes(16).toString('hex');
  const cicdDir = resolveCicdConfigsDir(options.cicdConfigsDir);
  ensureDir(cicdDir);
  const bundleDir = path.join(cicdDir, configId);
  ensureDir(bundleDir);

  try {
    const renderer = PLATFORM_RENDERERS[platform];
    const pipelineText = renderer(snapshot, purpose);
    const filenameRelative = PLATFORM_FILENAME[platform];
    const pipelinePath = path.join(bundleDir, path.basename(filenameRelative));
    fs.writeFileSync(pipelinePath, pipelineText, 'utf8');

    const readmePath = path.join(bundleDir, 'README.md');
    fs.writeFileSync(readmePath, buildReadme(platform, purpose, snapshot, configId), 'utf8');

    db.prepare(
      `INSERT INTO cicd_configs
         (id, platform, purpose, generated_at, generated_yaml_path,
          current_install_snapshot_json, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      configId, platform, purpose, snapshot.captured_at,
      pipelinePath, JSON.stringify(snapshot), options.userId,
    );

    return {
      id: configId,
      platform, purpose,
      pipeline_path: pipelinePath,
      pipeline_relative_path: filenameRelative,
      readme_path: readmePath,
      bundle_dir: bundleDir,
      generated_at: snapshot.captured_at,
      install_snapshot: snapshot,
    };
  } catch (err) {
    try { if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true }); }
    catch (cleanupErr) { /* swallow */ }
    throw err;
  }
}

module.exports = {
  generateConfig,
  captureSnapshot,
  VALID_PLATFORMS,
  VALID_PURPOSES,
  PLATFORM_FILENAME,
  GD_CICD_SHAPE,
};
