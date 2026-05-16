// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: Docker Compose (R3k C14)
//
// Universal (works for any provider running a Docker host). The
// provider parameter affects only the comment header and the env-file
// reference convention.
// ═══════════════════════════════════════════════════════════════════════════════

function render(snapshot, provider) {
  const yaml = [
    `# FireAlive — Docker Compose deployment (provider: ${provider})`,
    `# Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}, version=${snapshot.version.version}`,
    '#',
    '# Required env vars (provide via .env file alongside docker-compose.yml,',
    '# or via the provider\'s secret store mounted as env):',
    '#',
    '#   TIER1_ENCRYPTION_KEY   32-byte hex KEK for v2 backup engine',
    '#   JWT_SECRET             >=16 random chars',
    '#',
    'version: "3.9"',
    '',
    'services:',
    '  firealive:',
    '    image: ghcr.io/petermancina/firealive:latest',
    '    restart: unless-stopped',
    '    ports:',
    '      - "3000:3000"',
    '    environment:',
    '      - TIER1_ENCRYPTION_KEY=${TIER1_ENCRYPTION_KEY}',
    '      - JWT_SECRET=${JWT_SECRET}',
    '      - BACKUP_DIR=/data/backups',
    '      - CLOUD_PACKAGES_DIR=/data/cloud-packages',
    '    volumes:',
    '      - firealive-data:/data',
    '    healthcheck:',
    '      test: ["CMD", "curl", "-fsS", "http://localhost:3000/health"]',
    '      interval: 30s',
    '      timeout: 5s',
    '      retries: 3',
    '',
    'volumes:',
    '  firealive-data:',
    '    driver: local',
    '',
  ].join('\n');

  const envExample = [
    `# .env template for FireAlive Docker Compose (provider: ${provider})`,
    `# Generated at: ${snapshot.captured_at}`,
    '# Fill in real values before `docker compose up`.',
    '#',
    'TIER1_ENCRYPTION_KEY=replace-with-32-byte-hex-kek',
    'JWT_SECRET=replace-with-16+-random-chars',
    '',
  ].join('\n');

  return {
    files: [
      { path: 'docker-compose.yml', content: yaml },
      { path: '.env.example', content: envExample },
    ],
  };
}

module.exports = { render };
