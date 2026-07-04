// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Remediation Map
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's remediations.js.
// When a GD compliance check returns 'warning' or 'fail' status, the
// administrator needs to know what to do about it. The check function's
// detail field describes WHAT was found; this file describes WHAT TO DO.
// The two together make compliance reports actionable rather than merely
// diagnostic.
//
// USAGE
//
// generateComplianceReport (in services/compliance/index.js) looks up
// the remediation by the check function's name property:
//
//   const remediation = REMEDIATIONS[ctrl.check.name] || null;
//   if (status !== 'pass' && remediation) {
//     // include remediation in the per-control output
//   }
//
// The lookup is by function name, which is stable across the GD
// codebase. Both files that contain a function named
// 'checkAuditIntegrity' (compliance/index.js + checks/audit.js) and
// 'checkChangeManagement' (compliance/index.js + checks/config.js)
// share the same remediation entry by design.
//
// SCHEMA
//
// Each entry is:
//   {
//     summary: 'One-line description of the remediation action',
//     steps: [
//       'Step 1 -- be specific about UI tabs and field names',
//       'Step 2 -- include API endpoint paths when relevant',
//       ...
//     ],
//     uiPath: 'gd:integrations' or 'mc:admin/users' or null
//       The uiPath uses the format <app>:<route-hint>. For GD-side
//       remediations, the typical prefix is 'gd:'; some remediations
//       point to MC-side action items where the GD detects a
//       configuration whose fix lives at the MC.
//       uiPath: null means there is no single UI destination
//       (typically configuration outside the platform UI, like env
//       vars, reverse-proxy config, or operator-side host hardening).
//   }
//
// FORWARD-COMPATIBLE FRAMING
//
// Several GD check functions report on platform features that are
// planned but not yet built (Config Lock backend, KMS integration,
// integration_config table, etc.). The remediations for those checks
// describe BOTH the current operator-managed workaround AND the
// BUILD-PLAN-v16 phase that will close the gap. When the corresponding
// phase ships, the check transitions to reporting on real platform
// state and the remediation becomes straightforward configuration
// guidance.
//
// R3g PR3 has SHIPPED the signing_keys registry (MC-trust verification)
// + the compliance-report mailbox pattern + the manual CISO approval
// workflow. Remediation entries that previously contained "when R3g
// PR3 ships..." language have been updated to past-tense and to point
// at the current-state endpoints. Three NEW remediation slots cover
// the operational practices PR3 introduced:
//   - checkSigningKeyRotationCadence    operator-triggered rotation
//                                       with CISO approval gate
//   - checkMailboxFulfillmentLatency    full-report request fulfilment
//                                       latency expectations
//   - checkRoleSegregationCisoApprover  role-segregation reminder
//                                       for orgs assigning
//                                       signing_key_approver distinct
//                                       from ciso
// These slots are not yet wired to dedicated check functions; they
// serve as operator documentation and forward-compatible hooks for
// future checks that surface these signals.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const REMEDIATIONS = {

  // ── Inline check functions in compliance/index.js ──────────────────────────

  checkAccessControl: {
    summary: 'Ensure GD user roles are provisioned across CISO / VP / readonly tiers',
    steps: [
      'Navigate to GD -> Settings -> Users',
      'Verify at least one CISO-role user exists (required for write operations)',
      'Provision VP-role users for read + selected writes; readonly for auditors and board observers',
      'JWT bearer-token auth is automatic via authMiddleware on every /api route',
      'For MC-trust authentication (inbound pushes), see checkApiKeyRotation',
    ],
    uiPath: 'gd:users',
  },

  checkUniqueUsers: {
    summary: 'Resolve duplicate username conflicts',
    steps: [
      'Navigate to GD -> Settings -> Users',
      'Identify duplicate usernames in the report',
      'Deactivate the older account or rename one (users.username has a UNIQUE constraint at the DB layer; duplicates would only appear if case-insensitive collisions exist)',
      'Username uniqueness is required for unambiguous audit-log attribution',
    ],
    uiPath: 'gd:users',
  },

  checkEncryption: {
    summary: 'Configure GD_JWT_SECRET as a persistent random value',
    steps: [
      'Generate a key: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      'Set GD_JWT_SECRET in the GD server deployment environment (32 bytes / 64 hex chars minimum)',
      'Restart the GD server to pick up the env var',
      'Without GD_JWT_SECRET, the server generates an ephemeral key per-restart and all existing JWTs are invalidated on each restart',
      'For data-at-rest encryption: configure operator-managed disk encryption (LUKS / FileVault / BitLocker / AWS EBS encryption) on the underlying volume — the GD has no application-layer at-rest encryption',
    ],
    uiPath: null,
  },

  checkRBAC: {
    summary: 'Define users across the GD\'s three-tier role model',
    steps: [
      'Navigate to GD -> Settings -> Users',
      'Ensure users are spread across ciso / vp / readonly (not all in one role)',
      'SOC-grade Separation of Duties requires at least one CISO + at least one non-CISO role',
      'role column has a CHECK constraint enforcing (ciso, vp, readonly); changes require admin DB operation if direct migration is needed',
    ],
    uiPath: 'gd:users',
  },

  checkAuditControls: {
    summary: 'Ensure audit logging is active and exporting',
    steps: [
      'No action required if events flow into audit_log (every /api request except /api/health is logged via the request-logging middleware)',
      'If audit_log is empty: verify the request-logging middleware is mounted in packages/global-dashboard-server/index.js',
      'For SIEM streaming: integration_config table lands in B5b (v1.0.51); B3 (v1.0.48) wires SIEM/SOAR alerting',
      'Until SIEM streaming ships, manually export via /api/audit-logs/export/:format on a documented cadence to an external WORM destination',
    ],
    uiPath: 'gd:audit',
  },

  checkAuthentication: {
    summary: 'Configure GD_JWT_SECRET and any external IdP integrations',
    steps: [
      'Set GD_JWT_SECRET in the GD server deployment environment (see checkEncryption for key generation)',
      'For SSO via SAML / OIDC / LDAP: real IdP integration lands in B5b (v1.0.51); until then, users.auth_method is informational only',
      'For MFA: enable mfa_enabled = 1 per user via /api/auth/mfa-setup and /api/auth/mfa-confirm (note: /api/auth/mfa-verify is currently a stub accepting any 6+ digit code — known v0.0.31 limitation)',
      'Restart the GD server after GD_JWT_SECRET changes (invalidates all existing tokens)',
    ],
    uiPath: 'gd:users',
  },

  checkTransmission: {
    summary: 'Configure TLS at the reverse proxy in front of the GD',
    steps: [
      'GD has no application-layer HTTPS enforcement; TLS terminates at the reverse proxy',
      'Configure your reverse proxy (nginx / Caddy / cloud load balancer) with TLS 1.2 minimum (TLS 1.3 preferred)',
      'Use a CA-issued certificate (not self-signed) for production deployments',
      'Reject plaintext HTTP requests at the proxy before they reach the GD application port',
      'Set NODE_ENV=production in the GD deployment for industry convention (note: GD has no NODE_ENV-gated middleware as of v0.0.31)',
    ],
    uiPath: null,
  },

  checkBoundaries: {
    summary: 'Document the GD\'s third-party boundary (the connected MCs)',
    steps: [
      'Navigate to GD -> MCs',
      'Verify every connected MC has its country and regulatory_framework documented',
      'For each registered MC, last_sync should be recent (within 24h) — see checkIntegrationHealth',
      'Layer 2 integrations (SOAR / SIEM / IAM / cloud / ticketing on the GD\'s own network) land via B5b and later — until then the MCs are the GD\'s only third-party data sources',
    ],
    uiPath: 'gd:mcs',
  },

  checkAnomalyDetection: {
    summary: 'Verify rate limiting and audit logging are active',
    steps: [
      'No action required when apiLimiter (express-rate-limit) is mounted at /api/* in packages/global-dashboard-server/index.js (default 1000 req/15min)',
      'Failed logins are tracked in auth_log for IP-based blocking by an upstream reverse proxy or WAF',
      'For deeper anomaly detection on aggregate metrics streams from MCs: B3 (v1.0.48) wires runtime monitoring with SIEM/SOAR alerting',
    ],
    uiPath: null,
  },

  checkChangeManagement: {
    summary: 'Verify anti-rollback fuse and audit change events',
    steps: [
      'Confirm system_meta.fuse_counter is set to a positive integer (seeded by db-init.js)',
      'All PUT /api/config/:key operations log a CONFIG_UPDATED event in audit_log automatically (built into the route handler)',
      'Review recent change events via GD -> Audit Logs -> filter by event_type = "CONFIG_UPDATED"',
      'Note: package.json now carries a fuseCounter field (added in B6a, set to the platform anti-rollback floor). checkAntiRollback reports it as present-but-not-enforced; the boot-time comparison awaits the startup-verifier phase',
    ],
    uiPath: 'gd:audit',
  },

  checkIncidentResponse: {
    summary: 'Document GD-layer incident response procedures off-platform',
    steps: [
      'GD has no application-layer IR policy registry (no ir_policies table)',
      'CISO/governance-tier IR planning is operator-managed; document procedures off-platform (e.g., in your wiki or DMS)',
      'GD-specific scenarios to cover: GD server compromise, GD database corruption, suspicious aggregate metrics from an MC, MC api_key compromise, signing-key registry compromise (signing_keys table present)',
      'For SOC-level (analyst-facing) IR procedures: those live at the MC, not the GD',
    ],
    uiPath: null,
  },

  checkBackups: {
    summary: 'Configure backup schedules and verify a backup completes',
    steps: [
      'Navigate to GD -> Backup',
      'Add at least one backup schedule via POST /api/backup-schedules with frequency, destination, encrypted=true, retention_days',
      'Trigger a manual backup via POST /api/backups/trigger to bootstrap the backups table',
      'Each backup records a SHA-256 hash (backups.sha256_hash column) for integrity verification',
      'For redundancy: configure at least two schedules pointing to different destinations (see checkBackupMultiDestination)',
    ],
    uiPath: 'gd:backup',
  },

  // ── checks/access.js ───────────────────────────────────────────────────────

  checkPasswordPolicy: {
    summary: 'GD has no password policy enforcement endpoint as of v0.0.31',
    steps: [
      'There is no MIN_PASSWORD_LENGTH gate on the GD analogous to MC\'s server/routes/password.js',
      'Operator-side discipline: set strong passwords for CISO/VP/readonly accounts at provisioning time',
      'bcrypt hashing is automatic at storage (see /api/auth/login bcrypt.compare)',
      'A future GD enhancement could add a password-policy gate; until then, password quality is operator-enforced via process discipline',
    ],
    uiPath: null,
  },

  checkSessionTimeout: {
    summary: 'GD JWT expiry is hardcoded at 8h to match CISO operational rhythm',
    steps: [
      'GD JWT expiresIn is hardcoded "8h" in /api/auth/login route',
      'CISO operations are infrequent and multi-step; 8h is a deliberate UX choice but exceeds the SOC-grade 30-minute norm',
      'For shorter idle timeouts: reverse-proxy-enforce session cookies (e.g., nginx auth_request with shorter TTL) at the load balancer layer',
      'A future GD enhancement may add a GD_JWT_EXPIRY env var to make this configurable',
    ],
    uiPath: null,
  },

  checkAccountLockout: {
    summary: 'Verify apiLimiter and auth_log are active',
    steps: [
      'No action required when apiLimiter is mounted (express-rate-limit, 1000 req/15min)',
      'Failed login attempts are recorded in auth_log with action = LOGIN_FAILED',
      'For per-account lockout: implement at reverse-proxy or WAF layer using auth_log as the source of truth',
      'Recurring failures from a single IP should trigger upstream blocking via fail2ban or equivalent',
    ],
    uiPath: null,
  },

  checkMfaEnforcement: {
    summary: 'Enroll all GD users in MFA',
    steps: [
      'Navigate to GD -> Settings -> Users',
      'For each user, set mfa_enabled = 1 and walk them through MFA setup via /api/auth/mfa-setup',
      'Note: /api/auth/mfa-verify currently accepts any 6+ digit code without real TOTP verification — known v0.0.31 stub. Real verification lands in a future MFA-hardening pass.',
      'Until real MFA verify ships, mfa_enabled=1 is a posture marker indicating intent, not a cryptographic guarantee',
    ],
    uiPath: 'gd:users',
  },

  checkPrivilegedSeparation: {
    summary: 'Maintain 1-2 CISO-role users for SoD',
    steps: [
      'Navigate to GD -> Settings -> Users',
      'SOC-grade norm for GD: 1-2 CISO-role users (the CISO and their deputy)',
      'Promote additional senior roles to VP-tier rather than CISO-tier when possible',
      'If 0 CISO-role users exist, CISO-only routes (backups, schedules, MC registration, config writes) are unreachable',
    ],
    uiPath: 'gd:users',
  },

  checkApiKeyRotation: {
    summary: 'Re-register stale MC trust keys',
    steps: [
      'Navigate to GD -> MCs',
      'Identify MCs registered more than 90 days ago (last column: created_at)',
      'Re-register each stale MC: generate a fresh api_key on the MC side, then update the GD via PATCH /api/management-consoles/:id',
      'GD-stored api_key values are plaintext in management_consoles.api_key — reverse-proxy mTLS strongly advised for the push channel',
      'R3g PR3 added a signing_keys registry: cryptographically signed MC pushes supplement the api_key shared secret. See checkSigningKeyRegistry for current registry health and checkSigningKeyRotationCadence for the rotation workflow.',
    ],
    uiPath: 'gd:mcs',
  },

  checkIamIntegrationHealth: {
    summary: 'Configure IdP integrations and test recently',
    steps: [
      'PRE-B5b state (current): users.auth_method is set per-user; no integration_config table for IdP health tracking',
      'POST-B5b state (v1.0.51+): navigate to GD -> Integrations -> IAM',
      'For each IdP (SAML / OIDC / LDAP): configure endpoint, metadata, attribute mappings; click Test Connection',
      'Operational integrations should be tested at least every 30 days; check stale integrations and refresh',
    ],
    uiPath: 'gd:integrations',
  },

  checkRoleSeparation: {
    summary: 'Wait for GD Config Lock server-side persistence',
    steps: [
      'GD has no config_lock_state table or /api/config/lock route handler as of v0.0.31',
      'The Config Lock toggle in the GD frontend is server-side stubbed — clicks have no persistent effect',
      'A future BUILD-PLAN-v16 phase will land Config Lock server-side persistence on the GD (mirroring MC\'s R3e v1.0.32 pattern)',
      'Until then, role-based authority is enforced at route-middleware only (CISO-only routes via authMiddleware([\'ciso\']))',
    ],
    uiPath: null,
  },

  // ── checks/crypto.js ───────────────────────────────────────────────────────

  checkKeyRotation: {
    summary: 'Rotate GD_JWT_SECRET on a documented quarterly cadence',
    steps: [
      'GD has no in-platform key rotation registry; rotation is operator-managed',
      'Quarterly: generate a new GD_JWT_SECRET, update the env var, restart the GD server (invalidates all existing JWTs)',
      'For MC-trust api_keys: see checkApiKeyRotation (re-register each MC every 90 days)',
      'For MC-push signing keys (signing_keys registry, R3g PR3): rotation managed via POST /api/gd-signing-key/rotate (operator-initiated, requires CISO or signing_key_approver approval). See checkSigningKeyRotationCadence.',
    ],
    uiPath: null,
  },

  checkAlgorithmStrength: {
    summary: 'Ensure GD_JWT_SECRET is at least 32 bytes',
    steps: [
      'Generate a key: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      'Set GD_JWT_SECRET to the generated value (64 hex chars = 32 bytes for HMAC-SHA256)',
      'bcrypt cost factor is the bcryptjs library default; consider raising via deployment-time configuration if your threat model demands it',
      'For random IDs: crypto.randomBytes(16) and crypto.randomUUID() are already used; no operator action needed',
    ],
    uiPath: null,
  },

  checkTlsMinVersion: {
    summary: 'Enforce TLS 1.2 minimum at the reverse proxy',
    steps: [
      'GD has no application-layer HTTPS enforcement — TLS configuration is reverse-proxy responsibility',
      'Configure your reverse proxy with ssl_protocols TLSv1.2 TLSv1.3 (nginx syntax) or equivalent',
      'Reject TLS 1.0 / TLS 1.1 / SSL connections at the proxy',
      'Test with `nmap --script ssl-enum-ciphers -p 443 <gd-host>` to confirm acceptable cipher suite negotiation',
    ],
    uiPath: null,
  },

  checkKmsProvider: {
    summary: 'Configure external KMS when the GD KMS integration phase ships',
    steps: [
      'CURRENT STATE: GD has no kms_providers table; data-at-rest protection is filesystem-level on the SQLite database file',
      'Operator-managed alternative: enable disk encryption (LUKS / FileVault / BitLocker / AWS EBS encryption / similar) on the volume containing GD_DB_PATH',
      'FUTURE STATE: a GD KMS integration phase (B-phase track in BUILD-PLAN-v16) will introduce kms_providers — at that point, configure your provider (AWS KMS / GCP KMS / Azure Key Vault / HashiCorp Vault) via GD -> Integrations -> KMS',
    ],
    uiPath: null,
  },

  checkCertValidity: {
    summary: 'Manage TLS certificate lifecycle at the reverse proxy',
    steps: [
      'Certificate issuance, renewal, and expiry monitoring happen at the reverse proxy in front of the GD',
      'For ACME-based renewal (Let\'s Encrypt): use certbot or your proxy\'s built-in ACME support (Caddy auto-renews; nginx with certbot)',
      'For commercial-CA certs: track expiry in your operator-managed cert inventory; configure renewal alerts 30+ days before expiry',
      'The GD itself has no certificate-store integration — there is nothing to configure inside the GD',
    ],
    uiPath: null,
  },

  // ── checks/audit.js ────────────────────────────────────────────────────────

  checkAuditRetention: {
    summary: 'Wait for natural audit_log accumulation or import historical data',
    steps: [
      'GD does not auto-truncate audit_log — retention is bounded only by storage capacity on the SQLite file',
      'If oldest entry is <1 year, this typically reflects deployment age rather than policy failure',
      'For multi-year retention: provision sufficient disk capacity at the GD_DB_PATH volume',
      'For active retention enforcement: external WORM storage via /api/audit-logs/export/:format (operator-scheduled)',
    ],
    uiPath: null,
  },

  checkAuditIntegrity: {
    summary: 'Wait for B5a (v1.0.50) audit hash chain implementation',
    steps: [
      'PRE-B5a state (current): audit_log is append-only by API contract (no UPDATE or DELETE routes expose modification) but has no in-DB hash chain',
      'External tamper-evidence: protect the SQLite database file with operator-managed disk encryption + WORM storage if available',
      'POST-B5a state (v1.0.50): audit_log gains hash and prev_hash columns; every insert computes hash = SHA256(prev_hash + timestamp + event_type + detail + user_id)',
      'After B5a ships: GET /api/audit/integrity will validate the chain on demand; SIEM alerting will fire immediately on detected chain break',
    ],
    uiPath: null,
  },

  checkSyslogExport: {
    summary: 'Configure SIEM streaming when integration_config lands',
    steps: [
      'CURRENT STATE: GD has no SIEM streaming. Use the manual export endpoint GET /api/audit-logs/export/:format and archive to an external WORM destination on a documented cadence',
      'FUTURE STATE: B3 (v1.0.48) wires SIEM/SOAR alerting; integration_config table lands in B5b (v1.0.51) and onward',
      'After SIEM support ships: navigate to GD -> Integrations -> SIEM, configure your endpoint (Splunk HEC / Elastic / Sentinel / Chronicle), test connection',
      'Once streaming is operational, external tamper-evidence becomes available via SIEM-side retention of the streamed audit copy',
    ],
    uiPath: 'gd:integrations',
  },

  checkForensicsExport: {
    summary: 'Forensics export is operational — no action required',
    steps: [
      'GET /api/audit-logs/export/:format is mounted on the GD (authMiddleware ciso/vp)',
      'Returns full audit_log entries with timestamp, user_id, event_type, detail, ip, severity',
      'Pipe the export into external forensics tooling or schedule periodic exports to a SIEM/archive',
    ],
    uiPath: 'gd:audit',
  },

  checkAlertingThresholds: {
    summary: 'Configure notification_config delivery channels and recipients',
    steps: [
      'Navigate to GD -> Settings -> Notifications',
      'Set burnout_threshold (default 65), sla_below (default 85), turnover_risk_high (default true)',
      'Enable at least one delivery channel (email and/or sms)',
      'Populate recipients with comma-separated email addresses (or phone numbers for sms)',
      'Save via PUT /api/config/notification_config',
      'Note: domain-specific thresholds (burnout / SLA / turnover), not incident-severity SLAs (P1/P2 MTTA/MTTR — see checkNotificationTiming)',
    ],
    uiPath: 'gd:settings',
  },

  checkLogVolumeReasonable: {
    summary: 'Investigate zero-traffic or DoS conditions',
    steps: [
      'GD\'s request-logging middleware writes one audit_log entry per /api request (except /api/health)',
      'Zero entries in 24h: either GD has received no real traffic (check upstream reverse proxy) or audit logging is broken (verify the middleware is mounted in index.js)',
      'Abnormally high volume (>1M entries/24h): investigate for noise events or DoS attempting to consume SQLite storage; consider rate-limit tuning or upstream WAF rules',
    ],
    uiPath: 'gd:audit',
  },

  // ── checks/data-protection.js ──────────────────────────────────────────────

  checkDataClassification: {
    summary: 'GD data classification is architectural — no action required',
    steps: [
      'GD by design holds only aggregate metrics (regional_metrics, no analyst-identifying fields) and account-level identity (users, CISO/VP/readonly)',
      'The data-boundary is enforced by table absence on the GD (no analyst data tables exist) rather than by per-row classification',
      'Analyst-level data classification (Tier 1/2/3) is enforced at the MC, not the GD',
      'No GD-side configuration needed',
    ],
    uiPath: null,
  },

  checkPseudonymization: {
    summary: 'Pseudonymization is enforced upstream at the MC — no action required',
    steps: [
      'Each MC keys analyst behavioral signals to a pseudonym BEFORE producing aggregate metrics for push to the GD',
      'The GD receives only aggregates; the identity-to-signal linkage never reaches the GD',
      'Verify this guarantee by inspecting regional_metrics — fields are mc_id + various aggregate counts/percentages with no analyst-identifying columns',
      'No GD-side configuration needed; if a future MC release introduces analyst-identifying fields to the push payload, that\'s an upstream concern at the MC level',
    ],
    uiPath: null,
  },

  checkDataSubjectRights: {
    summary: 'Document operator-side data-subject-rights procedures',
    steps: [
      'GD\'s data-subject surface is narrow: only GD users (CISO / VP / readonly accounts) are direct data subjects on the GD',
      'Access: queryable via /api/audit-logs and exportable via /api/audit-logs/export/:format',
      'Erasure: no dedicated /api/users/:id DELETE endpoint as of v0.0.31 — operator-managed via direct DB operations',
      'Rectification: no dedicated /api/users/:id PATCH endpoint as of v0.0.31 — operator-managed via direct DB operations',
      'Document SOPs for handling subject-rights requests until application-layer endpoints ship',
    ],
    uiPath: null,
  },

  checkRetentionPolicy: {
    summary: 'Configure retention_days on active backup schedules',
    steps: [
      'Navigate to GD -> Backup',
      'For each active schedule, set retention_days to a positive integer (90 days is a common SOC-grade baseline; HIPAA retention often higher)',
      'Update via PUT /api/backup-schedules/:id with retention_days',
      'Audit log retention is unbounded on the GD (storage-capacity-limited); no policy configuration is required for audit',
    ],
    uiPath: 'gd:backup',
  },

  checkBackupEncryption: {
    summary: 'Enable encrypted = 1 on all active backup schedules',
    steps: [
      'Navigate to GD -> Backup',
      'For each active schedule with encrypted = 0: update via PUT /api/backup-schedules/:id with encrypted=true',
      'Or recreate the schedule with encrypted=true via POST /api/backup-schedules',
      'Destination-side at-rest encryption (S3 SSE / GCS CMEK / Azure SE / local LUKS) is operator-managed regardless of the in-platform encrypted flag',
    ],
    uiPath: 'gd:backup',
  },

  checkCrossBorderTransferControls: {
    summary: 'Document MC residency and set GD server residency',
    steps: [
      'Navigate to GD -> MCs',
      'For each active MC: ensure country is set (use ISO 3166-1 alpha-2 codes preferred); update via PATCH /api/management-consoles/:id',
      'Set the GD server\'s own residency: PUT /api/config/gd_residency with your jurisdiction details',
      'For cross-border data flows (any MC → GD where countries differ): document the legal basis (Standard Contractual Clauses, adequacy decision, Binding Corporate Rules) off-platform in your DPA archive',
      'A future GD enhancement may add UI for tracking transfer legal bases; currently customer-responsibility documentation only',
    ],
    uiPath: 'gd:mcs',
  },

  // ── checks/resilience.js ───────────────────────────────────────────────────

  checkBackupFrequency: {
    summary: 'Trigger a backup or wait for scheduled backup to run',
    steps: [
      'Navigate to GD -> Backup',
      'If no completed backups: trigger a manual backup via POST /api/backups/trigger to bootstrap',
      'If completed backups exist but none recent (>48h): verify active backup schedules are configured with appropriate frequency',
      'If schedules exist but aren\'t executing: investigate the scheduler (a known limitation in v0.0.31 — the active_schedule count may not yet wire through to backups table insertion; manual triggers still work)',
    ],
    uiPath: 'gd:backup',
  },

  checkBackupMultiDestination: {
    summary: 'Configure backup schedules with distinct destinations',
    steps: [
      'Navigate to GD -> Backup',
      'Add at least 2 active backup schedules pointing to different destinations (e.g., local + S3, or S3 + Azure)',
      'For each schedule: configure destination URL, encrypted=true, retention_days, frequency',
      'Single-destination configurations cannot survive a destination failure; SOC-grade is at least 2 distinct destination types',
    ],
    uiPath: 'gd:backup',
  },

  checkDrTestRecency: {
    summary: 'Perform off-platform DR drill until in-platform DR test infrastructure ships',
    steps: [
      'CURRENT STATE: GD has no application-layer DR test infrastructure (/api/regression-test runs a real integration-test suite but is not a backup-restore drill; no restore workflow)',
      'Off-platform DR drill (SOC-grade norm: quarterly): provision a side-by-side GD instance; restore from backup; verify users/MCs/metrics are correctly recovered; document the drill in your operator runbook',
      'FUTURE STATE: B2 (v1.0.47) builds the regression test runner with real integration tests; B4 (v1.0.49) builds compromise scan orchestration; a future restore-workflow phase would close the DR-drill gap entirely',
      'Until then, schedule and document off-platform drills',
    ],
    uiPath: null,
  },

  checkIrPlanExists: {
    summary: 'Document GD-layer IR procedures off-platform',
    steps: [
      'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31)',
      'Document CISO/governance-tier IR procedures off-platform — in your wiki, DMS, or runbook system',
      'Cover scenarios specific to the GD layer: GD compromise, GD database corruption, suspicious aggregate metrics from an MC, MC api_key compromise, signing-key registry compromise (signing_keys table present)',
      'Reference NIST 800-61 and ISO 27035 for IR program structure',
    ],
    uiPath: null,
  },

  checkNotificationTiming: {
    summary: 'Document incident-severity SLAs off-platform',
    steps: [
      'GD\'s notification_config holds domain thresholds (burnout, SLA, turnover) — not incident MTTA/MTTR',
      'Document P1/P2 incident-response SLAs off-platform: typical SOC-grade is P1 5m MTTA / 60m MTTR, P2 15m MTTA / 4h MTTR',
      'Regulatory notification windows (NIS2 24h, DORA Art.19, GDPR Art.33 72h breach notification) are tracked off-platform per framework customerResponsibility lists',
      'A future GD enhancement may add an sla_config table parallel to MC\'s; until then, off-platform tracking',
    ],
    uiPath: null,
  },

  // ── checks/vuln.js ─────────────────────────────────────────────────────────

  checkMalwareProtection: {
    summary: 'Verify in-platform runtime monitoring; optionally integrate an external EDR',
    steps: [
      'BASELINE (in-platform, B6a): the GD runtime-monitor continuously checks file-integrity over the GD server tree and watches for resource anomalies; findings route through the alert-router to SIEM/SOAR/notification. Confirm it is running under Self-Protection > Runtime, or POST /api/compromise-scan for a point-in-time self-integrity check',
      'EXTERNAL EDR (optional, additive): register a provider under Self-Protection > EDR / Endpoint Monitoring (POST /api/self-protection/config/edr). Supported: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Palo Alto Cortex XDR, Trellix, Sophos Intercept X, VMware Carbon Black, Cisco Secure Endpoint, Wazuh, Elastic Defend, LimaCharlie. Credentials are stored AES-256-GCM-encrypted',
      'HOST ANTIVIRUS (operator option, defense in depth): host-level antivirus on the GD server OS (Microsoft Defender / ClamAV / similar) with on-access scanning of the installation directory and GD_DB_PATH remains a valid additional layer',
    ],
    uiPath: 'gd:self-protection',
  },

  checkPatchManagement: {
    summary: 'Maintain OS / Node.js / dependency patching on the GD',
    steps: [
      'Verify system_meta.fuse_counter is set to a positive integer (seeded by db-init.js)',
      'Operator-side: maintain a regular cadence for OS package updates, Node.js LTS upgrades, and npm dependency security patches',
      'Dependency scanning: `npm audit` in packages/global-dashboard-server/, plus Snyk / Dependabot / similar in CI',
      'Upgrade the GD to new FireAlive releases promptly to receive framework definition updates and security patches',
    ],
    uiPath: null,
  },

  checkVulnScanning: {
    summary: 'Run external vulnerability scans on a quarterly cadence',
    steps: [
      'GD has no in-platform vuln scan history (no scan-result table)',
      'Operator-side: schedule quarterly external scans with Nessus / Qualys / OpenVAS / Trivy / Snyk against the GD deployment environment',
      'CI/CD: integrate dependency vulnerability monitoring (npm audit / Snyk / Dependabot) into the deployment pipeline',
      'Container deployments: scan container images with Trivy / Grype before deployment',
    ],
    uiPath: null,
  },

  checkCloudVulnScanning: {
    summary: 'Use cloud-native vuln scanning on the GD\'s underlying infrastructure',
    steps: [
      'GD has no in-platform cloud vuln scanning (no integration_config table; C2 phase applies to MC, not GD)',
      'Operator-side: enable cloud-native vuln scanning on the GD\'s host VMs, container hosts, and managed databases',
      'AWS: enable Inspector + Security Hub findings + GuardDuty',
      'Azure: enable Defender for Cloud + Defender for Servers',
      'GCP: enable Security Command Center + Container Threat Detection',
      'Third-party alternatives: Wiz / Lacework / Orca / Prisma Cloud',
    ],
    uiPath: null,
  },

  checkIntegrityVerification: {
    summary: 'Operator-managed deployment-artifact integrity until in-platform verifier ships',
    steps: [
      'CURRENT STATE: GD has no startup integrity verifier (no SKIP_INTEGRITY_CHECK env var consumption; no release-manifest.json comparison at boot)',
      'Operator-managed alternatives: use signed installers, verify sha256sum of the GD distribution against published hashes, sign container images with Cosign or Notary if deployed via container',
      'FUTURE STATE: a future GD buildout phase will add a manifest-based verifier (release-manifest.json shipping with each release; boot-time SHA-256 comparison against index.js / db-init.js / package.json)',
      'When the verifier ships: set NODE_ENV=production and do NOT set SKIP_INTEGRITY_CHECK in production',
    ],
    uiPath: null,
  },

  // ── checks/network.js ──────────────────────────────────────────────────────

  checkNetworkSegmentation: {
    summary: 'Configure network-layer isolation of the GD server port',
    steps: [
      'GD has no in-platform network-layer middleware (no preventPivot / validateMtls equivalent of MC\'s network-security module)',
      'Operator-managed: configure firewall rules / network ACLs / security groups to restrict access to GD_PORT (default 4001) to authorized sources only',
      'Inbound: allow only the reverse proxy and the registered MCs (for compliance-report pushes via R3g PR3 signed-push contract)',
      'Outbound: typically minimal (notification delivery, MC heartbeats); explicit allow-list rather than allow-all',
      'No GD-side data tiering — boundary is architectural (analyst data tables do not exist on GD)',
    ],
    uiPath: null,
  },

  checkAntiReplay: {
    summary: 'Operator-managed anti-replay protection until in-platform middleware lands',
    steps: [
      'GD has no anti-replay middleware (no nonce tracking, no sliding-window protection)',
      'JWT 8h expiry provides time-bounded protection only — within the validity window, a stolen JWT is replayable',
      'For the MC → GD push channel: R3g PR3 added anti-replay protection via a 5-minute timestamp skew window enforced by verifyPushSignature in services/mc-signature-verifier.js. Persistent server-side nonce tracking remains a future enhancement (would extend the replay window arbitrarily; the 5-minute bound is the current trade-off).',
      'Until PR3: enforce mTLS at the reverse proxy with strict client-cert pinning for inbound MC connections',
      'For interactive JWT replay: reduce JWT validity at the proxy layer (idle timeout shorter than 8h)',
    ],
    uiPath: null,
  },

  checkRateLimiting: {
    summary: 'Rate limiting is active — no action required',
    steps: [
      'apiLimiter (express-rate-limit) is mounted inline in packages/global-dashboard-server/index.js at /api/* paths',
      'Default: 1000 req per 15-minute window per IP; /api/health is exempt to avoid impacting reverse-proxy health probes',
      'For tighter limits: modify the apiLimiter configuration in index.js and redeploy',
    ],
    uiPath: null,
  },

  checkSystemBoundaries: {
    summary: 'Resolve unhealthy management consoles',
    steps: [
      'Navigate to GD -> MCs',
      'For each MC in a non-active, non-offboarded state: investigate via the MC details endpoint',
      'Offboard MCs that should no longer connect via POST /api/management-consoles/:id/offboard',
      'Re-register MCs that should reconnect (often after credential rotation)',
      'Each MC is the GD\'s third-party data source; unhealthy MCs interrupt cross-region aggregation',
    ],
    uiPath: 'gd:mcs',
  },

  // ── checks/config.js ───────────────────────────────────────────────────────

  checkConfigLockState: {
    summary: 'Wait for GD Config Lock server-side persistence to ship',
    steps: [
      'CURRENT STATE: GD has no config_lock_state table or /api/config/lock route handler; the frontend Config Lock toggle is server-side stubbed',
      'FUTURE STATE: a future BUILD-PLAN-v16 phase will land GD Config Lock server-side persistence (mirroring MC\'s R3e v1.0.32 pattern with TOTP-MFA-gated unlock)',
      'When it ships: in production deployments, enable Config Lock immediately after initial configuration; require TOTP unlock for any subsequent changes',
      'Until then: configuration-change discipline is operator-managed via route-middleware role gating (CISO-only writes) plus audit-log review of CONFIG_UPDATED events',
    ],
    uiPath: null,
  },

  checkAntiRollback: {
    summary: 'Wait for GD startup integrity verifier to ship',
    steps: [
      'CURRENT STATE: the GD manifest now declares a fuseCounter (added in B6a), but there is still no startup version-vs-fuse comparison; system_meta.fuse_counter remains informational with no enforcement at startup',
      'Operator-managed alternative: maintain deployment-artifact discipline (signed installers, verified sha256sum, container image signing) to prevent rollback at the build/deploy layer',
      'FUTURE STATE: the GD startup-verifier phase should add the boot-time check that refuses to start if package.json fuseCounter < system_meta.fuse_counter (the rollback signal); the manifest fuseCounter field itself was added in B6a',
      'Track in your operator runbook to upgrade the GD to higher fuseCounter releases as they ship and not downgrade',
    ],
    uiPath: null,
  },

  checkSecureBaseline: {
    summary: 'Set NODE_ENV=production and harden via reverse proxy',
    steps: [
      'Set NODE_ENV=production in the GD deployment environment (for industry convention; no in-platform middleware is currently gated on it)',
      'Reverse-proxy-layer hardening (operator-managed): TLS 1.2 minimum, HSTS, X-Frame-Options DENY, Content-Security-Policy, X-Content-Type-Options nosniff',
      'Network isolation: GD port not directly internet-exposed; route inbound traffic only through the reverse proxy',
      'Segregate the GD management network from analyst-facing networks (which talk to the MC, not the GD)',
    ],
    uiPath: null,
  },

  // ── checks/third-party.js ──────────────────────────────────────────────────

  checkIntegrationHealth: {
    summary: 'Refresh stale MCs and unhealthy integrations',
    steps: [
      'Layer 1 — MCs: navigate to GD -> MCs; for each MC with stale last_sync (>24h): investigate MC connectivity, push scheduler health, network path',
      'Layer 2 — integrations (post-B5b v1.0.51): navigate to GD -> Integrations; test stale integrations (>30d) and resolve errored integrations',
      'Combine: any integration in error state OR stale beyond threshold triggers a warning',
      'Configure upstream alerting (PagerDuty / Opsgenie / similar) on prolonged stale-MC conditions',
    ],
    uiPath: 'gd:mcs',
  },

  checkVendorRiskAssessment: {
    summary: 'Document MC jurisdiction metadata and test integrations',
    steps: [
      'Layer 1 — MCs: for each active MC, ensure country and regulatory_framework are populated (PATCH /api/management-consoles/:id)',
      'Layer 2 — integrations (post-B5b v1.0.51): test every configured integration at least once after configuration to establish baseline operational evidence',
      'Off-platform: formal vendor risk assessment (questionnaires, SOC 2 report review, DPA negotiation) remains customer-responsibility regardless of in-platform documentation',
      'For each MC vendor (the SOC operator running that MC), maintain a vendor file: contract, SOC 2 report if available, DPA, contact information',
    ],
    uiPath: 'gd:mcs',
  },

  checkKmsProviderTrust: {
    summary: 'Probe and refresh KMS providers when the table ships',
    steps: [
      'CURRENT STATE: kms_providers table not present on the GD; no per-provider probe history to evaluate',
      'FUTURE STATE: a future GD KMS integration phase introduces kms_providers; navigate to GD -> Integrations -> KMS to configure',
      'Once configured: the platform should probe each enabled provider every few hours; investigate any providers with failed or stale probes (>7 days)',
      'Refresh stale providers by re-testing connectivity from the GD -> Integrations -> KMS detail view',
    ],
    uiPath: null,
  },

  checkSigningKeyRegistry: {
    summary: 'Maintain signing-key registries: review pending registrations and provision keys for unshipped registries',
    steps: [
      'signing_keys (MC-trust verification, R3g PR3): SHIPPED. Pending registrations are surfaced by GET /api/signing-keys/pending. Review and act:',
      '  - POST /api/mc/<mcId>/signing-keys/<keyId>/approve to promote a pending key to approved + active',
      '  - POST /api/mc/<mcId>/signing-keys/<keyId>/reject to reject a key (operator must contact CISO out-of-band for the rejection reason — the MC-facing status endpoint deliberately does not surface it)',
      '  - Stale pending registrations (>7 days) suggest a neglected review queue — see checkRoleSegregationCisoApprover for role-assignment guidance',
      '  - For signing-key rotation lifecycle (operator triggers /rotate; CISO approves; grace window covers in-flight pushes): see checkSigningKeyRotationCadence',
      'Future GD backup-signing phase will introduce backup_signing_keys + chain_signing_keys: GD\'s own backup manifest and chain signing (parallel to MC R3d-5 pattern). Until then GD backup integrity is hash-only (no cryptographic signature).',
      'When the backup-signing registries land: provision at least one active key for each registered signing role; rotate per documented cadence (typically 6-12 months for Ed25519)',
    ],
    uiPath: 'gd:signing-keys',
  },

  // ── R3g PR3 Phase 9 (C42): operator-practice entries for PR3-shipped surfaces ──
  // These keys are not yet referenced by check functions; they are
  // forward-compatible documentation slots for the post-PR3 operator
  // practices (signing-key rotation lifecycle, mailbox-pattern
  // operator notes, role-segregation reminder). Future check
  // functions that surface these signals will reference them by name.

  checkSigningKeyRotationCadence: {
    summary: 'Rotate MC-push signing keys on a documented cadence with CISO approval',
    steps: [
      'WHO triggers: operator at the MC (the entity holding the active push signing key)',
      'HOW: POST /api/gd-signing-key/rotate on the MC. The route stages a fresh Ed25519 keypair, marks it pending_approval=1, and submits the new public key to the GD via C18 (POST /api/mc/<id>/signing-key)',
      'WHO approves: CISO or signing_key_approver at the GD via POST /api/mc/<mcId>/signing-keys/<keyId>/approve (Commit 19). Role segregation: see checkRoleSegregationCisoApprover',
      'GRACE WINDOW: when the new key is approved, the prior key is demoted (is_active=0, rotated_out_at=now) but remains in signing_keys with approval_status=\'approved\'. The verifier (C22 Path B) accepts signatures from the demoted key for the configured grace_period_minutes (default 60, range 0-1440). This covers in-flight pushes that signed under the previous key',
      'CADENCE: industry norm is 6-12 months for Ed25519 keys. Emergency rotation (suspected compromise): set signing_key_grace_period_minutes to 0 before approving the replacement; the old key dies immediately on the new key\'s approval',
      'MONITORING: checkSigningKeyRegistry (in checks/third-party.js) surfaces the population of approved active keys and any stale-pending review queue',
    ],
    uiPath: 'gd:signing-keys',
  },

  checkMailboxFulfillmentLatency: {
    summary: 'Tune compliance-tick cadence when full-report request fulfilment is too slow',
    steps: [
      'The mailbox pattern (R3g PR3 Phase 7): CISO requests a full report via POST /api/mc/<id>/full-report-requests (C33). The request lands as a pending row in mc_report_requests. The MC observes the pending row on its NEXT compliance tick and POSTs the generated full report back via /api/ingest/compliance-reports?full=true (C35). Fulfilment latency = up to one compliance-tick interval.',
      'DEFAULT CADENCE: compliance_push_cadence_hours = 24 (set in gd_push_config on the MC side, seeded by R3g PR3 Phase 2 / Commit 6). Range 1-720 hours.',
      'TUNING: if a CISO routinely needs faster turnaround, reduce the MC-side cadence: PUT /api/gd-config on the MC with compliance_push_cadence_hours = 4 (or whatever interval fits the review workflow). Lower cadences increase compliance push traffic to the GD; balance against total ingest volume',
      'STALENESS SIGNAL: pending requests older than the cadence + grace period (e.g., older than 25h with a 24h cadence) suggest the MC compliance tick has stopped firing — check gd_push_config.enabled=1, decrypt errors in audit_log, and the circuit breaker state (consecutive_failures column)',
      'NO ALERTING YET: a future GD enhancement may add an alert when pending requests exceed a configurable age threshold; until then this is operator-monitored via GET /api/audit-logs?event_type=COMPLIANCE_FULL_REPORT_REQUESTED',
    ],
    uiPath: 'gd:audit-logs',
  },

  checkRoleSegregationCisoApprover: {
    summary: 'Assign signing_key_approver to a user distinct from any ciso to enforce role segregation',
    steps: [
      'CONTROL CONTEXT: ISO 27001 A.6.1.2 Segregation of duties; NIST 800-53 AC-5; SOC 2 CC1.3. The compliance principle: the user who registers a new MC should NOT be the same user who establishes its cryptographic trust',
      'PLATFORM SUPPORT: R3g PR3 Phase 5 (Commit 15) introduced the signing_key_approver role. The approve/reject endpoints (Commits 19) accept either ciso OR signing_key_approver',
      'GUIDANCE: in orgs with >1 administrator, assign signing_key_approver to a user distinct from the ciso. POST /api/users (or your IdP-provisioning equivalent) with role=\'signing_key_approver\'',
      'SMALL ORGS: in single-administrator deployments, the ciso may hold both roles. The audit log records the acting role distinctly on each approval (approved_by_role column on signing_keys), so reviewers can see whether segregation was actually exercised',
      'AUDIT REVIEW: GET /api/audit-logs?event_type=MC_SIGNING_KEY_APPROVED. Look at the approver user id vs the original MC registrant (from MC_REGISTERED events). Matching IDs indicate unexercised segregation; distinct IDs document the control',
    ],
    uiPath: 'gd:users',
  },
};

module.exports = REMEDIATIONS;
