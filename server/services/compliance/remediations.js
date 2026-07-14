// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Remediation Map
//
// R3g (v1.0.33): when a compliance check returns 'warning' or 'fail'
// status, the administrator needs to know what to do about it. The
// detail field describes WHAT was found; this file describes WHAT TO
// DO. The two together make compliance reports actionable rather than
// merely diagnostic -- the half of GRC tooling that makes the
// difference between "audit-prep helper" and "decoration."
//
// USAGE
//
// generateComplianceReport (in server/services/compliance/index.js)
// looks up the remediation by the check function's name property:
//
//   const remediation = REMEDIATIONS[ctrl.check.name] || null;
//   if (status !== 'pass' && remediation) {
//     // include remediation in the per-control output
//   }
//
// The lookup is by function name, which is stable across the codebase
// (the named function declarations all have name === 'checkXxx' that
// matches their export key). Both files that contain a function named
// 'checkAuditIntegrity' (index.js + audit.js) and 'checkChangeManagement'
// (index.js + config.js) share the same remediation entry by design --
// the underlying control area is the same.
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
//     uiPath: 'mc:admin/users' or 'gd:integrations' or null
//       The uiPath uses the format <app>:<route-hint> where app is
//       one of 'mc' (Management Console), 'gd' (Global Dashboard),
//       or 'ac' (Analyst Client). The route-hint is a path that the
//       PR2 frontend implementation will resolve into a deep link.
//       uiPath: null means there is no single UI destination
//       (typically configuration outside the platform UI, like env
//       vars or deployment manifests).
//   }
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const REMEDIATIONS = {

  // ── Carried-forward check functions in compliance/index.js ─────────────────

  checkAccessControl: {
    summary: 'Ensure user roles and API keys are provisioned',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'Verify at least one user exists per required role (analyst, lead, admin)',
      'For programmatic access, create scoped API keys via MC -> Admin -> API Keys',
      'Each API key must have explicit scopes (comma-separated: health:read, siem:read, etc.)',
    ],
    uiPath: 'mc:admin/users',
  },

  checkUniqueUsers: {
    summary: 'Resolve duplicate username conflicts',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'Identify duplicate usernames in the report',
      'For each duplicate, either deactivate the older account (set active = 0) or rename one',
      'Username uniqueness is required for unambiguous audit-log attribution',
    ],
    uiPath: 'mc:admin/users',
  },

  checkEncryption: {
    summary: 'Configure Tier-1 and Tier-3 encryption keys',
    steps: [
      'Generate keys: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      'Set TIER1_ENCRYPTION_KEY and TIER3_ENCRYPTION_KEY in the deployment environment',
      'Keys must be DIFFERENT from each other (collapsing them defeats tier-based encryption segmentation)',
      'Restart the platform to pick up the new env vars',
    ],
    uiPath: null,
  },

  checkRBAC: {
    summary: 'Define at least two distinct roles',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'Ensure users are assigned across multiple roles, not all under one role',
      'SOC-grade SoD requires at least admin + lead role separation',
    ],
    uiPath: 'mc:admin/users',
  },

  checkAuditControls: {
    summary: 'Ensure audit logging is active',
    steps: [
      'No action required if events are flowing into audit_log',
      'If audit_log is empty: verify auditMiddleware is mounted at /api/ in server/index.js',
      'For SIEM streaming, set SIEM_ENABLED=true and configure SIEM via MC -> Admin -> Integrations',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkAuthentication: {
    summary: 'Verify JWT signing secret is configured',
    steps: [
      'Set JWT_SECRET in the deployment environment (32+ character random string)',
      'For SSO, configure SAML / OIDC / LDAP via MC -> Admin -> IAM Integrations',
      'Restart the platform after JWT_SECRET changes (invalidates all existing tokens)',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkTransmission: {
    summary: 'Set NODE_ENV=production and configure TLS at the reverse proxy',
    steps: [
      'Set NODE_ENV=production in the deployment environment',
      'Configure your reverse proxy (nginx / Caddy / cloud load balancer) with TLS 1.2 or higher',
      'Use a CA-issued certificate (not self-signed) for production',
      'The enforceMinTls middleware will reject non-HTTPS requests once NODE_ENV=production',
    ],
    uiPath: null,
  },

  checkBoundaries: {
    summary: 'Configure integrations to define system boundaries',
    steps: [
      'Navigate to MC -> Admin -> Integrations',
      'Configure SOAR / SIEM / ticketing / IAM integrations as needed',
      'Run integration tests for each to confirm operational status',
      'Each integration represents a defined boundary; document them as part of system inventory',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkAnomalyDetection: {
    summary: 'Verify anomaly detection middleware is active',
    steps: [
      'No action required when bandwidth monitor and rate limiter middleware are loaded',
      'Verify in server/index.js: bandwidthMonitor.middleware() and apiLimiter are app.use()d',
      'For deeper anomaly detection, configure SIEM integration for correlation analytics',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkChangeManagement: {
    summary: 'Verify anti-rollback fuse and audit change events',
    steps: [
      'Confirm package.json fuseCounter is set to a positive integer',
      'Confirm server/db/init.js writes the fuse to system_meta on startup',
      'All configuration changes route through audit_log via auditLog() calls in route handlers',
      'Review recent change events via MC -> Audit Log -> filter by event_type LIKE "%CONFIG%"',
    ],
    uiPath: 'mc:admin/audit-log',
  },

  checkIncidentResponse: {
    summary: 'Upload at least one incident response policy',
    steps: [
      'Navigate to MC -> Admin -> Policies (or IR Plans tab)',
      'Upload IR documents tagged with policy_type "incident_response" or "playbook"',
      'Recommend at least: one Incident Response Plan + 2-3 scenario playbooks',
      'Documents are content-hashed and versioned for change tracking',
    ],
    uiPath: 'mc:admin/policies',
  },

  checkBackups: {
    summary: 'Configure backup destinations and verify a backup completes',
    steps: [
      'Navigate to MC -> Admin -> Backup',
      'Add at least one backup destination (local, sftp, s3, azure-blob, or gcs)',
      'Configure backup schedule (recommend daily or more frequent)',
      'Run a manual backup to verify the destination is reachable',
      'After first backup completes, this check passes',
    ],
    uiPath: 'mc:admin/backup',
  },

  // ── checks/access.js ───────────────────────────────────────────────────────

  checkPasswordPolicy: {
    summary: 'Password policy is hardcoded at 12-character minimum',
    steps: [
      'No action required -- MIN_PASSWORD_LENGTH = 12 is enforced in server/routes/password.js',
      'If your organization requires a higher minimum, update MIN_PASSWORD_LENGTH and rebuild',
      'bcrypt hashing is automatic on user creation and password change',
    ],
    uiPath: null,
  },

  checkSessionTimeout: {
    summary: 'Set JWT_EXPIRY to 30 minutes or less',
    steps: [
      'Set JWT_EXPIRY environment variable to a value <= 30m (e.g., "15m", "30m")',
      'Valid format: <number><unit> where unit is s/m/h/d',
      'Restart the platform to pick up the new value',
      'Refresh token rotation handles long-running sessions transparently',
    ],
    uiPath: null,
  },

  checkAccountLockout: {
    summary: 'No action -- rate limiting is structurally enforced',
    steps: [
      'apiLimiter (express-rate-limit) is hardcoded at 1000 req / 15 min in server/index.js',
      'Failed-login attempts are tracked in auth_log via action LIKE "%FAIL%"',
      'For IP-based blocking, integrate auth_log with your reverse proxy or fail2ban',
      'No platform-level configuration required',
    ],
    uiPath: null,
  },

  checkMfaEnforcement: {
    summary: 'Enable MFA enforcement for all active users',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'For each active user without a hardware passkey enrolled, set mfa_enrollment_required = 1',
      'Affected users must enroll a FIDO2 hardware passkey before login will issue a session',
      'Bulk SOC-grade default: run the migration that sets mfa_enrollment_required = 1 for all users',
      'Passkey enrollment uses the MFA tab: register a hardware security key (FIDO2, user-verified)',
    ],
    uiPath: 'mc:admin/users',
  },

  checkPrivilegedSeparation: {
    summary: 'Reduce admin role headcount or audit assignments',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'Review users with role = "admin"; SoD norm is admins <= 25% of active users',
      'Demote unnecessary admin accounts to "lead" as appropriate',
      'For SoD audit trail: every role change is recorded in audit_log via USER_ROLE_CHANGED events',
    ],
    uiPath: 'mc:admin/users',
  },

  checkApiKeyRotation: {
    summary: 'Rotate API keys older than 90 days',
    steps: [
      'Navigate to MC -> Admin -> API Keys',
      'Identify keys with created_at older than 90 days',
      'For each: generate a new key, update all consumers (SOAR scripts, monitoring tools, etc.)',
      'Revoke the old key (set revoked = 1) after consumers are migrated',
      'Recommend rotation cadence: 90 days for production, 30 days for high-sensitivity scopes',
    ],
    uiPath: 'mc:admin/api-keys',
  },

  checkIamIntegrationHealth: {
    summary: 'Resolve errored IAM/SSO integrations',
    steps: [
      'Navigate to MC -> Admin -> IAM Integrations',
      'For each integration in error status, click "Test Connection" to diagnose',
      'Common failures: expired client secret, certificate chain mismatch, IdP-side config drift',
      'Affected users may be unable to authenticate via SSO until remediated',
      'Local bcrypt auth remains available as fallback for the duration of the outage',
    ],
    uiPath: 'mc:admin/iam-integrations',
  },

  checkRoleSeparation: {
    summary: 'Ensure Config Lock is held by an admin-role user',
    steps: [
      'If Config Lock is active but locked_by_user_id references a non-admin: this is a SoD violation',
      'Unlock the configuration (admin + a WebAuthn hardware-passkey step-up) then re-lock from a current admin account',
      'If the original user was demoted after locking, this stale state is now correct to clear',
      'Navigate to MC -> Admin -> Config Lock to manage the lock state',
    ],
    uiPath: 'mc:admin/config-lock',
  },

  // ── checks/crypto.js ───────────────────────────────────────────────────────

  checkKeyRotation: {
    summary: 'Rotate backup signing keys older than 180 days',
    steps: [
      'Navigate to MC -> Admin -> Backup Signing Keys',
      'For each active local-generated key older than 180 days, click "Rotate"',
      'The platform generates a new Ed25519 keypair and marks the old key rotated_out_at',
      'Cross-deployment trust is preserved: SPKI fingerprints in v3 manifests survive rotation',
      'External-registered keys (from partner deployments) rotate on the partner side',
    ],
    uiPath: 'mc:admin/backup-signing-keys',
  },

  checkAlgorithmStrength: {
    summary: 'Set 64-character hex encryption keys for AES-256',
    steps: [
      'Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      'Set TIER1_ENCRYPTION_KEY and TIER3_ENCRYPTION_KEY in the deployment environment',
      'Each value must be exactly 64 hex characters (32 bytes = 256 bits for AES-256)',
      'Keys must NOT start with "CHANGE_ME" (placeholder value)',
      'Restart the platform after setting the env vars',
    ],
    uiPath: null,
  },

  checkTlsMinVersion: {
    summary: 'Set NODE_ENV=production and configure proxy TLS 1.2+',
    steps: [
      'Set NODE_ENV=production in the deployment environment',
      'Configure the reverse proxy with minVersion TLSv1.2 or higher',
      'For nginx: ssl_protocols TLSv1.2 TLSv1.3;',
      'For Caddy: tls { protocols tls1.2 tls1.3 }',
      'For cloud LBs: select TLS policy "ELBSecurityPolicy-TLS-1-2-2017-01" or stronger',
    ],
    uiPath: null,
  },

  checkKmsProvider: {
    summary: 'Configure an external KMS provider',
    steps: [
      'Navigate to MC -> Admin -> KMS Providers',
      'Click "Add Provider" and select provider_type (aws-kms / azure-keyvault / gcp-kms / hashicorp-vault)',
      'Provide credentials (encrypted at rest in credentials_encrypted column)',
      'Set is_default = 1 on the production provider',
      'Click "Probe" to test connectivity; last_probe_status should report "ok"',
    ],
    uiPath: 'mc:admin/kms-providers',
  },

  checkCertValidity: {
    summary: 'Use a CA-issued certificate at the reverse proxy',
    steps: [
      'Obtain a certificate from a public CA (Let\'s Encrypt, DigiCert, etc.) for your deployment hostname',
      'Configure the reverse proxy with the cert + private key',
      'Set up automated renewal (certbot, cert-manager, or cloud provider auto-renewal)',
      'Self-signed certs are NOT acceptable for production',
      'Cert lifecycle (issuance, renewal, monitoring) is operator-responsibility',
    ],
    uiPath: null,
  },

  // ── checks/audit.js ────────────────────────────────────────────────────────

  checkAuditRetention: {
    summary: 'Plan audit_log storage capacity for regulatory retention',
    steps: [
      'The platform does not auto-truncate audit_log; retention is bounded by storage capacity',
      'Estimate audit_log growth: ~1KB per event * peak events/day * retention period',
      'Provision storage to accommodate at least 1 year (SOC-grade), 6 years (HIPAA), 7 years (SOC 2)',
      'For SIEM-side retention: configure SIEM platform with regulatory-appropriate retention',
      'The age of the oldest audit_log entry reflects deployment age, not policy enforcement',
    ],
    uiPath: null,
  },

  checkAuditIntegrity: {
    summary: 'Enable SIEM streaming for external tamper-evidence',
    steps: [
      'Set SIEM_ENABLED=true in the deployment environment',
      'Navigate to MC -> Admin -> Integrations and add an integration of type "siem"',
      'Provide SIEM endpoint (host:port for syslog, URL for HTTP), authentication, and CEF formatting',
      'Click "Test Connection" to verify; status should change to "operational"',
      'Restart the platform after setting SIEM_ENABLED',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkSyslogExport: {
    summary: 'Configure SIEM/syslog export destination',
    steps: [
      'Navigate to MC -> Admin -> Integrations',
      'Add integration of type "siem"; provide platform (Splunk / QRadar / Sentinel / etc.), host, port',
      'Choose CEF format for standardized SIEM correlation',
      'Test the connection and verify status = "operational"',
      'Alternative: set config.siem_config key directly via the underlying API',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkForensicsExport: {
    summary: 'No action -- forensics export endpoint is structurally mounted',
    steps: [
      'GET /api/audit/export-forensics is registered at startup (compliance-monitoring router)',
      'Endpoint requires admin role + valid JWT',
      'Returns audit_log entries with chain-of-custody metadata and integrity hash',
      'Test via API: curl -H "Authorization: Bearer <token>" /api/audit/export-forensics',
    ],
    uiPath: null,
  },

  checkAlertingThresholds: {
    summary: 'Configure notification thresholds and at least one delivery channel',
    steps: [
      'Navigate to MC -> Admin -> Notifications (or Alerting Settings)',
      'Set the threshold (watch / stressed / critical) per your monitoring strategy',
      'Enable at least one delivery channel: email, SMS, webhook, or PagerDuty',
      'Provide the delivery target (email address / SMS number / webhook URL / PagerDuty key)',
      'Test alert delivery via the "Send Test Notification" button',
    ],
    uiPath: 'mc:admin/notifications',
  },

  checkLogVolumeReasonable: {
    summary: 'Investigate zero audit_log volume or volume spike',
    steps: [
      'For zero volume in 24h: check that auditMiddleware is loaded and applied to /api/',
      'Verify audit_log INSERTs are not silently failing (check application logs)',
      'For unusually high volume: check for runaway event loops or denial-of-service conditions',
      'Examine event_type distribution: SELECT event_type, COUNT(*) FROM audit_log WHERE timestamp > datetime("now", "-1 hour") GROUP BY event_type',
    ],
    uiPath: 'mc:admin/audit-log',
  },

  // ── checks/data-protection.js ──────────────────────────────────────────────

  checkDataClassification: {
    summary: 'Assign tier classifications to all active users',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'For each user without a tier, set tier to 1 / 2 / 3 based on data sensitivity',
      'Tier-3: highest sensitivity (analyst PII, behavioral signals)',
      'Tier-2: moderate (operational data)',
      'Tier-1: lower sensitivity (general configuration)',
      'Bulk-assign via the User Management bulk edit panel',
    ],
    uiPath: 'mc:admin/users',
  },

  checkPseudonymization: {
    summary: 'Generate pseudonyms for analyst users',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'Filter by role = "analyst"',
      'For each analyst without a pseudonym, click "Generate Pseudonym"',
      'Pseudonym becomes the storage key for burnout / capacity / behavioral signals',
      'Direct identity-signal linkage is severed once pseudonym is set',
      'Schedule periodic rotation (sets pseudonym_rotated_at) for right-to-erasure compliance',
    ],
    uiPath: 'mc:admin/users',
  },

  checkDataSubjectRights: {
    summary: 'No action -- DSR mechanisms are structurally available',
    steps: [
      'Access / portability: POST /api/data-subject/export returns the subject record across every store (an analyst bundle sealed to the analyst key)',
      'Erasure: dual-control POST /api/data-subject/erase deletes personal rows and crypto-shreds analyst key material, then tombstones the user (audit retained, de-identified)',
      'Right-to-erasure via re-keying: rotate user pseudonym to sever identity-signal linkage',
      'Rectification: standard user-update endpoints permit data correction',
      'Document the DSR-handling process for your privacy operations team',
    ],
    uiPath: 'mc:admin/users',
  },

  checkRetentionPolicy: {
    summary: 'Configure retention_days on backup destinations',
    steps: [
      'Navigate to MC -> Admin -> Backup -> Destinations',
      'For each enabled destination, set retention_days to the regulatory minimum',
      'Common values: 30 (daily rotation), 90 (quarterly), 365 (annual), 2555 (HIPAA 7-year)',
      'The backup-push service enforces retention by pruning old backups at the destination',
      'audit_log retention is unbounded (no auto-truncation); provision storage accordingly',
    ],
    uiPath: 'mc:admin/backup',
  },

  checkBackupEncryption: {
    summary: 'Re-save backup destinations to encrypt credentials',
    steps: [
      'Navigate to MC -> Admin -> Backup -> Destinations',
      'For each non-local destination with NULL credentials_encrypted: click "Edit" and re-save',
      'The credentials field is encrypted at rest via TIER1_ENCRYPTION_KEY on save',
      'For destination-side encryption (S3 SSE, GCS CMEK, Azure Storage Encryption): configure at the cloud provider',
      'Destination-side encryption is customer-responsibility (enumerated in framework definitions)',
    ],
    uiPath: 'mc:admin/backup',
  },

  checkCrossBorderTransferControls: {
    summary: 'Populate geo_country for active users',
    steps: [
      'Navigate to MC -> Admin -> User Management',
      'For each active user, set geo_country to the ISO 3166-1 alpha-2 code of their primary work location',
      'Bulk-import via the SSO integration if your IdP supplies country claims',
      'For cross-region backup transfers, document the legal basis (SCCs / adequacy decision / BCRs) externally',
      'Backup destination region is in the destination config JSON',
    ],
    uiPath: 'mc:admin/users',
  },

  // ── checks/resilience.js ───────────────────────────────────────────────────

  checkBackupFrequency: {
    summary: 'Configure and verify automated backup schedules',
    steps: [
      'Navigate to MC -> Admin -> Backup -> Schedules',
      'Add a schedule with type "full" or "incremental"',
      'Set interval (recommended: 24h or shorter for production)',
      'Ensure the Backup storage route has a destination configured (MC -> Admin -> Backup, Storage Routing) so scheduled backups have a push target',
      'Run a manual backup to verify the schedule + destination path works end-to-end',
      'Confirm backup_pushes.status = "succeeded" within 48 hours',
    ],
    uiPath: 'mc:admin/backup',
  },

  checkBackupMultiDestination: {
    summary: 'Add a second destination to the backup route',
    steps: [
      'Navigate to MC -> Admin -> Backup (Storage Routing)',
      'Confirm the Backup route has a primary destination assigned',
      'In the Storage Destinations registry, ensure a second destination of a different adapter type exists (redundant pairs: local + S3, S3 + GCS, SFTP + Azure Blob)',
      'Set that destination as the Backup route\'s secondary; every backup is then written to both destinations on each run',
      'A single remote destination cannot survive a destination failure; a primary plus a secondary yields an on-host copy plus two remote copies (3-2-1)',
      'Run a manual backup and confirm both destinations receive the artifact (a succeeded backup_pushes row for each)',
    ],
    uiPath: 'mc:admin/backup',
  },

  checkDrTestRecency: {
    summary: 'Execute a DR drill via the restore workflow',
    steps: [
      'Navigate to MC -> Admin -> Backup -> Restores',
      'Click "Request Restore" and select a recent backup',
      'Choose approval mode (strict / delayed-self-approval / disabled) per your SoD policy',
      'The second admin approves with a fresh user-verified WebAuthn assertion for second-person approval (if strict mode)',
      'Click "Consume Approval" to execute the restore against a test environment',
      'SOC-grade norm: at least quarterly DR testing',
    ],
    uiPath: 'mc:admin/backup',
  },

  checkIrPlanExists: {
    summary: 'Upload incident response plans and playbooks',
    steps: [
      'Navigate to MC -> Admin -> Policies',
      'Click "Upload Policy" and select policy_type "incident_response" or "playbook"',
      'Upload your existing IR documents (Word, PDF, Markdown)',
      'Documents are content-hashed and versioned automatically',
      'Recommended: at least 1 IR Plan + 3-5 scenario playbooks covering common attack types',
      'Tag scenarios via scenario_tags for retrieval during incidents',
    ],
    uiPath: 'mc:admin/policies',
  },

  checkNotificationTiming: {
    summary: 'Configure incident-notification SLAs in sla_config',
    steps: [
      'Navigate to MC -> Admin -> SLA Configuration',
      'Set P1 MTTA (Mean Time To Acknowledge) -- recommended: 5m for SOC-grade',
      'Set P1 MTTR (Mean Time To Resolve) -- recommended: 60m for SOC-grade',
      'Set P2 MTTA / MTTR -- recommended: 15m / 4h',
      'These are internal SLAs; external regulatory timings (NIS2 24h, GDPR 72h) are documented separately',
    ],
    uiPath: 'mc:admin/sla',
  },

  // ── checks/vuln.js ─────────────────────────────────────────────────────────

  checkMalwareProtection: {
    summary: 'Enable at least one malware scanner integration',
    steps: [
      'Navigate to MC -> Admin -> Malware Scanners',
      'Click "Add Provider" and choose from 15 supported types (ClamAV, VirusTotal, CrowdStrike, Microsoft Defender, etc.)',
      'Provide credentials (encrypted at rest in credentials_encrypted)',
      'Set priority for multi-provider redundancy (lower number = higher priority)',
      'Click "Test" to verify the provider responds; last_test_status should be "success"',
    ],
    uiPath: 'mc:admin/malware-scanners',
  },

  checkPatchManagement: {
    summary: 'Ensure fuse_counter is initialized and integrity check is active',
    steps: [
      'Verify package.json has a numeric "fuseCounter" field (current: 25 at v1.0.32)',
      'Run server/db/init.js to write the fuse to system_meta if not already set',
      'Verify SKIP_INTEGRITY_CHECK is NOT set to "true" in the deployment environment',
      'Restart the platform; startup integrity check will validate fuse vs. version',
    ],
    uiPath: null,
  },

  checkVulnScanning: {
    summary: 'Configure and exercise malware scanners; address infra vuln scanning separately',
    steps: [
      'For platform-side: navigate to MC -> Admin -> Malware Scanners and run scans on suspect files',
      'For infrastructure: use operator tooling (Nessus / Qualys / OpenVAS / Trivy) against deployment hosts and dependencies',
      'Schedule infrastructure scans at least weekly per SOC-grade norm',
      'Document infrastructure scan results externally; the platform does not store them (in-platform infra scanning is the C2 phase, deferred)',
    ],
    uiPath: 'mc:admin/malware-scanners',
  },

  checkCloudVulnScanning: {
    summary: 'Run cloud-native vuln scanning at the cloud provider',
    steps: [
      'AWS: enable AWS Inspector and Security Hub for asset / container / Lambda scanning',
      'Azure: enable Microsoft Defender for Cloud (formerly Azure Security Center)',
      'GCP: enable Security Command Center and Container Threat Detection',
      'Connect findings to the platform via cloud-integration types (cloud_aws / cloud_gcp / cloud_azure)',
      'In-platform cloud vuln scanning is the C2 phase, deferred per BUILD-PLAN-v14',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkIntegrityVerification: {
    summary: 'Unset SKIP_INTEGRITY_CHECK in production',
    steps: [
      'Remove SKIP_INTEGRITY_CHECK from the deployment environment, or set it to anything other than "true"',
      'Restart the platform; startup integrity check will validate code and version state',
      'SKIP_INTEGRITY_CHECK=true is acceptable ONLY in development environments',
      'Production deployments MUST run the integrity check at startup',
    ],
    uiPath: null,
  },

  // ── checks/network.js ──────────────────────────────────────────────────────

  checkNetworkSegmentation: {
    summary: 'Set distinct values for TIER1 and TIER3 encryption keys',
    steps: [
      'If keys are the same: generate two new distinct keys',
      'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))" (run twice)',
      'Set TIER1_ENCRYPTION_KEY and TIER3_ENCRYPTION_KEY to the two different values',
      'Restart the platform after changing keys',
      'Note: changing keys requires re-encrypting existing Tier-3 data (operator-managed migration)',
    ],
    uiPath: null,
  },

  checkAntiReplay: {
    summary: 'Verify security-hardening middleware is loadable',
    steps: [
      'Confirm server/middleware/security-hardening.js exists and exports antiReplay',
      'Verify in server/index.js: antiReplay is imported and applied via app.use()',
      'If module unresolvable: the deployment is broken -- restore from backup or redeploy',
      'No runtime configuration; middleware activates at startup',
    ],
    uiPath: null,
  },

  checkRateLimiting: {
    summary: 'Verify express-rate-limit dependency is installed',
    steps: [
      'Confirm express-rate-limit is in package.json dependencies',
      'Run npm install (or your platform\'s equivalent) to ensure node_modules is populated',
      'Verify apiLimiter is configured in server/index.js (windowMs=15min, max=1000)',
      'If dependency unresolvable: the deployment is broken -- redeploy with full node_modules',
    ],
    uiPath: null,
  },

  checkSystemBoundaries: {
    summary: 'Resolve errored integrations',
    steps: [
      'Navigate to MC -> Admin -> Integrations',
      'For each integration in error state: click "Test Connection" to diagnose',
      'Common failures: expired credentials, endpoint URL changes, firewall blocking',
      'Update integration config or disable the integration if it is no longer needed',
      'Status should return to "operational" once the underlying issue is resolved',
    ],
    uiPath: 'mc:admin/integrations',
  },

  // ── checks/config.js ───────────────────────────────────────────────────────

  checkConfigLockState: {
    summary: 'Activate Config Lock for production',
    steps: [
      'Confirm all platform configuration is correct (integrations, KMS, backup destinations, users)',
      'Navigate to MC -> Admin -> Config Lock',
      'Click "Lock Configuration"',
      'Verify with a WebAuthn hardware-passkey step-up (admin role required)',
      'Subsequent configuration changes will require unlock + admin role + a WebAuthn hardware-passkey step-up',
      'Production deployments should remain locked except during planned maintenance',
    ],
    uiPath: 'mc:admin/config-lock',
  },

  checkAntiRollback: {
    summary: 'Resolve fuse mismatch between package.json and system_meta',
    steps: [
      'Compare package.json fuseCounter against system_meta.fuse_counter via SQL',
      'If package.json is newer: the DB needs migration -- run server/db/init.js (it will reconcile)',
      'If DB is newer: an attempted rollback has been detected -- review release history',
      'If unexplained: investigate possible DB tampering via audit_log review',
      'Never manually edit system_meta.fuse_counter to "fix" a mismatch',
    ],
    uiPath: null,
  },

  checkSecureBaseline: {
    summary: 'Set NODE_ENV=production in production deployments',
    steps: [
      'Set NODE_ENV=production in the deployment environment (systemd unit, docker env, etc.)',
      'Restart the platform to pick up the change',
      'Production-only middleware activates: enforceMinTls, mTLS on /api/internal/, production error handling',
      'Verify by checking the system health endpoint shows nodeEnv: "production"',
    ],
    uiPath: null,
  },

  // ── checks/third-party.js ──────────────────────────────────────────────────

  checkIntegrationHealth: {
    summary: 'Test stale or untested integrations',
    steps: [
      'Navigate to MC -> Admin -> Integrations',
      'For each integration not tested in 30+ days: click "Test Connection"',
      'Failed tests: diagnose using last_test_error; common causes are credential expiry and endpoint changes',
      'Schedule integration health checks at least monthly as part of operational hygiene',
      'Operational integrations that have not been tested may be silently broken',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkVendorRiskAssessment: {
    summary: 'Test every integration at least once + complete vendor risk review externally',
    steps: [
      'Navigate to MC -> Admin -> Integrations',
      'For each integration with NULL last_test_at, click "Test Connection"',
      'For each vendor (the entity at the far end of the integration), complete:',
      '  - Vendor questionnaire (CAIQ, SIG, or your standard intake)',
      '  - Review of vendor SOC 2 Type II report, ISO 27001 certificate, or equivalent',
      '  - DPA / BAA signed for personal-data processors',
      'Document vendor risk reviews in your GRC system (the platform stores test results, not risk reviews)',
    ],
    uiPath: 'mc:admin/integrations',
  },

  checkKmsProviderTrust: {
    summary: 'Probe KMS providers and resolve failures',
    steps: [
      'Navigate to MC -> Admin -> KMS Providers',
      'For each enabled provider: click "Probe Now"',
      'Failed probes: check credentials_encrypted contains current API keys; check IAM policy permits kms:Decrypt or equivalent',
      'Stale probes (older than 7 days): scheduled probing may be misconfigured -- verify probe scheduler',
      'last_probe_status = "ok" after a successful probe',
    ],
    uiPath: 'mc:admin/kms-providers',
  },

  checkSigningKeyRegistry: {
    summary: 'Generate active backup and chain signing keys',
    steps: [
      'For backup_signing_keys: navigate to MC -> Admin -> Backup Signing Keys; click "Generate Local Key"',
      'For chain_signing_keys: keys are typically auto-generated at first backup; if missing, run the backup-init command',
      'Both registries must have at least one active key for backup operations to sign cryptographically',
      'Ed25519 keypairs; private keys are Tier-1 AES-256-GCM encrypted at rest',
      'For cross-deployment trust: register external public keys via "Register External Key"',
    ],
    uiPath: 'mc:admin/backup-signing-keys',
  },
};

module.exports = REMEDIATIONS;
