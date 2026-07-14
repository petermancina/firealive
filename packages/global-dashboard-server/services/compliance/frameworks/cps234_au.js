// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: APRA CPS 234 (Australia)
//
// R3g PR2 (v1.0.33): GD-side coverage of Australian Prudential
// Regulation Authority Prudential Standard CPS 234 -- Information
// Security -- under the Shared Responsibility schema. GD-side
// counterpart to MC PR1's frameworks/cps234_au.js. Same metadata,
// same citation, same customerResponsibility list (CPS 234 paragraphs
// are APRA-defined and framework-level not platform-specific);
// adapted verifiedControls for the GD's surface.
//
// APPLICABILITY (per Foundational Rule 16)
//
//   CPS 234 applies to APRA-regulated entities in Australia:
//     - Authorised Deposit-taking Institutions (ADIs) -- banks,
//       credit unions, building societies, foreign branches
//     - General insurers, life insurers, private health insurers
//     - Registered Superannuation Entity Licensees (RSE Licensees)
//     - Authorised non-operating holding companies (NOHCs)
//
//   FireAlive is NOT an APRA-regulated entity. CPS 234 does not
//   name FireAlive nor any class to which FireAlive belongs as
//   subject to APRA prudential supervision.
//
//   This framework definition is provided for customers that ARE
//   APRA-regulated entities and have adopted FireAlive in their
//   SOC operations. The GD\'s technical controls support compliance
//   with CPS 234 information security obligations at the governance
//   / cross-region aggregation tier; the customer (the APRA-
//   regulated entity) remains responsible for board-level
//   accountability, CISO appointment, third-party assurance over
//   FireAlive and other ICT suppliers, internal audit, and APRA
//   notification obligations.
//
//   Australian non-APRA-regulated customers (e.g., businesses that
//   are not banks/insurers/super funds) can ignore this framework
//   report; CPS 234 does not apply.
//
// AUTHORITY
//
//   Australian Prudential Regulation Authority (APRA), established
//   under the Australian Prudential Regulation Authority Act 1998.
//   APRA supervises ~600 financial institutions in Australia and
//   has enforcement powers including direction, disqualification,
//   and license suspension.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Prudential Standard CPS 234 -- Information Security. The
//   standard contains 36 paragraphs covering: roles and
//   responsibilities, information security capability, policy
//   framework, asset identification, controls implementation,
//   incident management, testing, internal audit, and APRA
//   notification obligations.
//
//   APRA has issued companion Prudential Practice Guide CPG 234 --
//   Information Security, which provides non-binding implementation
//   guidance. Operators should consult CPG 234 alongside CPS 234.
//
//   verifiedControls map GD-layer technical platform implementations
//   to the substantive control paragraphs (13, 19, 21, 22, 23, 25,
//   26, 27, 32, 35-36 -- with the caveat that paragraph numbering
//   is per the current published standard; future revisions may
//   renumber). customerResponsibility covers governance, third-party
//   assurance, testing program, internal audit, and APRA
//   notification workflow.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'APRA CPS 234',
  authority: 'Australian Prudential Regulation Authority (APRA)',
  citation: 'Prudential Standard CPS 234 -- Information Security (current published version)',
  verifiedControls: [
    {
      id: 'CPS 234 [13]',
      name: 'Information Security Capability',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware with role-array gating on every /api route; MC-trust api_keys for inbound MC push authentication. CPS 234 para 13 requires entity to maintain information security capability commensurate with vulnerabilities and threats; the GD layer contributes its governance-tier technical-control capability.',
    },
    {
      id: 'CPS 234 [19]',
      name: 'Implementation of Controls',
      check: checks.checkConfigLockState,
      mapping: 'GD Config Lock server-side persistence is live (the config_lock_state singleton; the config-write chokepoint refuses writes while the GD is locked). Unlock requires a fresh hardware-passkey assertion (a UV step-up), the GD twin of the MC R3e v1.0.32 config-lock and hardened beyond the MC TOTP-MFA unlock. Configuration-change discipline is additionally backed by route-middleware role gating (CISO-only writes).',
    },
    {
      id: 'CPS 234 [21]',
      name: 'Information Asset Identification',
      check: checks.checkBoundaries,
      mapping: 'Layer 1 (current): management_consoles enumerates the connected MCs (the GD\'s primary information-asset relationships) with country and regulatory_framework. Layer 2 (post-B5b v1.0.51 et seq.): integration_config will enumerate SOAR / SIEM / cloud / IAM vendor integrations. The APRA-regulated entity\'s comprehensive asset inventory (including FireAlive among its ICT assets) is operator-side documentation.',
    },
    {
      id: 'CPS 234 [22]',
      name: 'Vulnerability and Threat Management',
      check: checks.checkVulnScanning,
      mapping: 'GD has no in-platform vuln scan history (no scan-result table). Infrastructure vuln scanning (Nessus / Qualys / OpenVAS / Trivy / Snyk) against the GD deployment is operator-responsibility. CPS 234 para 22 expects systematic monitoring of vulnerabilities and threats; CI/CD integration of dependency vulnerability monitoring (npm audit / Snyk / Dependabot) is the APRA-grade norm for dependency tracking.',
    },
    {
      id: 'CPS 234 [23a]',
      name: 'Information Security Controls -- Encryption',
      check: checks.checkEncryption,
      mapping: 'HMAC-SHA256 for JWT signing via GD_JWT_SECRET (32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). TLS 1.2+ at the reverse proxy in transit (operator-managed). Application-layer at-rest encryption awaits a future GD KMS integration phase; until then, at-rest protection is filesystem-level (operator-managed disk encryption). CPS 234 para 23 requires controls including encryption for sensitive data.',
    },
    {
      id: 'CPS 234 [23b]',
      name: 'Information Security Controls -- Authentication',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with operator-configured GD_JWT_SECRET; no passwords stored (passwordless FIDO2 hardware-passkey login). SSO via SAML / OIDC / LDAP planned for B5b (v1.0.51); login is a FIDO2 hardware passkey. The hardware-passkey MFA is enrolled in webauthn_credentials and enforced at login.',
    },
    {
      id: 'CPS 234 [25]',
      name: 'Identity and Access Management',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at the database layer (UNIQUE on users.username); MC-trust api_keys (management_consoles.api_key) for programmatic identity authenticating inbound MC pushes. Analyst-identity continuity (pseudonym_uuid) is enforced upstream at the MC layer (architectural boundary — the GD does not store analyst identities). CPS 234 para 25 explicitly addresses identity and access management.',
    },
    {
      id: 'CPS 234 [26]',
      name: 'Logging and Audit Trails',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware (inline in packages/global-dashboard-server/index.js) records every /api request (except /api/health) to audit_log with user_id, event_type, detail, ip, severity, timestamp. SIEM streaming for external evidence lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. CPS 234 para 26 requires audit trail of information security-relevant activities.',
    },
    {
      id: 'CPS 234 [27]',
      name: 'Backup and Restoration',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules table holds active=1 schedules; backups table records completed backups with SHA-256 integrity hash and timestamp; POST /api/backups/trigger bootstraps a manual backup. Multi-destination resilience via distinct destination values across active schedules. CPS 234 para 27 addresses backup arrangements proportional to the impact of information loss.',
    },
    {
      id: 'CPS 234 [32]',
      name: 'Systematic Testing of Controls',
      check: checks.checkDrTestRecency,
      mapping: 'GD has no in-platform DR test infrastructure as of v0.0.31 (no restore workflow; /api/regression-test runs a real integration-test suite but is not a backup-restore drill). CPS 234 para 32 requirement for systematic testing (including vulnerability testing, penetration testing, response exercises) is operator-managed off-platform: provision side-by-side GD instance, restore from backup, verify recovery; APRA-grade norm is quarterly.',
    },
    {
      id: 'CPS 234 [35]',
      name: 'Incident Response Plans',
      check: checks.checkIrPlanExists,
      mapping: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO / governance-tier incident response planning is operator-managed off-platform. notification_config provides multi-channel alert delivery (email, sms, recipients) for threshold-based alerts. CPS 234 para 35 requires incident response plans for material information security incidents.',
    },
    {
      id: 'CPS 234 [36]',
      name: 'APRA Incident Notification (72 hours)',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. CPS 234 para 36 requires APRA notification within 72 hours of incident materially affecting interests of beneficiaries. The APRA notification workflow itself is operator-managed off-platform.',
    },
  ],
  customerResponsibility: [
    {
      id: 'CPS 234 [8-10]',
      name: 'Board Ultimate Responsibility',
      category: 'organizational',
      detail: 'The Board of the APRA-regulated entity is ultimately responsible for information security and ensures the entity maintains information security in a manner commensurate with the size and extent of threats. Document the Board\'s oversight including review of information security capability, approval of policy framework, and acceptance of residual risk.',
    },
    {
      id: 'CPS 234 [11]',
      name: 'CISO Appointment',
      category: 'organizational',
      detail: 'Appoint a senior officer responsible for information security (typically Chief Information Security Officer or equivalent). Define the role, reporting line to Board or Board committee, authority to direct information security activities, and ongoing competency requirements. On the GD, the senior CISO-role user maps naturally to this designated officer.',
    },
    {
      id: 'CPS 234 [12]',
      name: 'Information Security Capability Assessment',
      category: 'procedural',
      detail: 'Assess the information security capability of the entity and its third parties commensurate with the impact, threats and vulnerabilities. The platform contributes to this assessment via its technical-control inventory; entity-level capability documentation is operator-side.',
    },
    {
      id: 'CPS 234 [13-14]',
      name: 'Third Party Information Security Assurance',
      category: 'procedural',
      detail: 'Obtain assurance that the information security of related parties and third parties is appropriate. Documentation: third-party register including FireAlive and other ICT suppliers, vendor security questionnaires, contractual security commitments, ongoing review. The MCs connected to the GD count as related parties from the GD\'s perspective.',
    },
    {
      id: 'CPS 234 [15-17]',
      name: 'Information Security Policy Framework',
      category: 'documentation',
      detail: 'Establish and maintain a policy framework setting out the entity\'s approach to managing information security. Policies cover: governance, asset management, access control, classification, incident management, supplier security, change management, monitoring, audit.',
    },
    {
      id: 'CPS 234 [18]',
      name: 'Information Asset Classification',
      category: 'procedural',
      detail: 'Classify information assets including those of third parties by their criticality and sensitivity. Document the classification scheme (e.g., Public / Internal / Confidential / Highly Confidential) and the implications for control selection and handling requirements.',
    },
    {
      id: 'CPS 234 [20]',
      name: 'Control Implementation Documentation',
      category: 'documentation',
      detail: 'Document the controls implemented to mitigate identified threats and exploit vulnerabilities. The Statement of Applicability / Control Inventory references where each control is implemented (platform vs operator vs third party).',
    },
    {
      id: 'CPS 234 [28-30]',
      name: 'Incident Response Capability and Plans',
      category: 'procedural',
      detail: 'Establish and maintain an incident response capability appropriate to the size, business mix and complexity of the entity. Document incident classification, escalation, response procedures, communication, and lessons-learned processes.',
    },
    {
      id: 'CPS 234 [31]',
      name: 'Annual Testing of Incident Response',
      category: 'procedural',
      detail: 'Test the incident response plans at least annually using a methodology commensurate with the size and complexity of the entity. Tabletop exercises, simulated incidents, and lessons-learned reviews. Document test results and corrective actions.',
    },
    {
      id: 'CPS 234 [33]',
      name: 'Internal Audit of Information Security',
      category: 'procedural',
      detail: 'Independent (typically internal audit) review of the design and operating effectiveness of information security controls at least annually. Internal audit findings reported to Board or appropriate Board committee. Corrective actions tracked to completion.',
    },
    {
      id: 'CPS 234 [34]',
      name: 'External Audit of Information Security',
      category: 'procedural',
      detail: 'External audit of information security controls and operations as required by APRA or determined by the entity. APRA may direct external audits of specific control areas. Coordinate with external auditors; provide access to documentation, systems, and personnel.',
    },
    {
      id: 'CPS 234 [36] [Workflow]',
      name: 'APRA Notification Workflow (72 hours)',
      category: 'procedural',
      detail: 'Document the procedure for APRA notification of incidents materially affecting (or with potential to materially affect) the entity, its members, customers, or beneficiaries within 72 hours of becoming aware. Designate notification owner, after-hours coverage, escalation triggers, and content template.',
    },
    {
      id: 'CPS 234 [36] [Weakness]',
      name: 'APRA Control Weakness Notification (10 business days)',
      category: 'procedural',
      detail: 'Notify APRA of material information security control weaknesses within 10 business days of becoming aware. Document the criteria for "material" weakness, the assessment workflow, and the notification template.',
    },
    {
      id: 'CPG 234',
      name: 'CPG 234 Implementation Guidance Awareness',
      category: 'documentation',
      detail: 'Maintain awareness of APRA Prudential Practice Guide CPG 234 (Information Security), which provides non-binding implementation guidance for CPS 234. Document where the entity\'s practices align with CPG 234 recommendations and where departures exist with rationale.',
    },
  ],
  note: 'CPS 234 is one prudential standard among ~30 APRA prudential standards (CPS, SPS series). Related standards include CPS 230 Operational Risk Management (effective July 2025), CPS 231 Outsourcing, and CPS 232 Business Continuity Management. Operators should consult CPS 230 for the broader operational risk lens that incorporates information security. CPS 234 has been in force since 1 July 2019 with progressive APRA enforcement. APRA has indicated intent to issue additional information security guidance and may update CPS 234; track APRA discussion papers and final standards. Australian Cyber Security Centre (ACSC) Essential Eight maturity model is sometimes referenced alongside CPS 234 as the technical-control implementation reference. The GD\'s role in a CPS 234 program is the governance / cross-region aggregation tier; analyst-level operational controls are at the MC layer per its CPS 234 framework definition.',
});
