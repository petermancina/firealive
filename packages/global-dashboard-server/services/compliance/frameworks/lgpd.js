// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: LGPD (Brazil)
//
// R3g PR2 (v1.0.33): GD-side coverage of Brazil's Lei Geral de
// Proteção de Dados (LGPD) -- Law No. 13.709/2018 -- under the
// Shared Responsibility schema. GD-side counterpart to MC PR1's
// frameworks/lgpd.js. Same metadata, same citation, same
// customerResponsibility list (LGPD articles are Brazilian statute
// and framework-level not platform-specific); adapted verifiedControls
// for the GD's surface.
//
// APPLICABILITY (per Foundational Rule 16)
//
//   LGPD applies to any natural person or public/private legal
//   entity processing personal data when:
//
//     - The processing operation is carried out in Brazil
//     - The processing activity has as its purpose the offer or
//       supply of goods or services or processing of data of
//       individuals located in Brazil
//     - The personal data was collected in Brazil
//
//   FireAlive is NOT inherently subject to LGPD. The statute does
//   not name FireAlive nor any class to which FireAlive belongs as
//   automatically scoped; applicability depends on each operator\'s
//   business activities and Brazil exposure.
//
//   At the GD layer specifically, the data-subject surface is
//   narrow: only GD user accounts (CISO / VP / readonly) are
//   directly identifiable. Analyst-level personal data (which is
//   the bulk of LGPD-relevant data in the FireAlive ecosystem)
//   lives at the MC layer; the MC\'s LGPD framework definition
//   covers analyst-level controls.
//
//   This framework definition is provided for customers that
//   process personal data of Brazilian data subjects and have
//   adopted FireAlive in their SOC operations. The GD\'s technical
//   controls support compliance with Art.46 security measures,
//   Art.18 data subject rights, Art.47 prevention practices, and
//   Art.48 incident notification at the governance / cross-region
//   aggregation tier. The customer remains responsible for
//   Art.7-11 legal bases, Art.18 response workflow, Art.37 records
//   of processing activities, Art.41 Encarregado (DPO) designation,
//   Art.48 ANPD notification process, and Art.52 sanction-risk
//   awareness.
//
//   For customers not processing Brazilian data subjects\' data,
//   this framework report can be ignored without consequence.
//
// AUTHORITY
//
//   Autoridade Nacional de Proteção de Dados (ANPD), the National
//   Data Protection Authority. Established by Law No. 13.853/2019
//   amending LGPD; operational since 2020 with progressively
//   expanded enforcement. Conselho Nacional de Proteção de Dados
//   Pessoais e da Privacidade (CNPDP) provides multistakeholder
//   advisory function.
//
// PENALTIES
//
//   Art.52 administrative sanctions include: warning, simple fine
//   up to 2% of the Brazilian-revenue gross income of the entity /
//   group / conglomerate in its last fiscal year (capped at R$ 50
//   million per infraction), daily fine within the same cap,
//   publicization of the infraction, blocking or elimination of
//   personal data. Daily fines apply for ongoing non-compliance.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Lei Geral de Proteção de Dados (LGPD) Law No. 13.709/2018,
//   in force since 18 September 2020. Administrative sanctions
//   provisions effective 1 August 2021. ANPD has issued
//   regulations on (among others) data protection officer,
//   incident notification, international transfer, dosimetria
//   (penalty calculation), and small-business application.
//
//   LGPD is broadly modeled on GDPR with adaptations for the
//   Brazilian context. Operators handling both EU and Brazilian
//   data subjects can leverage substantial overlap; key
//   differences include legal bases (10 LGPD bases vs 6 GDPR),
//   the absence of an explicit 72-hour breach notification
//   timeline (LGPD requires notification in "a reasonable
//   timeframe"), and ANPD-specific procedural rules.
//
//   verifiedControls map GD-layer platform implementations to
//   security measures, data subject rights, prevention practices,
//   and incident-handling controls. customerResponsibility covers
//   legal bases, response workflow, ROPA, DPO, ANPD notification,
//   and sanction-risk awareness.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'LGPD (Brazil)',
  authority: 'Autoridade Nacional de Proteção de Dados (ANPD)',
  citation: 'Lei Geral de Proteção de Dados Pessoais (LGPD) -- Lei No. 13.709/2018',
  verifiedControls: [
    {
      id: 'Art.6(VII)',
      name: 'Security Principle',
      check: checks.checkEncryption,
      mapping: 'HMAC-SHA256 for JWT signing via GD_JWT_SECRET (32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). TLS 1.2+ at the reverse proxy in transit (operator-managed). Application-layer at-rest encryption awaits a future GD KMS integration phase; until then, at-rest protection is filesystem-level (operator-managed disk encryption). Art.6(VII) requires use of technical and administrative measures to protect personal data from unauthorized access and accidental or unlawful destruction, loss, alteration, communication, or dissemination.',
    },
    {
      id: 'Art.6(VIII)',
      name: 'Prevention Principle',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware (inline in packages/global-dashboard-server/index.js) records every /api request (except /api/health) to audit_log. SIEM streaming externalization lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. Art.6(VIII) requires adopting measures to prevent harm to data subjects; comprehensive audit logging supports preventive monitoring.',
    },
    {
      id: 'Art.18(II)',
      name: 'Right to Access',
      check: checks.checkDataSubjectRights,
      mapping: 'GD\'s data-subject surface is narrow: only GD users (CISO / VP / readonly accounts) are direct data subjects on the GD. GET /api/audit-logs/export/:format produces structured exports of audit_log entries covering a GD user\'s activity history. Art.18(II) right of access to personal data; for the narrow GD-account surface, the platform provides the data substrate via the export endpoint. Analyst-level access is enforced at the MC layer.',
    },
    {
      id: 'Art.18(III)',
      name: 'Right to Correction',
      check: checks.checkDataSubjectRights,
      mapping: 'PATCH /api/users/:id permits correction of GD user account information (CISO-only) for the narrow GD-account data-subject surface. Analyst-level correction is enforced at the MC layer. Art.18(III) right covers incomplete, inaccurate, or outdated personal data.',
    },
    {
      id: 'Art.18(IV)',
      name: 'Right to Anonymization, Blocking, or Elimination',
      check: checks.checkDataSubjectRights,
      mapping: 'Account-level blocking via users.active=0 soft delete (CISO-only) for the narrow GD-account surface. No dedicated DELETE /api/users/:id endpoint as of v0.0.31; full elimination currently operator-managed via direct DB operations preserving audit trail. Analyst-data anonymization/blocking/elimination is enforced at the MC layer (architectural — the GD does not store analyst-level data, only aggregate metrics). Art.18(IV) right covers unnecessary, excessive, or unlawfully processed data.',
    },
    {
      id: 'Art.18(V)',
      name: 'Right to Data Portability',
      check: checks.checkDataSubjectRights,
      mapping: 'Structured exports (JSON / CSV) via GET /api/audit-logs/export/:format support Art.18(V) right to portability to another service or product provider for the narrow GD-account surface (activity history). Analyst-level portability is enforced at the MC layer. ANPD regulations elaborate portability requirements.',
    },
    {
      id: 'Art.46',
      name: 'Security Measures',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware with role-array gating on every /api route; MC-trust api_keys for inbound MC push authentication. Art.46 requires controllers/operators to adopt security, technical, and administrative measures suitable to protect personal data.',
    },
    {
      id: 'Art.46 §1',
      name: 'Pseudonymisation',
      check: checks.checkPseudonymization,
      mapping: 'Pseudonymisation is enforced upstream at the MC layer (each MC keys analyst behavioral signals to a pseudonym BEFORE producing aggregate metrics for push to the GD). The GD receives only aggregates; the identity-to-signal linkage never reaches the GD per the architectural data model. This architectural guarantee strengthens compliance with Art.46 §1 (which introduces pseudonymisation as an example of security measure that supports the security principle) at the GD layer.',
    },
    {
      id: 'Art.47',
      name: 'Prevention Practices',
      check: checks.checkChangeManagement,
      mapping: 'system_meta.fuse_counter + audit_log CONFIG_UPDATED events emitted by PUT /api/config/:key evidence preventive practices that address risks to data subject rights. Config Lock server-side persistence is live (the config_lock_state singleton + the config-write chokepoint; unlock requires a fresh hardware-passkey assertion), additionally backed by route-middleware role gating (CISO-only writes). Art.47 requires processing agents to ensure personal data security throughout the processing lifecycle.',
    },
    {
      id: 'Art.48',
      name: 'Security Incident Notification',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. Art.48 requires controllers to notify ANPD and affected data subjects of incidents that may pose relevant risk or damage. ANPD Resolution 15/2024 specifies the notification template and procedure; the notification workflow itself is operator-managed off-platform.',
    },
  ],
  customerResponsibility: [
    {
      id: 'Art.5',
      name: 'Definitions and Role Clarity',
      category: 'documentation',
      detail: 'Understand and apply LGPD definitions consistently: personal data, sensitive personal data, anonymised data, controller (controlador), operator (operador), data subject (titular), Encarregado (DPO), processing. Document the entity\'s role as controller and/or operator for each data flow.',
    },
    {
      id: 'Art.7-11',
      name: 'Legal Bases for Processing',
      category: 'procedural',
      detail: 'Identify and document the legal basis for each processing activity from the 10 LGPD bases: consent (Art.7(I)), legal/regulatory obligation (Art.7(II)), public policy/administration (Art.7(III)), study/research (Art.7(IV)), contract performance (Art.7(V)), judicial procedure (Art.7(VI)), legitimate interest (Art.7(IX) and Art.10), protection of life (Art.7(VII)), health protection (Art.7(VIII)), credit protection (Art.7(X)). Sensitive personal data legal bases under Art.11 are more restrictive.',
    },
    {
      id: 'Art.14',
      name: 'Processing of Children and Adolescents Data',
      category: 'procedural',
      detail: 'Processing of personal data of children (under 12) and adolescents (12-17) shall be carried out in their best interest. Children require specific and prominent consent by at least one of their parents or the legal guardian. Document procedures for verifiable parental consent.',
    },
    {
      id: 'Art.18 [Workflow]',
      name: 'Data Subject Rights Response Workflow (15 days)',
      category: 'procedural',
      detail: 'Respond to data subject requests under Art.18 immediately (in simplified form) or within 15 days (in complete form, including indication of relevant legal or contractual reasons and identification of the controller). Document workflow, verification procedures, and templates.',
    },
    {
      id: 'Art.20',
      name: 'Automated Decision Review',
      category: 'procedural',
      detail: 'Data subjects have the right to request a review of decisions made solely on the basis of automated processing of personal data that affect their interests, including decisions regarding their personal, professional, consumer, and credit profiles or aspects of their personality.',
    },
    {
      id: 'Art.33-36',
      name: 'International Data Transfer Mechanisms',
      category: 'procedural',
      detail: 'International transfers permitted under Art.33 to: countries with adequate protection level (ANPD-declared), with appropriate safeguards (standard contractual clauses, binding corporate rules, certifications, codes of conduct), with data subject consent, with international cooperation grounds, for life protection, for ANPD authorization, for contract performance, or for exercise of rights in judicial proceedings.',
    },
    {
      id: 'Art.37',
      name: 'Records of Processing Activities (RoPA)',
      category: 'documentation',
      detail: 'Controller and operator shall maintain record of personal data processing operations they carry out. Record includes: data categories, purposes, legal bases, data subject categories, retention period, security measures, international transfers, recipients, joint controllers if any. Available to ANPD on request.',
    },
    {
      id: 'Art.41',
      name: 'Encarregado (Data Protection Officer)',
      category: 'organizational',
      detail: 'Appoint an Encarregado (LGPD equivalent of DPO) responsible for: accepting communications from data subjects and ANPD, providing guidance to employees and contractors regarding compliance, executing other duties determined by the controller or established in regulations. ANPD Resolution 18/2024 elaborates the Encarregado role.',
    },
    {
      id: 'Art.48 [Workflow]',
      name: 'ANPD Incident Notification Workflow',
      category: 'procedural',
      detail: 'Document the procedure for ANPD incident notification under Art.48: criteria for "relevant risk or damage" determination, notification content (data categories affected, number of affected data subjects, technical and security measures used, risks and mitigation, technical and operational measures adopted to mitigate effects). ANPD Resolution 15/2024 prescribes timing and template.',
    },
    {
      id: 'Art.50',
      name: 'Voluntary Codes of Conduct',
      category: 'procedural',
      detail: 'Controllers and operators may, jointly with other associations, formulate rules of good practice and governance establishing standards, codes of conduct, ethics, certifications, and dispute resolution. Voluntary codes can demonstrate accountability to ANPD.',
    },
    {
      id: 'Art.52',
      name: 'Administrative Sanctions Awareness',
      category: 'organizational',
      detail: 'Up to 2% of Brazilian-revenue gross income (capped at R$ 50M per infraction) plus daily fines within the same cap, publicization of the infraction, blocking/elimination of personal data. ANPD Resolution 4/2023 elaborates dosimetria (penalty calculation methodology).',
    },
    {
      id: 'Workforce-Training',
      name: 'Workforce LGPD Training',
      category: 'training',
      detail: 'Train personnel handling personal data on LGPD obligations: legal bases, data subject rights, security duties, breach reporting, Encarregado escalation. Document training cadence (annual minimum recommended); require periodic refresher training and role-specific deep-dives for those with elevated responsibilities.',
    },
    {
      id: 'GDPR-Coordination',
      name: 'GDPR Coordination (where applicable)',
      category: 'procedural',
      detail: 'For operators subject to both LGPD and GDPR: leverage substantial overlap but track differences in legal bases (10 LGPD vs 6 GDPR), DSR response timeline (15 days LGPD vs 30 days GDPR), DPO role (Encarregado has slightly different formal requirements), and ANPD-specific procedural rules.',
    },
    {
      id: 'Sector-Sub-Regulations',
      name: 'Sectoral and ANPD Sub-Regulation Tracking',
      category: 'procedural',
      detail: 'ANPD issues regulations under its rulemaking authority. Maintain awareness of issued and pending regulations including: data protection officer, security incident notification, dosimetria, international transfer mechanisms, small-business and startup application, ICT sector specifics, health and credit sector specifics. ANPD publishes a regulatory agenda.',
    },
  ],
  note: 'LGPD entered into force 18 September 2020; administrative sanctions provisions effective 1 August 2021. ANPD became operational with progressive enforcement. ANPD Resolutions provide implementing detail on data protection officer (Resolution 18/2024), incident notification (Resolution 15/2024), dosimetria (Resolution 4/2023), small entities (Resolution 2/2022), and international transfer (Resolution 19/2024). LGPD is broadly modeled on GDPR with adaptations; operators with EU exposure can leverage substantial overlap. Key differences: 10 legal bases vs GDPR\'s 6, 15-day DSR response vs 30 days, no explicit 72-hour breach notification (LGPD requires reasonable timeframe per Art.48), Brazilian-revenue penalty cap (R$50M / 2%) rather than EU-wide global turnover (4%). Brazilian Constitutional Court has affirmed LGPD\'s constitutionality including the right to data protection as a fundamental right (Constitutional Amendment 115/2022). The GD\'s direct LGPD data-subject surface is narrow (GD user accounts only); the bulk of analyst-level LGPD concerns are evaluated at the MC layer.',
});
