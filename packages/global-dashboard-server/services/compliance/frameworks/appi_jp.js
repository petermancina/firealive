// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: APPI (Japan)
//
// R3g PR2 (v1.0.33): GD-side coverage of Japan's Act on the
// Protection of Personal Information (APPI) -- Act No. 57 of 2003
// as substantially amended -- under the Shared Responsibility schema.
// GD-side counterpart to MC PR1's frameworks/appi_jp.js. Same
// metadata, same citation, same customerResponsibility list (APPI
// articles are Japanese statute and framework-level not platform-
// specific); adapted verifiedControls for the GD's surface.
//
// APPLICABILITY (per Foundational Rule 16)
//
//   APPI applies to "Personal Information Handling Business
//   Operators" (PIHBOs) -- any entity that uses a personal
//   information database for business purposes. The 2017 and 2020
//   amendments eliminated the previous threshold (5,000 personal
//   data records); ALL businesses handling personal data are now
//   PIHBOs regardless of size.
//
//   Extraterritorial reach: APPI applies to foreign business
//   operators that handle personal data of individuals in Japan in
//   the course of supplying goods or services to those individuals,
//   even without physical presence in Japan. The 2020 amendments
//   substantially strengthened cross-border enforcement, including
//   direct PPC investigation and enforcement authority over
//   foreign operators.
//
//   FireAlive is NOT inherently subject to APPI. The Act does not
//   name FireAlive nor classify it; applicability depends on each
//   operator\'s business activities and Japan exposure.
//
//   At the GD layer specifically, the personal-information surface
//   is narrow: only GD user accounts (CISO / VP / readonly) are
//   directly identifiable. Analyst-level personal information
//   (which is the bulk of APPI-relevant data in the FireAlive
//   ecosystem) lives at the MC layer; the MC\'s APPI framework
//   definition covers analyst-level controls.
//
//   This framework definition is provided for customers processing
//   personal information of Japan individuals and have adopted
//   FireAlive in their SOC operations. The GD\'s technical controls
//   support compliance with Art.20 security control measures,
//   Art.22-23 supervision, Art.26 breach notification, Art.28
//   cross-border provision, and Art.32-34 data subject rights at
//   the governance / cross-region aggregation tier. The customer
//   remains responsible for Art.4 basic policy, Art.17 proper
//   acquisition, Art.18 purpose notification, Art.24 third-party
//   provision controls, Art.25 special-care-required information
//   handling, Art.26 PPC notification workflow, and Art.40 PIPO
//   designation.
//
//   For customers not processing Japan personal information, this
//   framework report can be ignored without consequence.
//
// AUTHORITY
//
//   Personal Information Protection Commission (PPC -- 個人情報
//   保護委員会). PPC is an independent administrative agency
//   established in 2016, with consolidated authority over personal
//   information protection (previously fragmented across ministry-
//   specific guidelines). PPC has investigation, recommendation,
//   order, and reporting-requirement authority.
//
// PENALTIES
//
//   PPC orders for non-compliance carry administrative penalties.
//   Following 2020 amendments, criminal penalties for non-
//   compliance with PPC orders include imprisonment up to 1 year
//   or fines up to JPY 1 million for individuals; corporate fines
//   up to JPY 100 million (dual penalty system -- corporation
//   liable for officer/employee acts).
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   APPI Act No. 57 of 2003 as amended -- major amendments in
//   2015 (effective 2017), 2020 (effective April 2022), and 2021
//   (effective April 2022). The 2020 amendments are particularly
//   significant:
//     - Eliminated PIHBO threshold (all data-handling businesses
//       now covered)
//     - Strengthened cross-border enforcement
//     - Introduced mandatory breach notification (Art.26)
//     - Added pseudonymously processed information category
//     - Strengthened data subject rights (Art.32-34)
//
//   The 2021 amendments addressed public-sector personal
//   information protection (different chapter); private-sector
//   provisions covered here.
//
//   verifiedControls map GD-layer platform implementations to
//   Art.20 security, Art.22-23 supervision, Art.26 breach
//   notification, Art.28 cross-border, and Art.32-34 data subject
//   rights. customerResponsibility covers Art.4 basic policy,
//   Art.17-18 acquisition and notification, Art.21 accuracy,
//   Art.24-25 third-party and sensitive provision, Art.26 PPC
//   workflow, Art.40 PIPO designation, and PPC Guidelines
//   tracking.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'APPI (Japan)',
  authority: 'Personal Information Protection Commission (PPC)',
  citation: 'Act on the Protection of Personal Information (Act No. 57 of 2003, as amended)',
  verifiedControls: [
    {
      id: 'Art.20 [Encryption]',
      name: 'Security Control Measures -- Encryption',
      check: checks.checkEncryption,
      mapping: 'HMAC-SHA256 for JWT signing via GD_JWT_SECRET (32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). TLS 1.2+ at the reverse proxy in transit (operator-managed). Application-layer at-rest encryption awaits a future GD KMS integration phase; until then, at-rest protection is filesystem-level (operator-managed disk encryption). Art.20 requires PIHBOs to take necessary and appropriate measures for security control of personal data, including measures preventing leakage, loss, or damage.',
    },
    {
      id: 'Art.20 [Access]',
      name: 'Security Control Measures -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware with role-array gating on every /api route; MC-trust api_keys for inbound MC push authentication. PPC Guidelines on security control measures expressly identify access management as a required security measure.',
    },
    {
      id: 'Art.22',
      name: 'Employee Supervision',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware (inline in packages/global-dashboard-server/index.js) records every /api request (except /api/health) to audit_log. SIEM streaming externalization for additional supervision evidence lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. Ed25519-signed log batches await future GD signing-key registries; R3g PR3 adds signing_keys for MC-push verification. Art.22 requires PIHBOs to provide necessary and appropriate supervision of employees handling personal data.',
    },
    {
      id: 'Art.23',
      name: 'Trustee Supervision',
      check: checks.checkIntegrationHealth,
      mapping: 'Layer 1 (current): management_consoles tracks each connected MC (the GD\'s primary third-party data-processor relationships) with last_sync timestamps for ongoing freshness monitoring. Layer 2 (post-B5b v1.0.51 et seq.): integration_config will track SOAR / SIEM / cloud / IAM trustee relationships with last_test_at fields. Art.23 requires PIHBOs to provide necessary and appropriate supervision over entrusted handling of personal data by trustees.',
    },
    {
      id: 'Art.26',
      name: 'Breach Notification Timing',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. Art.26 (2020 amendments) requires PIHBOs to report leakages to PPC concurrently with initial discovery (preliminary report "immediately" -- typically interpreted as within 3-5 days) and final report within 30 days (general cases) or 60 days (cases involving improper purpose). PPC notification workflow is operator-managed off-platform.',
    },
    {
      id: 'Art.28',
      name: 'Cross-Border Provision Controls',
      check: checks.checkCrossBorderTransferControls,
      mapping: 'management_consoles.country tracks each MC\'s jurisdiction; config \'gd_residency\' key documents the GD server\'s own jurisdiction. Layer 2 (post-B5b) integration_config will document outbound cross-border data flows. Art.28 (2020 amendments) significantly tightened cross-border provision rules: consent of data subject with disclosure of foreign jurisdiction information OR PPC-recognized equivalent protection OR equivalent measures by recipient under contract. Legal mechanism documentation is operator-side off-platform.',
    },
    {
      id: 'Art.32',
      name: 'Disclosure to Data Subject',
      check: checks.checkDataSubjectRights,
      mapping: 'GD\'s data-subject surface is narrow: only GD users (CISO / VP / readonly accounts) are direct data subjects on the GD. GET /api/audit-logs/export/:format produces structured exports of audit_log entries covering a GD user\'s activity history in electronic form. Art.32 (2020 amendments) strengthened the right of disclosure including in electronic form per data subject\'s choice; for the narrow GD-account surface, the platform provides the data substrate via the export endpoint. Analyst-level disclosure is enforced at the MC layer.',
    },
    {
      id: 'Art.33-34',
      name: 'Correction and Suspension of Use',
      check: checks.checkDataSubjectRights,
      mapping: 'PATCH /api/users/:id permits correction of GD user account information per Art.33 (CISO-only) for the narrow GD-account data-subject surface. Account-level suspension via users.active=0 soft delete per Art.34. Analyst-level correction and suspension are enforced at the MC layer. The 2020 amendments expanded suspension-of-use grounds including suspected breach.',
    },
  ],
  customerResponsibility: [
    {
      id: 'Art.4 [Policy]',
      name: 'Basic Personal Information Protection Policy',
      category: 'documentation',
      detail: 'Develop and publish basic policy on personal information protection. While Art.4 strictly addresses national/local government responsibilities, PIHBOs typically publish equivalent corporate basic policy as foundational documentation referenced by privacy notices, PIPO charter, and PPC inquiries.',
    },
    {
      id: 'Art.17',
      name: 'Acquisition by Proper Means',
      category: 'procedural',
      detail: 'Personal information shall not be acquired by deception or other wrongful means. Document acquisition channels and methods; verify each channel uses proper means; train personnel handling acquisition on proper-means standard.',
    },
    {
      id: 'Art.18',
      name: 'Purpose of Use Notification',
      category: 'procedural',
      detail: 'Specify purpose of use of personal information as specifically as possible. Notify or publicly announce the purpose of use promptly after acquisition (unless purpose was already specified and announced). Public privacy notice on company website is typical implementation.',
    },
    {
      id: 'Art.21',
      name: 'Accuracy of Personal Data',
      category: 'procedural',
      detail: 'Personal data kept up to date within scope necessary to achieve the purpose of use; deleted without delay when no longer necessary. Document accuracy-maintenance procedures and deletion triggers.',
    },
    {
      id: 'Art.24',
      name: 'Third-Party Provision Controls',
      category: 'procedural',
      detail: 'Third-party provision of personal data requires prior consent of the data subject UNLESS one of the specified exceptions applies (Art.24(1) exceptions or Art.24(2) opt-out provision -- which requires advance PPC filing). Document the lawful basis for each third-party provision; maintain opt-out filings with PPC if relying on Art.24(2).',
    },
    {
      id: 'Art.25',
      name: 'Special-Care-Required Personal Information (Sensitive PI)',
      category: 'procedural',
      detail: 'Special-care-required personal information (race, creed, social status, medical history, criminal record, fact of having been a victim of crime, other categories specified by Cabinet Order) requires opt-in consent for acquisition; opt-out provision under Art.24(2) is NOT permitted. Document categorization workflow; verify opt-in consent for any sensitive PI acquisition.',
    },
    {
      id: 'Art.26 [Workflow]',
      name: 'PPC Breach Notification Workflow',
      category: 'procedural',
      detail: 'Preliminary report to PPC "immediately" upon discovery of a leak (PPC Guidelines elaborate: within 3-5 days from awareness). Final report within 30 days for general leakage cases, within 60 days for cases involving improper purpose (e.g., suspected wrongful intent by perpetrator). Notify affected data subjects concurrent with regulatory obligation; some exemptions where notification not appropriate.',
    },
    {
      id: 'Art.27',
      name: 'Disclosure Record Retention',
      category: 'documentation',
      detail: 'Maintain records of third-party provisions and receipts of personal data. Records retained for periods specified by PPC rules (typically 1-3 years depending on category). Records produced on PPC request and used for data-subject disclosure requests.',
    },
    {
      id: 'Art.35',
      name: 'Complaints Handling',
      category: 'procedural',
      detail: 'Implement appropriate measures to handle complaints regarding personal information handling. Designate complaint-handling contact; document complaint procedure; provide accessible mechanism (web form, hotline). Cooperate with PPC-designated dispute-resolution organizations.',
    },
    {
      id: 'Art.40',
      name: 'Personal Information Protection Officer (PIPO)',
      category: 'organizational',
      detail: 'While not strictly mandated as DPO-equivalent, PPC Guidelines on security control measures expressly recommend designating a PIPO for organizational management of personal information protection. The PIPO oversees policy implementation, training, complaint handling, and PPC liaison. Practical operations standard.',
    },
    {
      id: 'Workforce-Training',
      name: 'Workforce APPI Training',
      category: 'training',
      detail: 'Train personnel on APPI obligations: proper acquisition, purpose-of-use limits, security control measures, employee-supervision expectations, third-party provision controls, breach reporting. PPC Guidelines elaborate training expectations; document training cadence and role-specific content.',
    },
    {
      id: 'Foreign-Operator',
      name: 'Foreign Business Operator Compliance (Extraterritorial)',
      category: 'procedural',
      detail: 'For foreign operators subject to APPI via extraterritorial reach (no Japan establishment but providing goods/services to Japan individuals): comply with all PIHBO obligations; designate domestic representative for PPC communications under amended Art.166. PPC has enhanced enforcement authority over foreign operators following 2020 amendments.',
    },
    {
      id: 'PPC-Guidelines',
      name: 'PPC Guidelines and Q&A Tracking',
      category: 'procedural',
      detail: 'PPC issues comprehensive Guidelines (General Rules, Cross-Border Provision, Pseudonymously Processed Information, etc.) and Q&A documents elaborating substantive obligations. Maintain awareness of issued and updated Guidelines; PPC publishes a public-comment process for proposed Guideline changes.',
    },
    {
      id: 'Sector-Specific',
      name: 'Sector-Specific Guidance',
      category: 'procedural',
      detail: 'Financial sector under FSA (Financial Services Agency) supervision additionally subject to FSA Guidelines on personal information handling in financial services. Healthcare under Ministry of Health, Labour and Welfare guidance. Telecom under MIC (Ministry of Internal Affairs and Communications). Identify sectoral overlays.',
    },
  ],
  note: 'APPI was substantially modernized by the 2020 amendments (effective April 2022) which: eliminated the previous 5,000-record PIHBO threshold (all data-handling businesses now covered), introduced mandatory breach notification (Art.26), strengthened cross-border provision rules (Art.28), expanded data subject rights including electronic disclosure (Art.32-34), added pseudonymously processed information category, and substantially strengthened cross-border enforcement against foreign operators. Japan has been recognized by the EU as providing adequate protection for purposes of GDPR international transfer (EU-Japan adequacy decision 2019, mutual adequacy). Operators handling Japan personal data alongside EU data can leverage substantial overlap in protection-obligation implementations. The 2021 amendments addressed public-sector personal information protection; that chapter is not enumerated here as out of typical commercial scope. The GD\'s direct APPI personal-information surface is narrow (GD user accounts only); the bulk of analyst-level APPI concerns are evaluated at the MC layer.',
});
