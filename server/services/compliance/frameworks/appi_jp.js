// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: APPI (Japan)
//
// R3g (v1.0.33): coverage of Japan\'s Act on the Protection of
// Personal Information (APPI) -- Act No. 57 of 2003 as
// substantially amended -- under the Shared Responsibility schema.
//
// APPLICABILITY
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
//   This framework definition is provided for customers
//   processing personal information of Japan individuals and have
//   adopted FireAlive in their SOC operations. The technical
//   controls support compliance with Art.20 security control
//   measures, Art.22-23 supervision, Art.26 breach notification,
//   Art.28 cross-border provision, and Art.32-34 data subject
//   rights. The customer remains responsible for Art.4 basic
//   policy, Art.17 proper acquisition, Art.18 purpose notification,
//   Art.24 third-party provision controls, Art.25 special-care-
//   required information handling, Art.26 PPC notification
//   workflow, and Art.40 PIPO designation.
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
//   verifiedControls map platform implementations to Art.20
//   security, Art.22-23 supervision, Art.26 breach notification,
//   Art.28 cross-border, and Art.32-34 data subject rights.
//   customerResponsibility covers Art.4 basic policy, Art.17-18
//   acquisition and notification, Art.21 accuracy, Art.24-25
//   third-party and sensitive provision, Art.26 PPC workflow,
//   Art.40 PIPO designation, and PPC Guidelines tracking.
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
      mapping: 'AES-256-GCM at rest via TIER1/TIER3 keys (distinct); TLS 1.2+ at reverse proxy in transit. Art.20 requires PIHBOs to take necessary and appropriate measures for security control of personal data, including measures preventing leakage, loss, or damage.',
    },
    {
      id: 'Art.20 [Access]',
      name: 'Security Control Measures -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware; scoped API keys. PPC Guidelines on security control measures expressly identify access management as a required security measure.',
    },
    {
      id: 'Art.22',
      name: 'Employee Supervision',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request to audit_log; SIEM streaming externalizes events; signed log batches via Ed25519 (signLogBatch). Art.22 requires PIHBOs to provide necessary and appropriate supervision of employees handling personal data.',
    },
    {
      id: 'Art.23',
      name: 'Trustee Supervision',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config tracks all third-party data-processor (trustee) relationships; last_test_at evidences ongoing monitoring. Art.23 requires PIHBOs to provide necessary and appropriate supervision over entrusted handling of personal data by trustees.',
    },
    {
      id: 'Art.26',
      name: 'Breach Notification Timing',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery. Art.26 (2020 amendments) requires PIHBOs to report leakages to PPC concurrently with initial discovery (preliminary report "immediately" -- typically interpreted as within 3-5 days) and final report within 30 days (general cases) or 60 days (cases involving improper purpose).',
    },
    {
      id: 'Art.28',
      name: 'Cross-Border Provision Controls',
      check: checks.checkCrossBorderTransferControls,
      mapping: 'cross_border_transfer_controls table records adequacy decisions, contractual safeguards, and consent records. Art.28 (2020 amendments) significantly tightened cross-border provision rules: consent of data subject with disclosure of foreign jurisdiction information OR PPC-recognized equivalent protection OR equivalent measures by recipient under contract.',
    },
    {
      id: 'Art.32',
      name: 'Disclosure to Data Subject',
      check: checks.checkDataSubjectRights,
      mapping: 'POST /api/legal-hold/export produces structured exports (user record + audit history). Art.32 (2020 amendments) strengthened the right of disclosure including in electronic form per data subject\'s choice; response workflow is operator-side.',
    },
    {
      id: 'Art.33-34',
      name: 'Correction and Suspension of Use',
      check: checks.checkDataSubjectRights,
      mapping: 'User-update endpoints permit correction per Art.33; offboarding workflow (active=0 soft delete) and pseudonym rotation support suspension of use per Art.34. The 2020 amendments expanded suspension-of-use grounds including suspected breach.',
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
  note: 'APPI was substantially modernized by the 2020 amendments (effective April 2022) which: eliminated the previous 5,000-record PIHBO threshold (all data-handling businesses now covered), introduced mandatory breach notification (Art.26), strengthened cross-border provision rules (Art.28), expanded data subject rights including electronic disclosure (Art.32-34), added pseudonymously processed information category, and substantially strengthened cross-border enforcement against foreign operators. Japan has been recognized by the EU as providing adequate protection for purposes of GDPR international transfer (EU-Japan adequacy decision 2019, mutual adequacy). Operators handling Japan personal data alongside EU data can leverage substantial overlap in protection-obligation implementations. The 2021 amendments addressed public-sector personal information protection; that chapter is not enumerated here as out of typical commercial scope.',
});
