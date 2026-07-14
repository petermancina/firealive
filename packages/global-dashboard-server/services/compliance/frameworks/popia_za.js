// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: POPIA (South Africa)
//
// R3g PR2 (v1.0.33): GD-side coverage of South Africa's Protection
// of Personal Information Act 4 of 2013 under the Shared
// Responsibility schema. GD-side counterpart to MC PR1's
// frameworks/popia_za.js. This is the final framework in the GD's
// v1.0.33 compliance suite, bringing the GD FRAMEWORKS object to 16
// entries (matching the MC's 16-framework suite).
//
// Same metadata, same citation, same customerResponsibility list
// (POPIA conditions and sections are statutory and framework-level
// not platform-specific); adapted verifiedControls for the GD's
// surface.
//
// APPLICABILITY (per Foundational Rule 16)
//
//   POPIA applies to "Responsible Parties" -- public or private
//   bodies (or any other person) which, alone or in conjunction
//   with others, determines the purpose of and means for processing
//   personal information. Specifically:
//
//     - The Responsible Party is domiciled in South Africa, OR
//     - The Responsible Party is not domiciled in South Africa but
//       makes use of automated or non-automated means in South
//       Africa, unless the means is only used to forward personal
//       information through South Africa
//
//   FireAlive is NOT inherently subject to POPIA. The Act does
//   not name FireAlive nor any class to which FireAlive belongs as
//   automatically scoped; applicability depends on each operator\'s
//   business activities and South Africa exposure.
//
//   At the GD layer specifically, the personal-information surface
//   is narrow: only GD user accounts (CISO / VP / readonly) are
//   directly identifiable. Analyst-level personal information
//   (which is the bulk of POPIA-relevant data in the FireAlive
//   ecosystem) lives at the MC layer; the MC\'s POPIA framework
//   definition covers analyst-level controls.
//
//   This framework definition is provided for customers
//   processing personal information of South African data subjects
//   and have adopted FireAlive in their SOC operations. The GD\'s
//   technical controls support compliance with §19 security
//   safeguards, §21 operator obligations, §22 compromise
//   notification timing, §23-24 data subject participation, and
//   §72 transborder information flows at the governance /
//   cross-region aggregation tier. The customer (the Responsible
//   Party) remains responsible for §8 accountability, §11 consent
//   management, §18 notification at collection, §20 Information
//   Officer designation, §22 IR notification workflow, §55-58 IO
//   registration with the Information Regulator, and §69-71 direct
//   marketing controls.
//
//   For customers not processing South African personal
//   information, this framework report can be ignored without
//   consequence.
//
// AUTHORITY
//
//   Information Regulator (South Africa), established under
//   §39 of POPIA and operational since 1 December 2016. The
//   Information Regulator has investigation, enforcement notice,
//   fine, and prosecution-referral authority. The Regulator also
//   administers the Promotion of Access to Information Act (PAIA)
//   alongside POPIA.
//
// PENALTIES
//
//   §107 establishes offences and penalties: fines up to ZAR 10
//   million OR imprisonment up to 10 years (for the most serious
//   offences including obstruction of the Information Regulator).
//   Less serious offences carry lower maxima. Administrative
//   penalties under §109 can be imposed by the Regulator instead
//   of criminal referral; civil action under §99 enables data
//   subjects to claim damages.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Protection of Personal Information Act 4 of 2013. Long
//   commencement history: enacted 2013, partial commencement
//   2014 (definitions, Information Regulator establishment), full
//   commencement of operational provisions on 1 July 2020 with
//   one-year grace period; enforcement effective 1 July 2021.
//
//   POPIA is structured around 8 "Conditions for Lawful
//   Processing" of personal information (§§8-25), plus specific
//   provisions on special information, children\'s information,
//   direct marketing, transborder flows, codes of conduct, and
//   enforcement.
//
//   verifiedControls map GD-layer platform implementations to §19
//   security safeguards (Condition 7), §21 operator obligations,
//   §22 compromise notification, §23-24 data subject participation
//   (Condition 8), and §72 transborder flows. customerResponsibility
//   covers all 8 Conditions, IO designation and registration,
//   compromise workflow, direct marketing controls, and POPIA
//   Regulations tracking.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'POPIA (South Africa)',
  authority: 'Information Regulator (South Africa)',
  citation: 'Protection of Personal Information Act 4 of 2013',
  verifiedControls: [
    {
      id: '§19 [Encryption]',
      name: 'Security Safeguards -- Integrity and Confidentiality',
      check: checks.checkEncryption,
      mapping: 'HMAC-SHA256 for JWT signing via GD_JWT_SECRET (32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). TLS 1.2+ at the reverse proxy in transit (operator-managed). Application-layer at-rest encryption awaits a future GD KMS integration phase; until then, at-rest protection is filesystem-level (operator-managed disk encryption). §19 (Condition 7) requires responsible parties to secure the integrity and confidentiality of personal information by taking appropriate, reasonable technical and organisational measures.',
    },
    {
      id: '§19 [Access]',
      name: 'Security Safeguards -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware with role-array gating on every /api route; MC-trust api_keys for inbound MC push authentication. §19 access controls prevent loss of, damage to, or unauthorised destruction of personal information AND prevent unlawful access to or processing of personal information.',
    },
    {
      id: '§17',
      name: 'Information Quality',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware records every /api request (except /api/health) to audit_log including data-quality-relevant updates (PATCH /api/users/:id account-information corrections). SIEM streaming for additional information-quality oversight evidence lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. §17 (Condition 5) requires responsible parties to take reasonably practicable steps to ensure personal information is complete, accurate, not misleading, and updated where necessary.',
    },
    {
      id: '§21',
      name: 'Operator Obligations',
      check: checks.checkIntegrationHealth,
      mapping: 'Layer 1 (current): management_consoles tracks each connected MC (the GD\'s primary third-party operator relationships) with last_sync timestamps. Layer 2 (post-B5b v1.0.51 et seq.): integration_config will track SOAR / SIEM / cloud / IAM operator relationships with last_test_at fields. §21 requires processing by operators (POPIA equivalent of GDPR processor) only with knowledge or authorisation of responsible party, treated as confidential, and only as specified by responsible party.',
    },
    {
      id: '§22',
      name: 'Compromise Notification Timing',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. §22 requires notification of compromise to Information Regulator AND data subjects "as soon as reasonably possible" after discovery of the compromise; delays only permitted for criminal investigation cooperation. Notification workflow is operator-managed off-platform.',
    },
    {
      id: '§23',
      name: 'Right of Access',
      check: checks.checkDataSubjectRights,
      mapping: 'GD\'s data-subject surface is narrow: only GD users (CISO / VP / readonly accounts) are direct data subjects on the GD. GET /api/audit-logs/export/:format produces structured exports of audit_log entries covering a GD user\'s activity history. §23 (Condition 8) gives data subjects the right to access personal information held about them; for the narrow GD-account surface, the platform provides the data substrate via the export endpoint. Analyst-level access is enforced at the MC layer.',
    },
    {
      id: '§24',
      name: 'Right to Correct or Delete',
      check: checks.checkDataSubjectRights,
      mapping: 'PATCH /api/users/:id permits correction of GD user account information per §24(1)(a) (CISO-only) for the narrow GD-account data-subject surface. Account-level deletion via users.active=0 soft delete per §24(1)(b) where information is inaccurate, irrelevant, excessive, out of date, incomplete, misleading, or obtained unlawfully. No dedicated DELETE /api/users/:id endpoint as of v0.0.31; full deletion currently operator-managed via direct DB operations preserving audit trail. Analyst-level correction/deletion is enforced at the MC layer.',
    },
    {
      id: '§72',
      name: 'Transborder Information Flows',
      check: checks.checkCrossBorderTransferControls,
      mapping: 'management_consoles.country tracks each MC\'s jurisdiction; config \'gd_residency\' key documents the GD server\'s own jurisdiction. Layer 2 (post-B5b) integration_config will document outbound cross-border data flows. §72 permits transborder flow only if: recipient subject to law/binding rules providing adequate protection AND including PoPI principles, OR data subject consents, OR transfer necessary for performance of contract, OR transfer for the benefit of the data subject and consent impractical, OR transfer for other limited purposes. Legal mechanism documentation is operator-side off-platform.',
    },
  ],
  customerResponsibility: [
    {
      id: '§8 (Condition 1)',
      name: 'Accountability',
      category: 'organizational',
      detail: 'The responsible party must ensure that the conditions for lawful processing of personal information and all measures that give effect to such conditions are complied with at the time of determining the purpose and means of processing AND during processing itself. Document accountability framework, responsible party identification, governance.',
    },
    {
      id: '§9 (Condition 2)',
      name: 'Processing Limitation -- Lawfulness',
      category: 'procedural',
      detail: 'Personal information processed lawfully and in a reasonable manner that does not infringe the privacy of the data subject. Document the lawful basis for each processing activity (consent under §11, contract performance, legal obligation, protection of legitimate interest, public benefit, vital interest).',
    },
    {
      id: '§10 (Condition 2)',
      name: 'Minimality',
      category: 'procedural',
      detail: 'Personal information processed only if, given the purpose for which it is processed, it is adequate, relevant, and not excessive. Document the necessity analysis for each personal information category collected; periodic review of necessity.',
    },
    {
      id: '§11 (Condition 2)',
      name: 'Consent Management',
      category: 'procedural',
      detail: 'Where consent is the basis for processing, obtain a voluntary, specific and informed expression of will. Document consent records; honor withdrawal of consent; ensure consent is freely given and not bundled with other terms.',
    },
    {
      id: '§12 (Condition 2)',
      name: 'Collection Directly from Data Subject',
      category: 'procedural',
      detail: 'Personal information must be collected directly from the data subject, except where: data is in public record / publicly available, data subject consents to collection from another source, collection from another source would not prejudice a legitimate interest, collection necessary for legal/regulatory function, collection in interests of national security or law enforcement.',
    },
    {
      id: '§13 (Condition 3)',
      name: 'Purpose Specification',
      category: 'documentation',
      detail: 'Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party. Document the purpose for each collection point; ensure data subjects are aware of the purpose.',
    },
    {
      id: '§14 (Condition 3)',
      name: 'Retention and Restriction',
      category: 'procedural',
      detail: 'Records of personal information must not be retained any longer than necessary for achieving the purpose. Retention permitted where required by law, reasonably required for lawful purposes, retention required by contract, data subject has consented, or for research/statistical purposes with appropriate safeguards.',
    },
    {
      id: '§18 (Condition 6)',
      name: 'Notification at Collection',
      category: 'procedural',
      detail: 'When collecting personal information, take reasonably practicable steps to ensure data subject is aware of: information being collected, source if not from data subject, name and address of responsible party, purpose, whether supply is voluntary or mandatory, consequences of failure to provide, particular law authorising or requiring collection, recipient class.',
    },
    {
      id: '§20',
      name: 'Information Officer Designation',
      category: 'organizational',
      detail: 'Head of every private body (and Deputy Information Officers as applicable) is automatically the Information Officer (IO) by operation of §1 definition and §17 of PAIA. Designate additional Deputy Information Officers as needed for the organisation\'s scale. The IO oversees PoPI compliance, complaint handling, PAIA requests, IR liaison.',
    },
    {
      id: '§22 [IR + DS Workflow]',
      name: 'Compromise Notification Workflow (IR + Data Subjects)',
      category: 'procedural',
      detail: 'Document procedure for compromise notification to Information Regulator AND to affected data subjects "as soon as reasonably possible" after discovery. Notification content includes: nature of breach, identity of the unauthorised person if known, what is being done to address the compromise, what data subjects can do to mitigate adverse effects, name and contact of Information Officer.',
    },
    {
      id: '§55-58',
      name: 'Information Officer Registration with Regulator',
      category: 'documentation',
      detail: 'Register the Information Officer (and any Deputy Information Officers) with the Information Regulator. Registration via the IR online portal. Update registration when officers change. Failure to register is itself an offence; the Information Regulator has made registration a priority enforcement area.',
    },
    {
      id: '§69-71',
      name: 'Direct Marketing Controls',
      category: 'procedural',
      detail: '§69 prohibits unsolicited electronic communications for direct marketing without consent (opt-in for non-customers) or pre-existing customer relationship with opt-out. §71 prohibits automated decision-making solely on automated processing without safeguards. Document direct marketing controls separately from general PoPI compliance.',
    },
    {
      id: '§107 [Penalties]',
      name: 'Penalty Risk Awareness',
      category: 'organizational',
      detail: 'Fines up to ZAR 10 million OR imprisonment up to 10 years for serious offences. Administrative penalties under §109 may be imposed by the Regulator. Civil damages under §99 enable data subjects to claim. Document the risk in enterprise risk register; ensure D&O insurance covers personal-liability exposure for designated officers.',
    },
    {
      id: 'POPIA-Regulations',
      name: 'POPIA Regulations and Codes of Conduct Tracking',
      category: 'procedural',
      detail: 'The Information Regulator has issued POPIA Regulations elaborating responsibilities, IO duties, EnforcementCommittee procedures, and Codes of Conduct. Industry-specific Codes of Conduct (e.g., banking, insurance, credit) may be issued. Track Regulations and applicable Codes; assess organisational alignment.',
    },
  ],
  note: 'POPIA had an unusually long commencement timeline: enacted 2013, partial commencement 2014, full operational commencement 1 July 2020 with one-year grace period, enforcement effective 1 July 2021. The Information Regulator has been progressively building enforcement capacity; significant enforcement actions began emerging in 2023. POPIA is broadly modeled on the EU 1995 Data Protection Directive (predecessor to GDPR); it predates GDPR but has similar structural concepts. Operators handling both EU and South African data subjects can leverage substantial overlap but track South African specifics (8 Conditions structure, Information Officer/Deputy IO designation requirement, mandatory IR registration, ZAR 10M penalty / 10-year imprisonment ceiling). The Information Regulator additionally administers the Promotion of Access to Information Act (PAIA), which establishes mandatory information manuals and access procedures for both public and private bodies. The GD\'s direct POPIA personal-information surface is narrow (GD user accounts only); the bulk of analyst-level POPIA concerns are evaluated at the MC layer.',
});
