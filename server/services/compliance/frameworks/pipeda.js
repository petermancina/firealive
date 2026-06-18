// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: PIPEDA (Canada)
//
// R3g (v1.0.33): coverage of Canada\'s Personal Information
// Protection and Electronic Documents Act under the Shared
// Responsibility schema.
//
// APPLICABILITY
//
//   PIPEDA applies to private-sector organizations that collect,
//   use, or disclose personal information in the course of
//   commercial activity. Specifically:
//
//     - Federally-regulated organizations (banking,
//       telecommunications, transportation, etc.) across all of
//       Canada
//     - Personal information in interprovincial or international
//       transactions
//     - Personal information of private-sector employees of
//       federally-regulated organizations
//     - Provincial coverage where there is no substantially
//       similar provincial law (Alberta, British Columbia, and
//       Québec have substantially-similar provincial privacy laws
//       that displace PIPEDA for intra-provincial private-sector
//       activity)
//
//   FireAlive is NOT inherently subject to PIPEDA. The Act does
//   not name FireAlive nor any class to which FireAlive belongs
//   as automatically scoped; applicability depends on each
//   operator\'s business activities and Canada exposure.
//
//   This framework definition is provided for customers
//   processing personal information of Canadians and have adopted
//   FireAlive in their SOC operations. The technical controls
//   support compliance with Principle 7 safeguards, Principle 9
//   individual access, and §10.1 breach notification. The
//   customer remains responsible for Principle 1 accountability
//   (privacy officer designation, privacy management program),
//   Principle 2-3 purposes/consent, Principle 5 retention,
//   Principle 8 openness, and §10.1 breach notification workflow.
//
//   For customers not processing Canadian personal information,
//   this framework report can be ignored without consequence.
//
// AUTHORITY
//
//   Office of the Privacy Commissioner of Canada (OPC). The OPC
//   is an Agent of Parliament that reports to the House of
//   Commons and the Senate. The Privacy Commissioner has
//   investigative authority but limited direct enforcement
//   powers; remedies are typically pursued in Federal Court after
//   the Commissioner\'s investigation.
//
//   Three provincial privacy commissioners administer
//   substantially-similar provincial laws: Alberta Information
//   and Privacy Commissioner (AB PIPA), British Columbia
//   Information and Privacy Commissioner (BC PIPA), and the
//   Commission d\'accès à l\'information du Québec (CAI) -- the
//   latter notably strengthened by Québec\'s Law 25 (formerly
//   Bill 64), with significant new requirements as of 2022-2024.
//
// PENALTIES
//
//   PIPEDA itself has limited direct administrative penalty
//   authority. Federal Court of Canada may impose damages and
//   injunctive relief on complaint. The Digital Charter
//   Implementation Act (Bill C-27) would significantly expand
//   penalties if enacted; track the legislative status.
//
//   Provincial laws have varied penalty regimes; Québec\'s Law 25
//   introduced administrative monetary penalties up to CAD 10
//   million or 2% of worldwide gross income (whichever higher).
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Personal Information Protection and Electronic Documents Act
//   (S.C. 2000, c. 5). Part 1 (Protection of Personal Information
//   in the Private Sector) incorporates the 10 fair information
//   principles from Schedule 1 (CSA Model Code for the Protection
//   of Personal Information).
//
//   Division 1.1 (Breaches of Security Safeguards) -- §10.1-10.3
//   -- mandatory breach notification regime added by the Digital
//   Privacy Act (S.C. 2015, c. 32) and in force since 1 November
//   2018.
//
//   verifiedControls map platform implementations to safeguards,
//   methods of protection, retention, individual access,
//   compliance challenges, and breach notification timing.
//   customerResponsibility covers accountability program, purpose
//   identification, consent management, collection limitation,
//   accuracy, openness, individual-access workflow, breach
//   notification workflow, and provincial-law coordination.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'PIPEDA (Canada)',
  authority: 'Office of the Privacy Commissioner of Canada (OPC)',
  citation: 'Personal Information Protection and Electronic Documents Act (S.C. 2000, c. 5)',
  verifiedControls: [
    {
      id: 'Principle 7 [Encryption]',
      name: 'Safeguards -- Encryption',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM at rest via TIER1/TIER3 keys (distinct); TLS 1.2+ at reverse proxy in transit. Schedule 1, Principle 7 requires personal information to be protected by security safeguards appropriate to the sensitivity of the information; encryption is foundational.',
    },
    {
      id: 'Principle 7 [Access]',
      name: 'Safeguards -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware; scoped API keys. Schedule 1, Principle 7 includes safeguards against unauthorized access, disclosure, copying, use, or modification.',
    },
    {
      id: 'Principle 4.7.3',
      name: 'Methods of Protection -- Logging',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request to audit_log; SIEM streaming externalizes events. Principle 4.7.3 includes administrative safeguards (e.g., logging) alongside technical and physical safeguards.',
    },
    {
      id: 'Principle 5',
      name: 'Limiting Use, Disclosure, and Retention -- Retention Schedule',
      check: checks.checkRetentionPolicy,
      mapping: 'Configurable retention policies via retention_config; offboarding workflow respects retention obligations while supporting deletion when allowable. Principle 5 requires retention only as long as necessary for identified purposes.',
    },
    {
      id: 'Principle 9',
      name: 'Individual Access',
      check: checks.checkDataSubjectRights,
      mapping: 'POST /api/data-subject/export produces a structured export of the subject\'s record across every store. Principle 9 grants individuals access to their personal information; the subject can self-serve or an admin can initiate the export.',
    },
    {
      id: 'Principle 10',
      name: 'Challenging Compliance',
      check: checks.checkAuditControls,
      mapping: 'audit_log enables organizations to demonstrate compliance with PIPEDA principles when challenged. Principle 10 requires organizations to provide accessible complaint procedures and respond to complaints.',
    },
    {
      id: '§10.1',
      name: 'Breach Notification Timing',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery to support breach notification. §10.1 requires notification to OPC, affected individuals, and (under §10.2) other organizations that may help reduce risk -- as soon as feasible after determining a breach has occurred that poses real risk of significant harm.',
    },
    {
      id: '§10.3',
      name: 'Breach Record Retention (24 months)',
      check: checks.checkAuditRetention,
      mapping: 'audit_log is unbounded (no auto-truncation); SIEM streaming creates external evidence. §10.3 requires records of every breach of security safeguards involving personal information to be kept for 24 months.',
    },
  ],
  customerResponsibility: [
    {
      id: 'Principle 1 [Officer]',
      name: 'Accountability -- Privacy Officer Designation',
      category: 'organizational',
      detail: 'Designate an individual(s) accountable for the organization\'s compliance with PIPEDA. The identity and contact information of the privacy officer must be made known on request. The accountability persists even when personal information is transferred to third parties for processing.',
    },
    {
      id: 'Principle 1 [Program]',
      name: 'Accountability -- Privacy Management Program',
      category: 'procedural',
      detail: 'Implement a privacy management program: policies and procedures, training, breach response plan, complaint handling, contracts with service providers including privacy obligations, audit/monitoring. OPC has published guidance on what a "demonstrably accountable" organization looks like.',
    },
    {
      id: 'Principle 2',
      name: 'Identifying Purposes',
      category: 'documentation',
      detail: 'Identify the purposes for which personal information is collected at or before the time the information is collected. Purposes are documented; new purposes require either new consent or fall within original consent scope. Communicate purposes to individuals.',
    },
    {
      id: 'Principle 3',
      name: 'Consent Management',
      category: 'procedural',
      detail: 'Knowledge and consent are required for collection, use, or disclosure of personal information (except where inappropriate or permitted by law). Form of consent (express vs implied) calibrated to sensitivity. Honor withdrawal of consent; document consent records.',
    },
    {
      id: 'Principle 4',
      name: 'Limiting Collection',
      category: 'procedural',
      detail: 'Limit collection of personal information to what is necessary for the identified purposes. Information collected by fair and lawful means. Document the necessity analysis for each data element collected.',
    },
    {
      id: 'Principle 6',
      name: 'Accuracy',
      category: 'procedural',
      detail: 'Personal information shall be as accurate, complete, and up-to-date as is necessary for the purposes for which it is to be used. Provide mechanisms for individuals to update or correct their information; document accuracy-maintenance procedures.',
    },
    {
      id: 'Principle 8',
      name: 'Openness -- Privacy Policy Publication',
      category: 'documentation',
      detail: 'Make readily available specific information about policies and practices relating to management of personal information. Public-facing privacy policy includes: name and contact of privacy officer, means of access to personal information held, kinds of personal information held and general account of use, what personal information is made available to related organizations.',
    },
    {
      id: 'Principle 9 [Workflow]',
      name: 'Individual Access Response Workflow',
      category: 'procedural',
      detail: 'Respond to access requests within 30 days (extendable +30 days with notice). Provide access at minimal or no cost to the individual; provide in alternative format if individual has sensory disability; account for any disclosures in past 12 months. Document workflow, verification, and refusal/redaction rationales.',
    },
    {
      id: '§10.1 [OPC]',
      name: 'Breach Notification to OPC -- "Real Risk of Significant Harm" Determination',
      category: 'procedural',
      detail: 'Determine whether a breach of security safeguards involves personal information that creates "real risk of significant harm" under §10.1(7). Factors per regulation: sensitivity of personal information, probability of misuse. If yes: notify OPC, affected individuals, and other organizations as relevant. Document the determination methodology and decision trail.',
    },
    {
      id: '§10.1 [Individuals]',
      name: 'Breach Notification to Affected Individuals',
      category: 'procedural',
      detail: 'Notify affected individuals as soon as feasible after determination of breach with real risk of significant harm. Direct notification preferred (email, mail, telephone, in person). Indirect notification (website, public announcement) permitted where direct notification would cause further harm, is prohibitively expensive, or contact info unavailable.',
    },
    {
      id: '§10.2',
      name: 'Breach Notification to Other Organizations',
      category: 'procedural',
      detail: 'Notify any government institution or organization that can help reduce the risk of harm or mitigate the harm. Examples: financial institutions (for credit-related breaches), law enforcement (for criminal breaches), other organizations with related data.',
    },
    {
      id: '§10.3 [Workflow]',
      name: 'Breach Record Retention Procedure',
      category: 'documentation',
      detail: 'Keep a record of every breach of security safeguards involving personal information under the organization\'s control for 24 months. Records available to OPC on request. The 24-month retention applies to ALL breaches, not just those triggering individual notification under §10.1.',
    },
    {
      id: 'Provincial-Law',
      name: 'Provincial Privacy Law Coordination',
      category: 'procedural',
      detail: 'For intra-provincial private-sector activity in Alberta, British Columbia, and Québec: provincial law displaces PIPEDA. Alberta PIPA and BC PIPA are substantially-similar to PIPEDA but with provincial-specific procedural rules. Québec Law 25 is substantially stronger than PIPEDA -- includes 72-hour breach notification, automated decisionmaking transparency, anonymization criteria, and CAD 10M / 2% global gross income administrative monetary penalties.',
    },
    {
      id: 'CPPA-Tracking',
      name: 'CPPA (Bill C-27) Legislative Tracking',
      category: 'procedural',
      detail: 'Bill C-27 (Digital Charter Implementation Act) would replace PIPEDA with the Consumer Privacy Protection Act (CPPA) and create the Personal Information and Data Protection Tribunal. Significant new administrative penalties (up to CAD 10M / 3% global revenue), strengthened consent rules, and data-mobility rights would apply. Track the legislative status; assess organizational readiness for transition.',
    },
  ],
  note: 'PIPEDA combines the federal private-sector privacy law with electronic-documents/signatures provisions. Personal information protection in Canada is layered: federal (PIPEDA) + provincial (AB PIPA, BC PIPA, Québec Law 25) for the private sector; federal Privacy Act for federal government institutions; provincial public-sector laws for provincial/municipal government. The patchwork is unique among comparable jurisdictions. Bill C-27 (introduced 2022, in committee as of writing) would significantly modernize the federal regime if enacted, including substantial new penalty authority. Operators handling Canadian personal information should track both PIPEDA and Bill C-27 developments. Québec Law 25 is substantially more demanding than PIPEDA and operates as a forerunner for what enhanced federal regulation might look like.',
});
