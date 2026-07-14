// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: CCPA / CPRA
//
// R3g (v1.0.33): coverage of the California Consumer Privacy Act
// (CCPA) as amended by the California Privacy Rights Act (CPRA)
// under the Shared Responsibility schema.
//
// APPLICABILITY
//
//   CCPA / CPRA applies to for-profit entities doing business in
//   California that satisfy at least one of these thresholds:
//
//     - Annual gross revenue exceeding USD 25,000,000 (as adjusted
//       for inflation per CCPA regulations)
//     - Annually buys, sells, or shares personal information of
//       100,000 or more California consumers or households
//     - Derives 50% or more of annual revenue from selling or
//       sharing California consumers\' personal information
//
//   FireAlive is NOT inherently subject to CCPA / CPRA. The
//   statute does not name FireAlive nor any class to which
//   FireAlive belongs as automatically subject; applicability
//   depends on each operator\'s business activities and California
//   consumer exposure.
//
//   This framework definition is provided for customers that meet
//   the CCPA / CPRA thresholds and have adopted FireAlive in their
//   SOC operations. The technical controls support compliance with
//   §1798.100(e) reasonable security duty, §1798.105/106/110/115
//   consumer rights, §1798.121 sensitive personal information (SPI)
//   limits, §1798.130 verification, and §1798.150 encryption
//   defense for the private right of action. The customer remains
//   responsible for privacy notice content, request-handling
//   workflow, service-provider contracts, GPC honoring, and CPPA
//   regulation compliance.
//
//   For non-California-consumer-data-processing customers, this
//   framework report can be ignored without consequence.
//
// AUTHORITY
//
//   California Privacy Protection Agency (CPPA), established by
//   CPRA and operational since 2022. CPPA has rulemaking authority
//   under §1798.185 and enforcement authority alongside the
//   California Attorney General. CPPA Board members are appointed
//   by Governor, Legislature, and Attorney General.
//
//   Private right of action under §1798.150 enables individual
//   consumers to seek statutory damages of USD 100-750 per
//   incident per consumer for breaches of unencrypted personal
//   information caused by violation of reasonable security duty.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   California Civil Code Title 1.81.5 §§ 1798.100-1798.199.100
//   (CCPA as amended by CPRA). CPRA-amendment effective dates:
//   most provisions 1 January 2023, enforcement 1 July 2023.
//
//   CPRA introduced the CPPA, sensitive personal information (SPI)
//   category with separate consumer rights, right to correct,
//   contractor designation (alongside service provider), purpose
//   limitation, retention disclosure, and other expansions over
//   original CCPA.
//
//   verifiedControls map platform implementations to security duty,
//   consumer rights (delete/correct/know/limit SPI), verification,
//   and encryption-defense controls. customerResponsibility covers
//   privacy notice, request handling, service-provider contracts,
//   opt-out signals, training, and CPPA regulation compliance.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'CCPA / CPRA',
  authority: 'California Privacy Protection Agency (CPPA) and California Attorney General',
  citation: 'California Civil Code §§ 1798.100-1798.199.100 -- California Consumer Privacy Act as amended by the California Privacy Rights Act',
  verifiedControls: [
    {
      id: '§1798.100(e) [Encryption]',
      name: 'Reasonable Security -- Encryption',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM at rest via TIER1/TIER3 keys (distinct); TLS 1.2+ at reverse proxy in transit. §1798.100(e) requires reasonable security procedures and practices appropriate to the nature of the information; encryption is foundational.',
    },
    {
      id: '§1798.100(e) [Access Control]',
      name: 'Reasonable Security -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware; scoped API keys. Reasonable security includes limiting access to personal information to those with a need.',
    },
    {
      id: '§1798.105',
      name: 'Right to Delete',
      check: checks.checkDataSubjectRights,
      mapping: 'Offboarding workflow (active=0 soft delete) + pseudonym rotation severs identity-signal linkage for analyst data. §1798.105 right to delete is subject to enumerated exceptions; operator implements the response-decision workflow.',
    },
    {
      id: '§1798.106',
      name: 'Right to Correct',
      check: checks.checkDataSubjectRights,
      mapping: 'User-update endpoints permit correction of personal information; pseudonym rotation supports correction of pseudonymous behavioral data linkage. §1798.106 (added by CPRA) requires correction of inaccurate personal information.',
    },
    {
      id: '§1798.110',
      name: 'Right to Know',
      check: checks.checkDataSubjectRights,
      mapping: 'POST /api/data-subject/export produces a structured export of the subject\'s record across every store. §1798.110 right to know covers specific pieces of personal information collected about the consumer; the export provides that data directly.',
    },
    {
      id: '§1798.115',
      name: 'Right to Know About Sale/Sharing',
      check: checks.checkAuditControls,
      mapping: 'audit_log captures all data-handling events; if the entity sells or shares personal information, audit_log + integration_config enable the entity to enumerate third-party recipients in response to §1798.115 requests.',
    },
    {
      id: '§1798.121',
      name: 'Right to Limit Use of Sensitive Personal Information',
      check: checks.checkPseudonymization,
      mapping: 'Analyst pseudonym_uuid + pseudonym_rotated_at fields sever identity linkage for wellbeing/behavioral data that may constitute SPI under §1798.140(ae). CPRA-introduced right; operator implements the workflow for honoring limit-use requests.',
    },
    {
      id: '§1798.130(a)(5)',
      name: 'Verification Methods',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication; multi-factor via a FIDO2 hardware passkey (AAL3, phishing-resistant). §1798.130(a)(5) requires reasonable methods to verify the requester for sensitive rights (delete, know, limit SPI). The verification workflow itself is operator-defined.',
    },
    {
      id: '§1798.150 [Encryption Defense]',
      name: 'Private Right of Action Encryption Defense',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM at rest. §1798.150(a)(1) limits statutory damages under the private right of action to breaches of nonencrypted and nonredacted personal information. Encrypted data substantially reduces private-right-of-action exposure.',
    },
    {
      id: '§1798.150 [Key Management]',
      name: 'Encryption Defense -- Key Management',
      check: checks.checkKeyRotation,
      mapping: 'backup_signing_keys 180-day rotation cadence; kms_providers integration for hardware-backed key custody. The encryption defense under §1798.150 only holds if the encryption keys themselves were not also breached -- key custody and rotation are material.',
    },
  ],
  customerResponsibility: [
    {
      id: '§1798.100(a)(2)',
      name: 'Privacy Notice at Collection',
      category: 'documentation',
      detail: 'At or before the point of collection of personal information, inform consumers of: categories of personal information collected, purposes for collection/use, retention period for each category, whether sold or shared, categories of third parties to whom disclosed. Notice posted prominently on collection points.',
    },
    {
      id: '§1798.100(b)(2)',
      name: 'Privacy Policy Annual Update',
      category: 'documentation',
      detail: 'Privacy policy updated at least every 12 months. Policy posted prominently on website; explains consumer rights and how to exercise them, retention practices, sale/sharing practices.',
    },
    {
      id: '§1798.130 [Methods]',
      name: 'Methods for Submitting Consumer Requests',
      category: 'procedural',
      detail: 'Provide at least two designated methods for submitting requests (e.g., toll-free telephone number, online form, email address, in-person at retail location). If the business operates exclusively online with a direct relationship with consumer, an email address may suffice.',
    },
    {
      id: '§1798.130 [Response]',
      name: 'Request Response Workflow',
      category: 'procedural',
      detail: 'Respond to access / delete / correct / limit-SPI requests within 45 calendar days (extendable +45 days with notice). Confirm receipt within 10 business days. For free first response per 12-month period; reasonable fee permitted for additional copies. Document response workflow and SLAs.',
    },
    {
      id: '§1798.130(a)(5)',
      name: 'Verification Procedures Documentation',
      category: 'procedural',
      detail: 'Document verification procedures for consumer requests, calibrated to the sensitivity of the request and the type of information. Categorize as "verified consumer", "reasonable degree of certainty", "high degree of certainty" depending on right requested. CPPA regulations elaborate verification requirements.',
    },
    {
      id: '§1798.135',
      name: 'Notice of Right to Opt-Out of Sale/Sharing',
      category: 'documentation',
      detail: 'Provide a clear and conspicuous link titled "Do Not Sell or Share My Personal Information" on the business\'s internet homepage. Link directs to opt-out mechanism. Alternative link text "Your California Privacy Choices" is also permitted.',
    },
    {
      id: '§1798.135(b)(1)',
      name: 'Global Privacy Control (GPC) Browser Signal Honoring',
      category: 'procedural',
      detail: 'Honor Global Privacy Control browser signals as a valid opt-out request. GPC indicates the consumer\'s opt-out preference at the browser level; treat as equivalent to an explicit opt-out. CPPA enforcement has explicitly addressed GPC since 2022.',
    },
    {
      id: '§1798.140 [Service Provider]',
      name: 'Service Provider Contracts',
      category: 'documentation',
      detail: 'For each service provider (e.g., FireAlive when configured to process consumer personal information), have a written contract limiting the service provider\'s use of personal information to the business purposes specified. Required contractual provisions per CCPA / CPRA regulations.',
    },
    {
      id: '§1798.140 [Contractor]',
      name: 'Contractor Contracts',
      category: 'documentation',
      detail: 'For each contractor (entity that makes available personal information for a business purpose pursuant to written contract -- distinct from service provider), maintain the contractual protections required by CPRA, including processing limitations and end-of-engagement requirements.',
    },
    {
      id: '§1798.145',
      name: 'Employee and B2B Exemption Awareness',
      category: 'procedural',
      detail: 'CCPA / CPRA exemptions for employee personal information and B2B personal information expired 1 January 2023. Employee and B2B contexts are now fully covered. Update internal practices to extend privacy notices, request mechanisms, and other obligations to employee and B2B personal information.',
    },
    {
      id: '§1798.155',
      name: 'Civil Penalty Exposure Awareness',
      category: 'organizational',
      detail: 'Up to USD 2,500 per unintentional violation, up to USD 7,500 per intentional violation. CPPA administrative actions and California Attorney General civil actions. The cure period under original CCPA was eliminated by CPRA for many violations; remediation does not automatically prevent enforcement.',
    },
    {
      id: '§1798.185',
      name: 'CPPA Regulations Compliance',
      category: 'procedural',
      detail: 'Track CPPA-issued regulations under §1798.185. CPPA has finalized regulations on (among others) cybersecurity audit, risk assessment, automated decisionmaking technology, insurance regulation, and additional rules. Maintain awareness of pending regulations and adjust practices accordingly.',
    },
    {
      id: 'Training',
      name: 'Employee Training on CCPA / CPRA Obligations',
      category: 'training',
      detail: 'Train employees handling consumer requests on CCPA / CPRA obligations, verification procedures, response timelines, and escalation pathways. Document training cadence and content; require periodic refresher training.',
    },
    {
      id: 'Multi-State',
      name: 'Multi-State Privacy Law Coordination',
      category: 'procedural',
      detail: 'CCPA / CPRA is one of ~14 US state privacy laws (Virginia, Colorado, Connecticut, Utah, Texas, Oregon, Montana, Iowa, Tennessee, Delaware, Indiana, New Hampshire, New Jersey, Kentucky and growing). Maintain a multi-state compliance matrix; harmonize where possible but track state-specific provisions (e.g., CCPA SPI category does not match Virginia CDPA "sensitive data").',
    },
  ],
  note: 'CCPA was enacted in 2018; CPRA amended CCPA effective 1 January 2023 with enforcement beginning 1 July 2023. The CPPA Board has rulemaking authority and has been actively issuing regulations. The private right of action under §1798.150 is unusual among US privacy laws -- most state laws are enforcement-only. The encryption defense materially reduces statutory-damages exposure if breached data was encrypted. CCPA / CPRA represents one approach in the proliferating US state privacy landscape; operators handling US consumer data should track all applicable state laws and may benefit from a multi-state compliance program rather than per-state implementations.',
});
