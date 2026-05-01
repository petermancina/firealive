// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — TTX Scenario Library (Phase 1.4d)
//
// Curated tabletop exercise scenarios. Each scenario has:
//   - id: stable identifier used by routes and audit logs
//   - title: human-readable name
//   - category: ransomware, data_exfil, insider_threat, etc.
//   - description: 2-3 sentence framing for the SitMan cover
//   - actors: list of roles/teams mentioned in the scenario
//   - assumptions: ground truth the participants accept (e.g., "MFA is enabled
//     for all admin accounts", "EDR is deployed but not tuned")
//   - difficulties: { easy, intermediate, hard } each containing:
//     - brief: opening narrative the facilitator reads aloud
//     - injects: ordered events that escalate the scenario, each with
//       timing (e.g., "T+15min"), text, and decision_points
//     - discussion_questions: open-ended prompts for the team
//     - references: NIST/HSEEP/MITRE links for facilitator prep
//
// Source material:
//   - NIST SP 800-84 (tabletop exercise design)
//   - CISA Tabletop Exercise Packages (CTEPs)
//   - MITRE ATT&CK for inject realism
//   - HSEEP Volume IV (exercise documentation)
//
// Difficulty calibration (consistent across all scenarios):
//   easy:         3-4 injects, 1-2 decision points each, 4-6 discussion qs.
//                 Clear chain of events, single attack vector, room for the
//                 team to talk through process without panic.
//   intermediate: 5-7 injects, 2-3 decision points each, 6-8 discussion qs.
//                 Multiple concurrent issues, some red herrings, third-party
//                 involvement.
//   hard:         8-12 injects, 3-4 decision points each, 8-12 discussion qs.
//                 Cascading failures, conflicting indicators, time pressure
//                 baked into the timeline, multi-stakeholder coordination.
//
// Adding a scenario: append to SCENARIOS array. Keep ids stable — the audit
// log references them. Removing a scenario: don't. If a scenario goes stale,
// mark it deprecated:true and stop offering it in the picker but leave the
// data so old audit references still resolve.
// ═══════════════════════════════════════════════════════════════════════════════

const SCENARIOS = [
  {
    id: 'ransomware-finance-shared',
    title: 'Ransomware: Finance department shared drive',
    category: 'ransomware',
    description: 'A ransomware variant has begun encrypting files on the finance department\'s shared drive. The encryption is in progress when discovered. Backups exist but their integrity is unconfirmed.',
    actors: ['SOC analyst on shift', 'IR lead', 'Finance department head', 'IT operations', 'Legal counsel', 'External IR retainer (optional callout)'],
    assumptions: [
      'Daily backups are taken and stored on a separate system.',
      'EDR is deployed on all endpoints but tuning is incomplete.',
      'No formal ransomware playbook exists; the team has the IR Recovery Runbook system.',
      'Cyber insurance is in place. Carrier requires notification within 24 hours of confirmed incident.',
    ],
    difficulties: {
      easy: {
        brief: 'It is 09:15 on a Tuesday. The finance department head calls the IT helpdesk reporting that several spreadsheets on the shared drive will not open. The error message says the files are "encrypted by [redacted]." She says about ten files are affected. The SOC analyst on shift has just been pulled in.',
        injects: [
          {
            timing: 'T+0',
            text: 'Helpdesk forwards the call to the SOC. Initial report: 10 files affected on \\\\fileserver01\\finance. User reports files were fine an hour ago.',
            decision_points: [
              'Who declares this an incident, and when?',
              'What is the first containment action?',
            ],
          },
          {
            timing: 'T+10min',
            text: 'EDR alerts fire on the file server: suspicious process writing to many files in rapid succession. The alerts had been firing for 8 minutes before anyone looked at them.',
            decision_points: [
              'How does the team handle the EDR alert backlog issue going forward?',
              'Do you isolate the file server now? What does the business impact look like?',
            ],
          },
          {
            timing: 'T+25min',
            text: 'IT operations confirms backups exist for the finance shared drive (last successful: 03:00 today). Backup system is on a separate VLAN.',
            decision_points: [
              'Do you initiate restore now, or contain first and verify scope?',
              'How do you confirm the backups themselves are clean?',
            ],
          },
          {
            timing: 'T+45min',
            text: 'Encryption appears to have stopped. About 240 files affected. No ransom note found yet. No evidence of lateral movement.',
            decision_points: [
              'When and how do you notify the cyber insurance carrier?',
              'When do you tell the finance department they can stop working / can resume work?',
            ],
          },
        ],
        discussion_questions: [
          'What was the gap between EDR alert firing and human review? What process change closes that gap?',
          'Who has authority to declare a ransomware incident in this org? Is that documented anywhere the SOC can reach at 09:15?',
          'What is the legal reporting threshold? Does this incident cross it? Who decides?',
          'If backups had been compromised too, what would the next step have been?',
          'Walk through the communication tree. Who tells the CEO? When?',
        ],
        references: [
          'NIST SP 800-61r2 — Computer Security Incident Handling Guide',
          'CISA #StopRansomware Guide (joint advisory)',
        ],
      },
      intermediate: {
        brief: 'It is 09:15 on a Tuesday. The finance department head calls reporting encrypted files. Within minutes, similar reports come in from HR and legal. The SOC has multiple EDR alerts in queue from overnight that no one reviewed because the on-call analyst was responding to a P1 SIEM alert that turned out to be a false positive.',
        injects: [
          { timing: 'T+0', text: 'Three departments report encrypted files on three separate shared drives. Helpdesk is overwhelmed.', decision_points: ['Who establishes incident command? Where does that command structure live?', 'What is the priority order for the three drives?', 'Does the team activate the IR Recovery Runbook now or wait for more information?'] },
          { timing: 'T+8min', text: 'EDR shows the encryption process originated from a workstation in finance — user account mfaherty. The user is in a meeting and not at her desk.', decision_points: ['Do you isolate her workstation remotely now, or wait to talk to her?', 'How do you reach her without tipping off a potential insider threat?'] },
          { timing: 'T+20min', text: 'The compromised workstation has VPN access to the data center. EDR shows credential dumping activity 6 hours before the encryption started.', decision_points: ['What credentials are at risk? Who decides which to rotate?', 'Do you pull the plug on the VPN tunnel for that user, the whole department, or globally?'] },
          { timing: 'T+35min', text: 'Backup verification reveals last night\'s backup of the finance share is incomplete — the backup job failed at 03:47 and no one was paged.', decision_points: ['How far back do you go for a clean restore?', 'Who owns the missing-backup-alert gap?'] },
          { timing: 'T+55min', text: 'A ransom note is found on the finance share. Demand: $850K in Monero. Wallet address provided. Deadline: 72 hours.', decision_points: ['Who reads the ransom note? Who is told it exists?', 'Is anyone on the team thinking about paying? What is the org\'s public stance? What is the legal stance?'] },
          { timing: 'T+90min', text: 'A journalist from a regional tech publication emails the press contact: "We have heard you are dealing with a ransomware incident. Comment?"', decision_points: ['Who handles the media inquiry?', 'What is said? What is not said?', 'Who needs to know the media is asking before someone else gives a statement?'] },
          { timing: 'T+2hr', text: 'The cyber insurance carrier has been notified. Their preferred IR firm is on the way. They want full network access for forensics within 4 hours.', decision_points: ['How do you give a third party "full network access" without making the situation worse?', 'What evidence preservation has happened so far? Is it forensically sound?'] },
        ],
        discussion_questions: [
          'Where did the EDR alert backlog start? What process or staffing change prevents it next time?',
          'Walk through the credential rotation. Whose credentials? In what order? Who has the authority to do it?',
          'How does the team coordinate with an external IR firm under time pressure? Who is the single point of contact?',
          'What is the org\'s position on paying ransom? Is it written down? Where? Who has the decision rights?',
          'The backup job failure went unnoticed. What backup health monitoring exists? Is it sufficient?',
          'What does the team tell employees in the affected departments while the investigation is active?',
          'Walk through the legal notification timeline. State breach notification laws, federal requirements, contractual obligations to customers.',
        ],
        references: [
          'NIST SP 800-61r2 — Computer Security Incident Handling Guide',
          'CISA #StopRansomware Guide',
          'MITRE ATT&CK T1486 (Data Encrypted for Impact), T1003 (OS Credential Dumping)',
        ],
      },
      hard: {
        brief: 'It is 03:00 on a Saturday holiday weekend. The on-call SOC analyst is paged: ransomware alerts firing across multiple subsidiaries simultaneously. The IR lead is unreachable (international travel). The backup IR lead is on vacation. Cyber insurance carrier line goes to voicemail. The team has the IR Recovery Runbook system and a partial playbook from the most recent runbook the team built.',
        injects: [
          { timing: 'T+0', text: 'Encryption alerts fire on file servers in the US, EU, and APAC subsidiaries within the same 5-minute window. Pattern suggests coordinated attack, not opportunistic ransomware.', decision_points: ['Who declares the incident? With both IR leads unavailable, what does the escalation tree say?', 'How do you determine if this is one actor with persistent access or three coincident attacks?', 'What is the first defensive action when you suspect coordinated attack?'] },
          { timing: 'T+15min', text: 'EDR shows lateral movement from a compromised domain controller. The DC was compromised 11 days ago based on log timestamps. The attacker has had 11 days of dwell time.', decision_points: ['What does 11 days of dwell time mean for evidence preservation?', 'How do you scope the compromise? What systems do you assume are dirty?', 'Do you trust your existing detection telemetry or assume tampering?'] },
          { timing: 'T+30min', text: 'Domain controllers in two regions are now offline. Authentication is failing across the org. VPN users are getting logged out. Critical business apps are inaccessible.', decision_points: ['Is this the attacker\'s next phase, or your team\'s containment side effect?', 'How do you maintain communication if your auth systems are down?', 'Do you have a known-good out-of-band channel? Is anyone on it?'] },
          { timing: 'T+50min', text: 'A second ransom note is found, distinct from the first. Different wallet, different language, different payment demand. Suggests two threat actors.', decision_points: ['Are there really two actors, or is this one actor staging a confusion play?', 'How does this change the investigation strategy?'] },
          { timing: 'T+1hr 15min', text: 'Customer-facing API starts returning 500s. Sales operations team starts paging executive leadership. Twitter is starting to notice.', decision_points: ['What is the team\'s public communication posture? Who decides?', 'Status page: update or stay silent? What does each option signal?'] },
          { timing: 'T+1hr 45min', text: 'A third subsidiary reports a separate, possibly unrelated incident: a Tier 3 SaaS provider has emailed claiming they detected anomalous access from your accounts.', decision_points: ['Is the SaaS incident related? Do you treat it as if it is?', 'Who interfaces with the SaaS provider while the rest of the team handles the main incident?'] },
          { timing: 'T+2hr 30min', text: 'The IR lead\'s phone is reached. She is in a country 12 time zones away. She joins on a poor connection. The first thing she asks is whether the team has activated the IR Recovery Runbook.', decision_points: ['How do you brief someone joining 2.5 hours into an incident, on a bad line, jet-lagged?', 'What if her instructions conflict with what the team has already done?', 'How is the runbook keeping the audit trail so she can catch up?'] },
          { timing: 'T+3hr', text: 'Forensics finds evidence of data exfiltration to an attacker-controlled server. Volume estimate: 240 GB. Content unknown but the staging directory had finance, HR, and customer DB exports.', decision_points: ['You now have a data breach in addition to ransomware. How do reporting obligations change?', 'How does this change the team\'s posture on ransom payment?', 'What does the team tell affected customers? When?'] },
          { timing: 'T+4hr', text: 'CEO joins the bridge. She wants a one-page summary of: what happened, what you know, what you don\'t know, what you\'re doing, and whether you need her to authorize anything.', decision_points: ['Who writes the one-pager? When?', 'What goes on it? What gets left off?', 'How is this written so that if she forwards it to the board, it doesn\'t make things worse?'] },
          { timing: 'T+5hr 30min', text: 'Cyber insurance carrier reaches the team. They activate their IR retainer. The retainer firm wants administrator access to all systems for forensics. Their lead investigator says he wants to "wipe and rebuild" the affected DCs.', decision_points: ['Wipe-and-rebuild destroys evidence. How does the team negotiate?', 'How do you give third-party admin access during an active incident without expanding the blast radius?', 'Who has authority to override an IR firm recommendation?'] },
          { timing: 'T+8hr', text: 'A regulator (state AG\'s office) is calling. They have heard about the incident from a leaked screenshot circulating on Twitter. They want to know if customer PII was exposed.', decision_points: ['Who responds to the regulator? With what?', 'What is the org\'s legal counsel saying about state breach notification timing?', 'How do you balance regulatory transparency with investigation operational security?'] },
        ],
        discussion_questions: [
          'Walk through the escalation tree when both primary IR leads are unavailable. Is it documented? Was anyone trained on it?',
          'What is the team\'s posture on ransom payment when data exfiltration is also confirmed? Has that been written down before today?',
          'How does the team coordinate three concurrent regional responses without fragmenting the investigation?',
          'How long would it have taken to detect the original DC compromise without the ransomware revealing it? What detection gap does that 11-day dwell time expose?',
          'Walk through the IR firm engagement under time pressure. Where does their authority end and yours begin? Is that in the contract?',
          'How does the team verify the second ransom note is/isn\'t real before acting on it?',
          'What is the customer notification timeline given confirmed exfiltration? GDPR (72hr), state laws (varies), contractual (varies). Who tracks each clock?',
          'After the incident, what does the AAR need to capture for board, regulator, and insurance audiences? Are those the same document or different?',
          'How does the team decompress after a 12+ hour incident response? What is the wellbeing protocol?',
          'What does the team need from leadership to be ready for an attack of this scale next time?',
        ],
        references: [
          'NIST SP 800-61r2 — Computer Security Incident Handling Guide',
          'NIST SP 800-184 — Guide for Cybersecurity Event Recovery',
          'CISA #StopRansomware Guide',
          'MITRE ATT&CK: T1486, T1003, T1078 (Valid Accounts), T1041 (Exfiltration Over C2)',
          'HSEEP Volume IV — Exercise Documentation',
        ],
      },
    },
  },
  {
    id: 'data-exfil-departing-employee',
    title: 'Data exfiltration: departing employee',
    category: 'data_exfiltration',
    description: 'A senior engineer has given two weeks notice. DLP triggers fire on his account showing large data transfers to a personal cloud account. He has not yet been notified that the team is aware.',
    actors: ['SOC analyst', 'IR lead', 'HR business partner', 'Legal counsel', 'Engineering manager (suspect\'s direct supervisor)', 'IT operations'],
    assumptions: [
      'DLP is deployed on endpoints and at the egress.',
      'The departing employee has admin access to multiple production systems.',
      'There is an employee handbook with acceptable use policy. There is no specific clause on data retention by departing employees.',
      'The new employer is publicly known to be a competitor.',
    ],
    difficulties: {
      easy: {
        brief: 'Wednesday, 14:00. DLP fires an alert: 12 GB transfer to a personal Google Drive account from the laptop of a senior engineer who gave notice five days ago. He has 9 working days remaining.',
        injects: [
          { timing: 'T+0', text: 'DLP alert: 12 GB transferred. File types: source code repos, design docs, customer lists.', decision_points: ['Is this an incident or an HR matter? Who decides?', 'What is the first action? Talk to the employee, escalate to HR, or preserve evidence first?'] },
          { timing: 'T+15min', text: 'Audit log review shows the transfer happened over 4 hours, mostly during the lunch hour when his manager would not have noticed.', decision_points: ['What does this tell you about intent?', 'Do you assume more transfers happened that DLP missed?'] },
          { timing: 'T+30min', text: 'HR confirms his last day is in 9 working days. He is leaving to join a publicly named competitor.', decision_points: ['Does this change the response? What is the legal exposure?', 'Who needs to know within the next hour?'] },
          { timing: 'T+1hr', text: 'Legal counsel is on the phone. They want to know what was taken before they advise on response.', decision_points: ['How quickly can you produce a definitive list of what was exfiltrated?', 'What if he has remote-wiped his evidence trail?'] },
        ],
        discussion_questions: [
          'What is the org\'s policy on monitoring departing employees? Is the policy actually applied? When does it kick in?',
          'How does the team distinguish "taking my own work product" from "stealing IP"?',
          'When you confront an employee with evidence of exfiltration, what do you say? Who is in the room?',
          'What is the technical action plan in the next hour? Account lock, credential rotation, access review?',
          'What does the AAR look like for an incident that resolves into legal action rather than a technical fix?',
        ],
        references: [
          'NIST SP 800-61r2',
          'Carnegie Mellon CERT Insider Threat Center publications',
        ],
      },
      intermediate: {
        brief: 'Wednesday, 14:00. DLP fires multiple alerts on the senior engineer who gave notice. 12 GB to personal Google Drive. He still has admin access to the production source code repo, the customer database, and the engineering wiki. His manager is on PTO.',
        injects: [
          { timing: 'T+0', text: 'DLP alert: 12 GB transfer. Source code, customer data, design docs.', decision_points: ['First action with the manager unreachable?', 'Who fills in for the missing manager during the response?'] },
          { timing: 'T+10min', text: 'Audit logs show 30 days of unusual git clone activity from his account. Consistent across his entire notice period.', decision_points: ['How far back do you investigate?', 'Were there indicators before notice was given?'] },
          { timing: 'T+25min', text: 'A second alert: he has just emailed the customer database export to his personal Gmail.', decision_points: ['Is this still in progress? Do you intervene now?', 'Email has gone — can it be retrieved? From whom?'] },
          { timing: 'T+45min', text: 'HR is concerned about wrongful termination exposure if you act before having a clear picture.', decision_points: ['How do you balance evidence preservation with HR concerns?', 'Who has authority to override HR in an active incident?'] },
          { timing: 'T+1hr 15min', text: 'IT operations reports he has accessed three production systems in the last 30 minutes — including one he has no business reason to touch.', decision_points: ['Is he covering his tracks? Is he sabotaging on the way out?', 'When do you revoke his access? With what justification?'] },
          { timing: 'T+1hr 45min', text: 'Engineering manager is reached on PTO. He says, "Oh, he asked me last week if he could take some of his own code as portfolio work. I said sure."', decision_points: ['How does this change the response?', 'Was the manager authorized to grant that?', 'What does this say about the org\'s policies?'] },
        ],
        discussion_questions: [
          'When does monitoring of departing employees begin? Day of notice? Day after? Some scenarios warrant pre-notice monitoring?',
          'What is the manager\'s authority to grant data takeout? Is it written down?',
          'How does the team scope the investigation: does this widen to other recent departures?',
          'What is the legal escalation path? Who decides whether to pursue legal action?',
          'How does the team document this so the AAR supports either a clean termination or an actionable lawsuit?',
          'How does the team preserve the suspect\'s laptop without tipping him off?',
        ],
        references: [
          'NIST SP 800-61r2',
          'CMU CERT Insider Threat Common Sense Guide',
          'MITRE ATT&CK T1567 (Exfiltration to Cloud Storage)',
        ],
      },
      hard: {
        brief: 'A senior engineer gave notice 10 days ago. DLP fires on his account. Within an hour, you discover the exfiltration started 90 days ago — well before he gave notice. He is one of three engineers who left in the last six weeks. They all went to the same competitor.',
        injects: [
          { timing: 'T+0', text: 'DLP alert: 12 GB transfer to personal cloud. Engineer is in his last week.', decision_points: ['First action?', 'How quickly can you correlate against other recent departures?'] },
          { timing: 'T+15min', text: 'Audit logs reveal 90 days of incremental data takeout, well-disguised inside normal work patterns. He clearly knew what he was doing.', decision_points: ['What does 90-day premeditation suggest?', 'How does that change the response posture?'] },
          { timing: 'T+30min', text: 'You correlate his activity against the two other recent departures. They share the same pattern. All three left for the same competitor. The competitor announced a "stealth team" two weeks ago.', decision_points: ['Coordinated departure / coordinated theft. Who do you tell first?', 'What is the org\'s relationship with the competitor? Are there NDAs in play?'] },
          { timing: 'T+1hr', text: 'The competitor has just published a blog post announcing a new product feature that closely mirrors a roadmap document one of the departed engineers had access to.', decision_points: ['How public was the roadmap? How public was their announcement?', 'Does this affect the legal calculus?'] },
          { timing: 'T+1hr 30min', text: 'Legal counsel pulls in outside trade-secret counsel. They want a full forensic preservation of all three former employees\' devices and accounts. Two of those devices have already been wiped per standard offboarding policy.', decision_points: ['Forensic preservation that should have happened didn\'t. What does the team say to legal?', 'How does this change offboarding policy going forward?'] },
          { timing: 'T+2hr', text: 'A board member calls the CTO directly. They have heard rumors about the departures and want to know if there is "an issue."', decision_points: ['Who responds to the board member? With what?', 'What is the comms plan when an active investigation has not been disclosed publicly?'] },
          { timing: 'T+3hr', text: 'The current engineer (who is still employed for 4 more days) discovers he is being investigated. He emails HR demanding an explanation, citing potential wrongful termination.', decision_points: ['How did he find out? Was there an OPSEC failure on the team\'s side?', 'How do you respond? With what timing?', 'Does the team continue the investigation, or does the dynamic change?'] },
          { timing: 'T+5hr', text: 'Forensics on his laptop reveals he has been using a personal VPN that masks DLP egress for some traffic. The 12 GB DLP saw is the tip of the iceberg.', decision_points: ['Estimate the actual exposure. How?', 'What is the customer notification calculus if customer PII or contracts were exposed?'] },
          { timing: 'T+8hr', text: 'A press inquiry comes in. A reporter has been talking to one of the departed engineers about "his experience at the company." The reporter is fishing for a story about the exodus.', decision_points: ['What is the press response? Who handles it?', 'How does the team protect the active investigation while not being misleading to the press?'] },
        ],
        discussion_questions: [
          'When does pre-notice monitoring become legally and ethically defensible? Are there laws (state, federal, jurisdictional) that constrain it?',
          'How does the team detect a coordinated insider threat campaign? What signals were missed?',
          'What is the right offboarding forensic preservation policy? How long do you hold ex-employee data, and on what authority?',
          'How does the team handle the OPSEC failure that tipped off the suspect?',
          'What does the legal landscape look like for trade-secret litigation against a competitor with the documents in hand vs. circumstantial evidence?',
          'How does the team support the rest of engineering, who are watching their colleagues get investigated?',
          'What does the AAR recommend changing? Hiring? Offboarding? Detection? Culture?',
          'How does the org communicate with employees broadly without being either alarmist or so vague it breeds rumor?',
        ],
        references: [
          'NIST SP 800-61r2',
          'CMU CERT Insider Threat Common Sense Guide (5th ed.)',
          'EEUU Defend Trade Secrets Act (DTSA) and analogues',
          'MITRE ATT&CK T1567, T1078, T1530 (Data from Cloud Storage)',
        ],
      },
    },
  },
  {
    id: 'credential-compromise-helpdesk-vish',
    title: 'Credential compromise via helpdesk vishing',
    category: 'credential_compromise',
    description: 'An attacker called the IT helpdesk impersonating a remote employee, social-engineered an MFA reset, and now has access to that employee\'s account. The employee has flagged unusual activity.',
    actors: ['Helpdesk technician (target of the vish)', 'SOC analyst', 'IR lead', 'Targeted employee', 'IT operations'],
    assumptions: [
      'Helpdesk has documented MFA reset procedures, but they rely on knowledge-based authentication (date of birth, employee ID).',
      'MFA is enabled across the org.',
      'There is no requirement for video verification or callback to a known number.',
    ],
    difficulties: {
      easy: {
        brief: 'Tuesday, 10:30. A regional sales rep emails the helpdesk: "Did one of you call me yesterday? My account password was reset and I have been logged out everywhere." The helpdesk has no record of an outbound call.',
        injects: [
          { timing: 'T+0', text: 'Helpdesk reviews their internal queue. They have a record of an INBOUND call yesterday at 16:00 from someone identifying as the sales rep, who passed knowledge-based auth and got an MFA reset.', decision_points: ['Was the helpdesk procedure followed? Was it sufficient?', 'What are the immediate actions on the compromised account?'] },
          { timing: 'T+15min', text: 'Audit logs show the attacker logged in at 16:14, accessed the customer CRM, and downloaded a list of 1,200 contacts.', decision_points: ['Customer notification obligations?', 'How do you scope what else they may have done?'] },
          { timing: 'T+45min', text: 'Network logs show the attacker IP also tried to access SharePoint and the engineering wiki, but failed (no permission).', decision_points: ['What does the failed access tell you about their intent?', 'Was anything else attempted?'] },
        ],
        discussion_questions: [
          'What is the helpdesk MFA reset procedure? What does it rely on for identity verification?',
          'How does video or callback verification change the attack surface?',
          'What customer notification obligations are triggered by the CRM download?',
          'How does the team retrain helpdesk on social engineering resistance?',
        ],
        references: [
          'NIST SP 800-63B (Authentication)',
          'CISA Vishing Guidance',
        ],
      },
      intermediate: {
        brief: 'Tuesday, 10:30. The compromised account belongs to a sales engineer with broad access to demo environments and partner portals. The attack happened on Friday at 16:00 — 3.5 days of dwell time before the user noticed.',
        injects: [
          { timing: 'T+0', text: 'Sales engineer reports MFA reset he did not request. Account has been active for 3.5 days under the attacker.', decision_points: ['How do you scope 3.5 days of activity?', 'What systems does this account touch?'] },
          { timing: 'T+15min', text: 'Helpdesk has the recording of the inbound call. The attacker had the employee\'s real DOB, employee ID, and address. The helpdesk tech followed procedure exactly.', decision_points: ['How did the attacker get the verification info?', 'What changes to the procedure prevent this?'] },
          { timing: 'T+30min', text: 'Audit log review: attacker accessed 8 partner portals using SSO, downloaded customer pricing data from 3 of them.', decision_points: ['Partner notification obligations? When and how?', 'Who in the team coordinates with each partner?'] },
          { timing: 'T+1hr', text: 'A second similar vish attempt is happening RIGHT NOW. Helpdesk has another caller on the line trying the same approach with another employee\'s details.', decision_points: ['How do you handle the live attack?', 'What does the helpdesk tech do? What does the SOC do?', 'How do you document this for prosecution?'] },
          { timing: 'T+1hr 30min', text: 'OSINT reveals the org\'s employee directory was leaked on a paste site 6 months ago. It included DOBs (which had been required for a benefits enrollment that incidentally collected too much data).', decision_points: ['Why is DOB still being used as a verification factor when it has been leaked?', 'What is the policy review timeline?'] },
        ],
        discussion_questions: [
          'What knowledge-based authentication is the helpdesk using? Has any of it been leaked? How would the team know?',
          'What is the cost-benefit of video verification for MFA resets? Where would it be feasible?',
          'How does the team handle a live attack in progress? What is the SOC playbook?',
          'How does the team coordinate partner notifications when SSO has crossed a trust boundary?',
          'What is the offensive disclosure obligation when you can identify the attacker\'s phone number, IP, etc.?',
        ],
        references: [
          'NIST SP 800-63B',
          'CISA Vishing Guidance',
          'MITRE ATT&CK T1078 (Valid Accounts), T1556 (Modify Authentication Process)',
        ],
      },
      hard: {
        brief: 'A sophisticated attacker has run vishing campaigns against the helpdesk for 6 weeks. They have compromised at least 4 accounts. They have used those accounts to build a map of the org\'s SSO trust relationships. They are now staging the next phase: privilege escalation through a SaaS provider that the org federates with.',
        injects: [
          { timing: 'T+0', text: 'Investigation reveals the recent compromise was not the first. Audit logs show 4 accounts compromised over 6 weeks.', decision_points: ['Why was this not detected earlier?', 'What detection gap allowed 6 weeks of dwell?'] },
          { timing: 'T+30min', text: 'Forensics on the compromised accounts reveals the attacker has been mapping SSO trust: pulling SAML configs, listing federated SaaS apps, enumerating service accounts.', decision_points: ['What is the next attacker move? Pre-empt or react?', 'Which SaaS providers are highest risk?'] },
          { timing: 'T+1hr', text: 'A federated SaaS provider (a customer support tool) reports an unusual admin login from your org\'s SSO. It happened 2 hours ago. They are calling for verification.', decision_points: ['Confirm legitimate or compromise?', 'What does the SaaS provider need from the team to act?', 'What systems are downstream of the SaaS provider?'] },
          { timing: 'T+1hr 30min', text: 'The compromised SaaS admin account was used to add a new admin (not an employee in your org). That admin then accessed all customer support tickets, including those containing customer credentials in plaintext (a long-standing security gap with the SaaS provider).', decision_points: ['How does the team scope what was exposed?', 'What is the customer notification timeline now that customer credentials are in attacker hands?', 'How do you handle a vendor security gap that made the impact worse?'] },
          { timing: 'T+2hr 30min', text: 'A regional newspaper reporter calls. They have screenshots of customer support tickets. Their source is the attacker.', decision_points: ['How do you respond to the reporter?', 'How does the team negotiate timing — investigation vs. publication?', 'What is the disclosure obligation to customers vs. the operational security of an active investigation?'] },
          { timing: 'T+4hr', text: 'A senior leader pushes back on full credential rotation, citing operational impact. "We can\'t afford a full lockout right before quarter-end."', decision_points: ['How does the team make the case? What data does it need?', 'Where is the authority to decide? Is it documented?'] },
          { timing: 'T+5hr', text: 'Threat intel sharing partner reports the same vishing campaign hitting 6 other organizations in the sector. Your CISO is asked to join an industry call.', decision_points: ['What does the team share? What does it withhold?', 'How does industry coordination help / hurt the active investigation?'] },
          { timing: 'T+7hr', text: 'A second federated SaaS provider reports unusual activity. The attacker is moving laterally through the federation.', decision_points: ['How do you pull the federation trust without breaking the business?', 'What is the order of operations for revoking trust?'] },
          { timing: 'T+10hr', text: 'Investigation reveals one of the original 4 vish targets was a contractor whose employment ended 3 weeks ago — but their account was never deprovisioned.', decision_points: ['Lifecycle management gap. How widespread is it?', 'What does the AAR recommend on offboarding orphaned accounts?'] },
        ],
        discussion_questions: [
          'How does an org detect 6 weeks of slow-rolling vishing activity? What signals exist? What detection rules would catch it?',
          'How does the team approach SSO trust under active compromise? Tear it down, segment it, monitor it?',
          'What is the right level of dependency on third-party SaaS providers for security-critical access? How does the team measure and reduce it?',
          'How does the team\'s disclosure obligation change when the attacker is leaking to press?',
          'How does industry threat intel sharing actually work in real-time during an active incident?',
          'What is the orphan account problem in this org? How does the AAR fix it?',
          'How does the team support the helpdesk technicians who were social-engineered? Blame is not a useful response — what is?',
          'What does post-incident retraining look like for an attack that exploited correct procedure-following?',
          'What is the wellbeing impact on the team of a 10+ hour incident on top of weeks of stealth attack?',
        ],
        references: [
          'NIST SP 800-61r2, NIST SP 800-63B',
          'CISA Vishing and Smishing Guidance',
          'MITRE ATT&CK T1078, T1556, T1199 (Trusted Relationship), T1538 (Cloud Service Dashboard)',
        ],
      },
    },
  },
  {
    id: 'cloud-account-compromise',
    title: 'Cloud account compromise: leaked CI/CD credentials',
    category: 'cloud_account_compromise',
    description: 'A developer accidentally committed AWS credentials to a public GitHub repository. They were scraped within minutes. The attacker is now active in the cloud account.',
    actors: ['Developer who committed', 'SOC analyst', 'IR lead', 'Cloud platform engineer', 'Engineering manager'],
    assumptions: [
      'CI/CD has its own AWS credentials with broad permissions.',
      'No secret scanning is in place at commit time.',
      'CloudTrail is enabled but alerts are not tuned for compromise indicators.',
    ],
    difficulties: {
      easy: {
        brief: 'Friday, 11:00. AWS sends a credential exposure alert: an access key was found in a public GitHub commit by their abuse-detection scrapers. The commit was 8 minutes ago.',
        injects: [
          { timing: 'T+0', text: 'AWS notification: access key exposed publicly. Abuse detected: 1 EC2 instance launched in us-east-1 in the last 2 minutes.', decision_points: ['Rotate the key first or stop the instance first?', 'Who has authority to do either right now?'] },
          { timing: 'T+5min', text: 'CloudTrail shows the launched instance is a c5.24xlarge (large compute). Likely cryptomining.', decision_points: ['Cost exposure?', 'Is this only resource abuse, or are they staging something else?'] },
          { timing: 'T+15min', text: 'Three more instances launched in different regions in the last 5 minutes.', decision_points: ['Speed of attacker action vs. team response?', 'How do you stop all instances across regions efficiently?'] },
          { timing: 'T+30min', text: 'The compromised key has been rotated and the instances stopped. AWS shows total spend exposure: $340.', decision_points: ['How do you make sure no other resources were created?', 'What residual access remains?'] },
        ],
        discussion_questions: [
          'How did the credentials get committed? What process change prevents the next one?',
          'What secret scanning would catch this at commit time?',
          'What does the team do about the developer? Blame is not useful — what is?',
          'How tuned are CloudTrail alerts for "unusual instance launches"? Should they be tuned tighter?',
        ],
        references: [
          'AWS Security Best Practices',
          'NIST SP 800-204 (Microservices Security)',
        ],
      },
      intermediate: {
        brief: 'Friday, 11:00. A developer commits AWS credentials to a public GitHub repository. The commit is force-pushed-over within 3 minutes, but secret scrapers caught it. The attacker is in the account 5 minutes after commit.',
        injects: [
          { timing: 'T+0', text: 'Force-pushed commit detected by secret scanner. AWS notification arrives.', decision_points: ['Force-push hides the commit from casual viewers but not from scrapers. Does the dev team know that?', 'First containment action?'] },
          { timing: 'T+5min', text: 'CloudTrail shows attacker has called ListBuckets and is now downloading from a customer-data S3 bucket.', decision_points: ['Customer data exposure. How fast can you cut access?', 'What is the disclosure clock?'] },
          { timing: 'T+15min', text: 'The credentials had IAM policies that the dev did not realize granted PutObject on production buckets. The attacker has not used that yet.', decision_points: ['IAM least-privilege failure. Whose responsibility?', 'How does the team confirm what was downloaded vs. what could have been written?'] },
          { timing: 'T+30min', text: 'The customer data bucket contains PII for 14,000 customers. Attacker has downloaded approximately 2 GB.', decision_points: ['Notification calculus: GDPR clock, state laws, contractual.', 'Who tells customers, when, how?'] },
          { timing: 'T+1hr', text: 'AWS support is on a call. They want to know if you want them to "lock down" the account at the platform level (which would also impact production).', decision_points: ['Trade-off: more containment vs. operational impact.', 'Who has authority to decide in this moment?'] },
          { timing: 'T+1hr 30min', text: 'The committed credentials also worked for a CI/CD secret manager. The attacker has paused (no more activity for 20 minutes). Suspicious.', decision_points: ['Are they planning something bigger? Or did they get scared off?', 'How do you tell the difference?'] },
        ],
        discussion_questions: [
          'Why did broad-permission credentials end up on a developer\'s laptop? Was there a least-privilege failure?',
          'What is the customer notification timeline? Who decides?',
          'How does the team forensically confirm what was downloaded and when, given the attacker had legitimate-looking API calls?',
          'What CI/CD changes prevent this? Workload identity, secret managers, scanning at commit?',
          'How does the team support the developer who made the mistake?',
        ],
        references: [
          'AWS Security Best Practices',
          'NIST SP 800-61r2, NIST SP 800-204',
          'MITRE ATT&CK T1078.004 (Cloud Accounts), T1530 (Data from Cloud Storage)',
        ],
      },
      hard: {
        brief: 'A developer commits credentials. The attacker is in within 5 minutes. Within 30 minutes, the attacker has pivoted from the dev account to production by exploiting an over-permissive cross-account role. The compromise expands rapidly.',
        injects: [
          { timing: 'T+0', text: 'Credentials committed. Attacker active.', decision_points: ['First action?'] },
          { timing: 'T+10min', text: 'Attacker assumes a cross-account role from dev to staging. CloudTrail shows it.', decision_points: ['How do you contain mid-attack?', 'What is the cross-account trust posture? Who approved it?'] },
          { timing: 'T+25min', text: 'Attacker pivots from staging to production via a chain of role assumptions, ending at a service account with admin permissions on the production database.', decision_points: ['Production compromise.', 'Authentication architecture failure: a chain of trust let one leaked dev credential reach prod.', 'Who has the authority to take production offline?'] },
          { timing: 'T+45min', text: 'Database backups in S3 are being downloaded. Approximately 80 GB of customer data, financial records, internal communications.', decision_points: ['Data breach declaration. Timing? Audience?', 'How do you stop the download mid-flight without making it worse?'] },
          { timing: 'T+1hr', text: 'Attacker creates a new IAM user with a console password and attaches AdministratorAccess. They are establishing persistence.', decision_points: ['How do you identify and remove all attacker persistence?', 'Are there other persistence mechanisms you haven\'t looked for?'] },
          { timing: 'T+1hr 30min', text: 'The team makes an aggressive containment call: revoke all IAM session tokens org-wide. This will log out every employee, kill all CI/CD pipelines, and disrupt production.', decision_points: ['Operational impact vs. containment value.', 'How do you communicate to the rest of the org?', 'Is the call reversible? When?'] },
          { timing: 'T+2hr 30min', text: 'AWS forensics team joins. They find 2 more attacker IAM users from days earlier — the team had been compromised before today.', decision_points: ['Today\'s compromise was the second event, not the first. How does this change the response?', 'What was missed before today?'] },
          { timing: 'T+3hr 30min', text: 'A regulator (FINRA — the org has a financial services subsidiary) is asking for a preliminary report within 24 hours.', decision_points: ['Regulatory clock. Who handles?', 'How does the team produce a regulator-grade report 4 hours into an active incident?'] },
          { timing: 'T+5hr', text: 'A customer\'s CISO calls. They saw their data on a paste site. They want to know what happened, when, and what the org is doing.', decision_points: ['Disclosure timing: regulator first? Customer first? Both? In what order?', 'What is the contractual obligation to that specific customer?'] },
          { timing: 'T+8hr', text: 'Wellbeing alert: the dev who committed the credentials has not eaten in 9 hours, has been on the bridge the whole time, and visibly looks unwell. He keeps apologizing.', decision_points: ['How does the team handle this in the moment?', 'What does psychological safety look like during an incident this severe?', 'Who makes him take a break?'] },
        ],
        discussion_questions: [
          'How did the cross-account trust chain end up letting a dev credential reach production? Where is the architectural failure?',
          'What is the org\'s posture on "blast radius" for credentials? Should every credential have a maximum scope, monitored?',
          'How does the team produce a regulator-quality preliminary report on a 24-hour clock?',
          'What is the disclosure sequencing? What goes wrong if you order it incorrectly?',
          'How does the team support the developer who made the mistake — without being so soft it papers over a real process gap?',
          'What does the AAR say about the missed earlier compromise? Detection? Hunt? Audit?',
          'How does the org reckon with the operational impact of the org-wide credential rotation?',
          'What does post-incident architecture review look like? What gets prioritized?',
          'How does the team decompress after an incident this severe and this exposing?',
        ],
        references: [
          'AWS Security Best Practices, AWS Well-Architected Framework — Security Pillar',
          'NIST SP 800-61r2, NIST SP 800-204',
          'MITRE ATT&CK T1078.004, T1530, T1098 (Account Manipulation), T1136 (Create Account)',
        ],
      },
    },
  },
];

function getScenarioMeta() {
  return SCENARIOS.filter(s => !s.deprecated).map(s => ({
    id: s.id,
    title: s.title,
    category: s.category,
    description: s.description,
    difficulties: Object.keys(s.difficulties),
  }));
}

function getScenario(id) {
  return SCENARIOS.find(s => s.id === id) || null;
}

function getScenarioDifficulty(id, difficulty) {
  const scenario = getScenario(id);
  if (!scenario) return null;
  if (!scenario.difficulties[difficulty]) return null;
  return {
    scenario: {
      id: scenario.id,
      title: scenario.title,
      category: scenario.category,
      description: scenario.description,
      actors: scenario.actors,
      assumptions: scenario.assumptions,
    },
    difficulty,
    ...scenario.difficulties[difficulty],
  };
}

function getValidDifficulties() {
  return ['easy', 'intermediate', 'hard'];
}

module.exports = {
  getScenarioMeta,
  getScenario,
  getScenarioDifficulty,
  getValidDifficulties,
};
