'use strict';

// FireAlive MC -- which FEATURE-GUIDE section documents which tab.
//
// WHY THIS FILE EXISTS AT ALL. Before H1 the Management Console's Help tab held
// 45 hand-written one-line descriptions against 95 nav tabs -- 50 tabs had no
// help of any kind, and only 33 of the 45 still matched a section name in the
// guide. The Analyst Client's Help panel rendered ZERO entries, and the Global
// Dashboard's covered 6 of 35 tabs. Three apps drifted independently for one
// reason: nothing failed when a tab shipped without help.
//
// So the fix is not a fresh set of hand-written descriptions, which would drift
// again. It is a MAPPING to a document that is already maintained at the end of
// every build phase, plus a gate that fails when a tab maps to nothing.
//
// WHY MOST TABS ARE NOT LISTED HERE. 57 of 76 tabs have a nav label that matches
// a `###` heading in FEATURE-GUIDE.md exactly, and those resolve by name with no
// entry in this file. Listing them would create a second place to update when a
// label changes, which is the failure this phase is undoing.
//
// WHY THE REST ARE DECLARED RATHER THAN FUZZY-MATCHED. Token-overlap scoring
// produces plausible answers, and plausible is the problem: `peersupport` scores
// equally against "Peer Skill-Share Configuration" and "Peer Conduct", and
// `helper_pay` scores HIGHEST against "Helper Pay (AC-side)" -- which is the
// ANALYST's own view of their points, not the lead's approval queue. A matcher
// would have silently shown a Management Console operator the wrong document.
// Every alias below was resolved by reading the tab and the section, and the
// reasoning is kept beside it.
//
// A DECLARED MAP ALSO FAILS LOUDLY. Rename a guide section and the gate breaks
// the build; a fuzzy matcher would quietly re-point at the next best score.

/**
 * tab id -> exact `###` heading text in FEATURE-GUIDE.md.
 *
 * Only tabs whose nav label does NOT match a heading exactly.
 */
const TAB_SECTION = {
  // The section heading names this tab id explicitly. There is a second
  // "IR Simulator" section documenting the AI/ML training feature; this tab is
  // the lead-side one.
  ooda_mgmt: 'IR Simulator (lead-side, ooda_mgmt)',

  // The MC tab is "Helper Pay Management -- approve redemption requests", i.e.
  // the lead's queue. "Helper Pay (AC-side)" is the analyst's own view of their
  // points and is the WRONG document for this tab, despite scoring highest on
  // name similarity.
  helper_pay: 'Team Helper Scores (operational view)',

  // Two runbook-ish sections exist. This tab is the Operations-group generator;
  // the Reports & Compliance section covers SOAR playbooks alongside runbooks
  // and belongs to the `playbooks` tab below.
  runbook: 'Runbook Generator',
  playbooks: 'Playbooks (SOAR Playbook / Runbook Generator)',

  // Straightforward renames: the nav shortened the label, the guide did not.
  retro: 'CISM Retro (Incident Retrospectives)',
  peersupport: 'Peer Skill-Share Configuration',
  siem: 'SIEM Integration',
  edr: 'EDR File Inspection',
  threat_hunt: 'Threat Hunting Integrations',
  kms: 'KMS (Enterprise Key Management)',
  backup: 'Storage Destinations & Routing',
  geo_fence: 'Data Sovereignty / Geo-Fencing',
  risk_register: 'Risk Register Asset Generator',
  risk_report: 'Human Impact Risk Report',
  data_subject: 'Data-Subject Rights',
  cloud_vuln: 'Cloud Vulnerability Scan',

  // The Help tab itself. It is reached from a button rather than the nav array,
  // so check-help-coverage never sees it -- without this entry, opening Help
  // while already on Help would render "no section mapped".
  help_mc: 'Help (MC)',

  // Sections written in H1 because the features shipped without one. Recorded
  // here rather than silently added, so it is visible that the GUIDE drifted
  // too and not only the Help tab.
  malware_scanners: 'Malware Scanners',
  mfa: 'MFA & Step-Up Authentication',
  forensic_exports: 'Forensic Exports',
};

// Headings that no MC tab may resolve to, with the reason. A tab landing here is
// a mapping bug that would render text about a different product surface.
const NOT_FOR_MC = {
  'IAM & Access / MFA / Posture / WiFi / Compromise Scan / Vulnerability Scan / Regression Test / Cloud & IaC / SDN-SASE / Backup / Data Sovereignty / Recertification / Troubleshooter / App Updates':
    'GD-scoped placeholder: one heading covering 14 Global Dashboard tabs, whose whole body is "Same purposes as MC equivalents but scoped to the GD server". H3 owns replacing it.',
  'Helper Pay (AC-side)':
    "The analyst's own view of their points. The lead's approval queue is Team Helper Scores (operational view).",
};

/**
 * Resolve a tab to its guide heading.
 *
 * @param {string} tabId
 * @param {string} navLabel
 * @returns {string} the `###` heading text to look up
 */
function sectionForTab(tabId, navLabel) {
  if (Object.prototype.hasOwnProperty.call(TAB_SECTION, tabId)) return TAB_SECTION[tabId];
  return navLabel;
}

module.exports = {
  TAB_SECTION,
  NOT_FOR_MC,
  sectionForTab,
};
