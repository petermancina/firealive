// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Recovery Runbook Scenario Library
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Curated FireAlive-specific failure and compromise scenarios. Each scenario
// produces two document artifacts on demand:
//
//   - quickRef: a single-page printable card with trigger conditions, first
//     3-5 immediate actions, and escalation guidance. Designed to live at a
//     desk or in a binder for fast reference during an incident.
//
//   - fullRunbook: a multi-page document with full procedure: identification,
//     containment, eradication, recovery, verification, post-incident review.
//     Includes FireAlive components involved and the tear-down + reinstall
//     workflow where applicable.
//
// Scenario IDs are stable. Once a scenario ships in production, its ID never
// changes — the audit log references generated runbooks by ID. To deprecate
// a scenario, set `deprecated: true`. Never remove an ID.
//
// To add a scenario: append a new entry. Verify the ID is unique. Verify
// quickRef.firstActions is at most 5 steps (page-fit constraint).
// ═══════════════════════════════════════════════════════════════════════════════

const SCENARIOS = [

  // ── IDENTITY & AUTHENTICATION ──────────────────────────────────────────────

  {
    id: 'jwt_token_theft',
    category: 'Identity & Authentication',
    title: 'Stolen JWT or Refresh Token (Lead Account Compromise)',
    summary: 'An attacker has obtained a valid JWT access token or refresh token belonging to a team lead account, allowing them to authenticate and perform lead-level actions.',
    indicators: [
      'Authentication events from unfamiliar IPs or geographies for a lead account',
      'Configuration changes the lead does not recognize',
      'API requests outside the lead\'s typical schedule (e.g. middle of night)',
      'New API keys, integration credentials, or routing rules created without authorization',
      'Audit log entries showing lead-role actions during periods the lead was offline',
    ],
    quickRef: {
      trigger: 'Lead-role activity detected from unexpected source, OR audit log shows lead actions during lead\'s offline hours, OR lead reports unauthorized changes to configuration.',
      firstActions: [
        'Force-revoke all active sessions for the affected lead via /api/auth/sessions endpoint or by restarting the server with REVOKE_ALL_SESSIONS=true.',
        'Rotate the JWT signing secret in the server configuration. This invalidates all outstanding tokens issued under the old secret.',
        'Re-issue the lead\'s client certificate (or re-enroll their passkey) and require MFA re-enrollment before next login.',
        'Review audit log for the past 72 hours filtered by user_id of affected lead. Identify which configuration changes, API key generations, or integration writes occurred during the suspected compromise window.',
        'Roll back any unauthorized changes using the Restore tab\'s Internal restore feature, picking a restore point from before the compromise window.',
      ],
      escalation: 'If the attacker created new API keys, made changes to integration credentials (SOAR, SIEM), or accessed Tier-1 aggregate burnout data, escalate to security operations and rotate all integration credentials. If pseudonym mapping was accessed, escalate to privacy/legal — analyst identities may have been deanonymized.',
    },
    fullRunbook: {
      identification: [
        'Pull auth_log entries for the affected lead account covering the suspected compromise window (typically last 72 hours, or whatever window the suspicion covers).',
        'Look for: logins from unfamiliar IPs, logins outside the lead\'s typical schedule, sessions that overlap when the lead was known to be offline, geo-IP mismatches against the lead\'s declared country (Data Sovereignty tab).',
        'Cross-reference with audit_log entries where user_id = lead\'s id. Look for actions the lead did not perform.',
        'Check api_keys table for keys created during the window — attackers commonly create persistence via long-lived API keys.',
        'Check integration_config table for credential changes — attackers may have rotated SOAR/SIEM credentials to maintain persistence even after the lead\'s session is killed.',
      ],
      containment: [
        'Force-revoke all active sessions for the affected lead. Either: (1) call /api/auth/sessions DELETE endpoint as admin; (2) flush the sessions table directly with `DELETE FROM sessions WHERE user_id = ?`; or (3) restart the server with environment variable REVOKE_ALL_SESSIONS=true.',
        'Rotate the JWT signing secret. Generate a new secret with `openssl rand -hex 32`, write it to the server environment, restart the server. This invalidates ALL outstanding JWTs across the platform — every user must re-authenticate. Coordinate with team to minimize disruption.',
        'Disable the affected lead\'s account temporarily via Offboarding tab → "Mark Inactive Pending Investigation". The account is preserved (for audit log continuity) but cannot authenticate.',
        'If integrations may have been tampered with: temporarily disable burnout-aware routing (Routing & SOAR tab) so any malicious routing rules don\'t affect ticket assignment during the response.',
      ],
      eradication: [
        'Revoke any API keys created during the compromise window. Audit existing API keys for unfamiliar names, expirations far in the future, or scopes outside the lead\'s normal needs.',
        'Reset all integration credentials that the lead had access to: SOAR API key, ticketing read credential, SIEM CEF stream credential, IAM service account if applicable, KMS access tokens. Each integration\'s credential goes through the integration tab\'s rotation flow.',
        'Review and revert any unauthorized configuration changes. Common targets: routing thresholds (could be set to disable burnout protection), feature toggles (could be disabled to remove safety controls), pseudonym rotation policy (could expose analyst identities).',
        'Examine pseudonym mapping access: if the encrypted UUID-pseudonym-realname file was downloaded during the window, treat as a privacy breach. Notify privacy officer and follow org\'s breach disclosure policy.',
      ],
      recovery: [
        'Re-issue the lead\'s client certificate (or re-enroll their passkey) and require MFA re-enrollment. The lead enrolls a new FIDO2 hardware passkey on first login.',
        'Re-enable the lead\'s account.',
        'Restore any reverted configuration. If unauthorized changes were rolled back via Restore tab, verify the restored configuration matches what was expected before the compromise.',
        'Re-create any legitimate API keys that were revoked during eradication. New keys, fresh expirations, audit-logged.',
        'Re-enable burnout-aware routing if it was disabled during containment.',
      ],
      verification: [
        'Run a Compromise Scan against the lead\'s MC client (Compromise Scan tab → single client). Check binary integrity, configuration drift, audit chain continuity.',
        'Verify the lead\'s next login completes the full IAM + MFA flow with the new credentials.',
        'Run a Regression Test (Regression Test tab) to confirm all integrations and controls still function after the credential rotations.',
        'Monitor auth_log and audit_log for the next 7 days for any signs of continued attacker access.',
      ],
      postIncident: [
        'Document the incident in the team\'s incident-tracking system. Include: how the JWT was obtained (phishing, malware on the lead\'s host, network interception, leaked from another system), the duration of compromise, what data or actions the attacker accessed.',
        'Conduct a CISM Retro (Analysts & Wellbeing → CISM Retro) for the lead and any analysts whose pseudonyms or signals may have been exposed during the compromise. Stress response to compromise events is real and supportive recovery is part of the response.',
        'Review the Auth Logs configuration: was the brute-force threshold or anomaly detection sensitive enough to catch this? Adjust if needed.',
        'Review the Geo-Fencing configuration: was the attacker\'s source location flagged? If not, was geo-fencing enabled for this lead?',
        'Update the org\'s threat model to include this attack path in future tabletop exercises.',
      ],
      componentsInvolved: ['MC', 'Server', 'Auth middleware', 'JWT signing service', 'Sessions table', 'Audit log', 'Integration credentials', 'API keys'],
      relatedScenarios: ['mfa_bypass_attempt', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'mfa_bypass_attempt',
    category: 'Identity & Authentication',
    title: 'MFA Bypass Attempt or Passkey / Client-Certificate Compromise',
    summary: 'An attacker attempts to authenticate without a valid hardware-passkey assertion, replays a captured WebAuthn assertion, presents a stolen client certificate, or enrolls an unexpected authenticator to bypass the phishing-resistant login.',
    indicators: [
      'Authentication completion events without a preceding WebAuthn assertion (mfa_challenge_issued / mfa_challenge_completed) in auth_log',
      'A WebAuthn assertion whose signature counter (sign_count) is equal to or lower than a previously recorded value for the same credential (possible cloned authenticator or replay)',
      'A passkey assertion or enrollment from an unexpected authenticator model (an AAGUID not previously seen for the account, or outside the attestation allow-list)',
      'A client-certificate serial reused from a new source IP, or presented after the certificate should have been retired',
      'WebAuthn challenges completing from unexpected device fingerprints or source IPs',
    ],
    quickRef: {
      trigger: 'A session recorded without a corresponding hardware-passkey assertion, OR a user reports unauthorized access despite login being a hardware passkey.',
      firstActions: [
        'Revoke all sessions for the affected account.',
        'Revoke the affected credential: delete the suspect row from webauthn_credentials, or revoke the client certificate by adding its serial to the CRL. Require re-enrollment of a fresh hardware key before the account can log in.',
        'Pull auth_log entries for the account (mfa_challenge_issued, mfa_challenge_completed, session_created) and confirm every session followed a completed assertion.',
        'Check the sign_count history for the credential: a counter that did not advance, or went backward, indicates a replayed or cloned assertion.',
        'Review recent enrollments for the account: an unexpected AAGUID, or a passkey registered from an unfamiliar source, is itself the compromise.',
      ],
      escalation: 'If multiple accounts show assertions without challenges, unexpected AAGUIDs, or reused certificate serials, assume the authenticator-attestation policy, the client-certificate CA, or the WebAuthn verification path is compromised. Engage AppSec.',
    },
    fullRunbook: {
      identification: [
        'Filter auth_log for the affected account. A normal login completes the primary factor (client certificate or passkey), then mfa_challenge_issued, then mfa_challenge_completed, then session_created.',
        'Look for sessions where the assertion events are missing or arrive after session_created, which indicates the assertion was bypassed in the auth flow.',
        'For each assertion, compare the reported signature counter (sign_count) against the stored value in webauthn_credentials. An equal or lower counter is the WebAuthn signal for a cloned authenticator or a replayed assertion.',
        'Compare the authenticator AAGUID and the client-certificate serial against what the account used before. A new AAGUID, or a certificate serial reused from a new source, suggests credential theft or an unauthorized enrollment.',
      ],
      containment: [
        'Revoke all active sessions for the affected account.',
        'Disable the account temporarily via Offboarding, then Mark Inactive Pending Investigation.',
        'Revoke the compromised credential: delete the suspect webauthn_credentials row and add any stolen client-certificate serial to the CRL. Force re-enrollment of a fresh hardware key on next login.',
        'If the pattern suggests a flaw in the WebAuthn verification path or an attestation-policy gap rather than theft of one credential, tighten the attestation allow-list to accept only the bundled vendor roots while the path is reviewed.',
      ],
      eradication: [
        'Confirm the suspect passkey row and any stolen client certificates are revoked and can no longer be used. Re-enroll the account with a fresh hardware security key via the MFA tab.',
        'Audit the authenticator that was compromised: a stolen or cloned hardware key must be physically retired; a mis-issued client certificate points at a CA-process gap to close.',
        'Review the enrollment and attestation trail: how a new passkey is enrolled, what attestation is required, and which vendor roots are trusted. Tighten if an unauthorized enrollment succeeded.',
      ],
      recovery: [
        'The account completes a fresh hardware-passkey enrollment; the new credential is a user-verified, attestation-checked hardware key.',
        'Re-enable the account.',
        'Issue grace logins per the MFA tab configuration so the user can complete the enrollment workflow.',
      ],
      verification: [
        'Verify the next login follows the full sequence: primary factor (client certificate or passkey), then mfa_challenge_issued, then mfa_challenge_completed, then session_created, with a monotonically increasing sign_count.',
        'Monitor auth_log for the account for 7 days.',
        'Run a Compliance Scan to verify the MFA controls still meet the framework requirements.',
      ],
      postIncident: [
        'Document the bypass mechanism. If the WebAuthn verification path had a flaw, file a security ticket and patch promptly.',
        'Confirm the attestation allow-list and the client-certificate CA policy are as intended; tighten if an unexpected authenticator or certificate was accepted.',
        'Consider a SOAR rule that alerts whenever a session is created without a completed WebAuthn assertion in the previous 60 seconds, or when a sign_count fails to advance.',
      ],
      componentsInvolved: ['MFA tab', 'Auth middleware', 'auth_log', 'webauthn_credentials', 'client-certificate CA'],
      relatedScenarios: ['jwt_token_theft'],
    },
  },

  // ── INTER-COMPONENT COMMUNICATION ──────────────────────────────────────────

  {
    id: 'mc_server_channel_compromise',
    category: 'Inter-Component Communication',
    title: 'MC ↔ Server Channel Compromise',
    summary: 'An adversary intercepts, modifies, or injects traffic between the Management Console and the FireAlive server. Could alter ticket assignments, configuration writes, or audit log entries in transit.',
    indicators: [
      'TLS errors in MC logs',
      'Configuration changes appearing in audit log without corresponding MC user actions',
      'Audit log gaps coinciding with reported MC activity',
      'Network monitoring flags unusual traffic patterns between MC and server hosts',
      'MC reports actions completed that the server has no record of (or vice versa)',
    ],
    quickRef: {
      trigger: 'TLS handshake errors, certificate mismatches, audit log gaps coinciding with reported MC activity, or network IDS/IPS alerts on MC-server traffic.',
      firstActions: [
        'Disconnect the affected MC client from the network immediately.',
        'On the server side, revoke the MC\'s session and rotate the MC\'s mTLS certificate (if mTLS is configured) or JWT (if JWT is the auth method).',
        'Capture network traffic logs for forensic analysis. Network-layer interception evidence is often only in the netflow/packet capture from the surrounding network infrastructure.',
        'Run Compromise Scan against the affected MC and the server itself.',
        'Verify TLS certificate pinning is configured (Posture Assessment tab) — if not, this is the vulnerability that allowed interception. Enable.',
      ],
      escalation: 'If the channel was compromised long enough that configuration changes or routing rules may have been altered, escalate to a full incident response: assume routing decisions during the window are untrusted, audit all configuration changes for the time period.',
    },
    fullRunbook: {
      identification: [
        'Examine MC client logs for TLS errors, certificate validation failures, or unexpected reconnections.',
        'Compare audit_log entries for the time window with MC user activity records. Mismatches (audit shows actions the MC user didn\'t perform, or MC user performed actions not in audit) indicate channel tampering.',
        'Pull network monitoring data for the MC-server traffic. Look for: unusual TLS versions, unexpected source IPs in the conversation, traffic volume anomalies.',
        'Verify the server\'s TLS certificate hash against the expected hash on the MC side. If they don\'t match, an attacker is likely terminating TLS on a proxy.',
      ],
      containment: [
        'Disconnect the affected MC client from the network. The MC machine may be compromised at the OS level, or the network path between MC and server may be hostile.',
        'On the server side, revoke the affected MC\'s session and certificate.',
        'If mTLS is configured: rotate both the server\'s certificate and the MC\'s certificate. Re-enroll the MC with fresh PKI material.',
        'If JWT is the auth method: rotate the JWT signing secret server-side, invalidating all outstanding tokens. The MC must re-authenticate.',
      ],
      eradication: [
        'Reprovision the MC client: tear down the compromised install, install a fresh copy from a verified-clean source, restore configuration from the External Restore feature using a backup from before the suspected compromise.',
        'Audit all configuration changes during the suspected compromise window. Use the Restore tab to roll back any changes that didn\'t originate from authenticated MC user actions.',
        'Verify the network path between MC and server. If a network appliance was tampered with, that appliance needs remediation before the path is trustworthy again.',
      ],
      recovery: [
        'Re-enroll the cleaned MC client. The MC re-authenticates via IAM + MFA, receives fresh PKI material if mTLS is in use.',
        'Re-establish the configuration baseline by importing from External Restore using a known-clean backup.',
        'Verify all integrations still work post-reprovision (Integrations Health tab).',
      ],
      verification: [
        'Run a Compromise Scan against both the MC and the server.',
        'Run a Regression Test to verify all controls still function.',
        'Monitor audit_log against MC user activity for 7 days. They should match continuously.',
        'Verify TLS certificate pinning is enabled (Posture Assessment tab). If it was disabled when the compromise occurred, this was the root vulnerability.',
      ],
      postIncident: [
        'Document the compromise mechanism: was it network-layer (man-in-the-middle), endpoint-layer (compromised MC host), or PKI-layer (stolen certificate)?',
        'Address the root cause: enforce TLS certificate pinning, deploy mTLS if not already, review the network path security.',
        'Update the threat model. Add this attack vector to the next tabletop exercise.',
      ],
      componentsInvolved: ['MC', 'Server', 'TLS/mTLS', 'JWT or PKI', 'Audit log', 'Configuration storage'],
      relatedScenarios: ['ac_server_channel_compromise', 'binary_tampering', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'ac_server_channel_compromise',
    category: 'Inter-Component Communication',
    title: 'AC ↔ Server Channel Compromise',
    summary: 'An adversary intercepts or modifies traffic between an Analyst Client and the FireAlive server. Could alter signal readings (false flagging or signal hiding), block ticket assignment, replay session tokens, or eavesdrop on Tier-3 metrics.',
    indicators: [
      'Signal readings showing patterns inconsistent with the analyst\'s actual work',
      'Tickets reportedly assigned to an analyst that the AC never received',
      'TLS errors in AC client logs',
      'Replay-detection alerts (anti-replay middleware tripping)',
      'Network traffic anomalies on AC-server path',
    ],
    quickRef: {
      trigger: 'Signal readings inconsistent with observed analyst activity, OR ticket-assignment mismatches between server records and AC records, OR replay-detection alerts.',
      firstActions: [
        'Disconnect the affected AC client from the network.',
        'On the server, revoke the AC\'s session and rotate session/PKI material.',
        'Check whether mTLS is enabled for AC-server traffic — if not, enable it now to prevent immediate re-compromise.',
        'Capture network logs for the AC-server path for forensics.',
        'Run Compromise Scan against the AC.',
      ],
      escalation: 'If multiple ACs show channel-tampering signs simultaneously, assume the network infrastructure between analysts and the server is compromised. Treat as broader incident.',
    },
    fullRunbook: {
      identification: [
        'Pull signal_readings for the affected analyst over the suspected window. Compare with the analyst\'s own report of activity. Substantial mismatches suggest signal injection or filtering.',
        'Cross-reference ticket_assignments table with the analyst\'s recollection of received tickets. Mismatches indicate channel tampering.',
        'Check the auth-hardening middleware\'s anti-replay alerts.',
        'Examine TLS connection patterns from the AC. Look for unusual reconnection rates, certificate validation issues, or timing anomalies.',
      ],
      containment: [
        'Disconnect the affected AC client from the network.',
        'Revoke the AC\'s session and rotate PKI/JWT material on the server side.',
        'If mTLS is not enabled for AC-server traffic, enable it. This is the strongest mitigation against in-transit interception.',
        'If signal readings were manipulated, mark the affected window\'s signals as untrusted in the Burnout Engine config so they don\'t poison the analyst\'s baseline.',
      ],
      eradication: [
        'Reprovision the affected AC: tear down, install fresh copy, restore configuration via External Restore.',
        'Re-establish the analyst\'s burnout baseline: discard the tampered window\'s signal data, run a fresh baseline calibration period.',
        'Audit the analyst\'s recent ticket assignments — if any were missing or misrouted, reconcile with the SOAR system\'s record.',
      ],
      recovery: [
        'Re-enroll the cleaned AC. Analyst authenticates via IAM + MFA.',
        'Baseline re-establishment begins on-device over the fixed ~90-day establishment window; until it completes, the analyst\'s signals read as \'establishing\' and are not scored against a personal baseline.',
        'Resume normal operations.',
      ],
      verification: [
        'Run Compromise Scan on the AC.',
        'Monitor signal_readings for the analyst against their actual reported activity for 7 days.',
        'Verify TLS pinning and mTLS are enforced (Posture Assessment, IAM tab).',
      ],
      postIncident: [
        'Document the attack vector and mechanism.',
        'If multiple ACs are at risk (network-path compromise rather than single-AC compromise), reprovision all ACs on the affected network segment.',
        'Update threat model. Channel tampering of AC-server traffic is now a known attack pattern.',
      ],
      componentsInvolved: ['AC', 'Server', 'TLS/mTLS', 'Anti-replay middleware', 'signal_readings', 'ticket_assignments'],
      relatedScenarios: ['mc_server_channel_compromise', 'false_signal_injection', 'binary_tampering'],
    },
  },

  {
    id: 'mc_gd_pipeline_tampering',
    category: 'Inter-Component Communication',
    title: 'MC → GD Push Pipeline Tampering',
    summary: 'An adversary tampers with aggregate data being pushed from a regional Management Console to the Global Dashboard. Could present false regional health to the CISO, hide actual problems, or fabricate problems that don\'t exist.',
    indicators: [
      'GD shows regional health metrics that don\'t match what the regional MC shows',
      'GD-side audit log shows ingest events the MC has no record of sending',
      'TLS errors on the MC→GD push path',
      'GD recipients report receiving aggregate data that doesn\'t match expectations',
    ],
    quickRef: {
      trigger: 'Mismatch between regional MC metrics and what the GD displays for that region.',
      firstActions: [
        'Pause the MC→GD push pipeline (Global Dashboard tab → Pause Push).',
        'Compare specific metric values between MC and GD. Identify which metrics are diverging.',
        'Verify the GD ingest endpoint and RO API key on the MC side match the values configured on the GD side.',
        'Rotate the RO API key the MC uses to push to GD.',
        'Audit the GD\'s recently-ingested data for tampering signs.',
      ],
      escalation: 'If the GD itself is compromised (not just the channel), follow the broader GD compromise scenario. If multiple regional MCs report similar tampering, suspect adversary access to the GD ingest infrastructure.',
    },
    fullRunbook: {
      identification: [
        'Pull metrics from the regional MC for a specific time window.',
        'Pull the GD\'s ingest record for the same window for the same region.',
        'Compare value-by-value. Mismatches that exceed normal aggregation rounding suggest tampering.',
        'Check audit logs on both sides for the push events. Each successful push should appear in both MC and GD audit logs with matching timestamps.',
      ],
      containment: [
        'Pause the MC→GD push pipeline.',
        'Rotate the RO API key. Generate a fresh key on the GD side, update the MC configuration.',
        'If the network path between MC and GD is unprotected (no TLS pinning, no mTLS), enable these mitigations.',
      ],
      eradication: [
        'On the GD side, identify and remove the tampered ingest data for the affected window.',
        'On the MC side, verify the data being sent matches what the regional MC actually computed (compare in-flight payloads with the source data via the audit log).',
        'If a man-in-the-middle proxy is suspected on the network path, work with network engineering to identify and remediate.',
      ],
      recovery: [
        'Resume the push pipeline with the fresh key.',
        'Re-push metrics for the affected window to overwrite the tampered data on GD.',
        'Verify GD-side data matches MC for several push cycles.',
      ],
      verification: [
        'Continuous comparison of MC vs GD metrics for 7 days.',
        'Verify TLS/mTLS is in effect on the push path.',
      ],
      postIncident: [
        'Document the tampering mechanism.',
        'Strengthen the push pipeline: TLS pinning, mTLS, signed payloads.',
        'Consider adding a payload-integrity check (HMAC over the pushed data) so tampering would be detected automatically by the GD on ingest.',
      ],
      componentsInvolved: ['MC', 'GD', 'GD Server', 'Push pipeline', 'RO API key', 'Audit log'],
      relatedScenarios: ['mc_server_channel_compromise', 'gd_compromise'],
    },
  },

  {
    id: 'websocket_hijack',
    category: 'Inter-Component Communication',
    title: 'WebSocket Connection Hijack',
    summary: 'The real-time WebSocket channel between AC/MC and the server is hijacked by an adversary. Could feed false signal updates, eavesdrop on real-time team aggregates, or inject fake notifications.',
    indicators: [
      'WebSocket reconnection events at unusual frequency in the websocket-server logs',
      'Real-time signal updates received that don\'t correspond to recent signal_readings entries',
      'Notifications appearing in the inbox without matching events in the audit log',
      'WebSocket frames from unexpected source IPs',
    ],
    quickRef: {
      trigger: 'Anomalous WebSocket reconnection patterns, real-time updates without corresponding event records, or network IDS/IPS alerts on WebSocket traffic.',
      firstActions: [
        'Identify the affected client(s) by inspecting websocket-server logs.',
        'Forcibly disconnect the suspect WebSocket session(s) via the websocket-server admin function.',
        'Revoke the affected client\'s JWT — this prevents reconnection.',
        'Rotate WebSocket authentication tokens for all clients (forces all to reconnect with fresh credentials).',
        'Capture network traffic for the WebSocket path for forensics.',
      ],
      escalation: 'If many WebSocket sessions show hijack patterns simultaneously, the WebSocket auth mechanism may be flawed. Engage AppSec.',
    },
    fullRunbook: {
      identification: [
        'Pull websocket-server logs for the affected time window. Look for reconnection events at high frequency, sessions originating from unexpected IPs, or sessions whose initial-auth challenge succeeded but session ID doesn\'t match an active user session.',
        'Compare real-time updates received by clients against the underlying source data (signal_readings, audit_log). Mismatches indicate injection.',
        'Check the heartbeat-check service\'s logs for clients that drop and reconnect repeatedly.',
      ],
      containment: [
        'Forcibly disconnect the suspect WebSocket sessions.',
        'Revoke the affected client\'s JWT to prevent reconnection.',
        'Rotate WebSocket authentication keys/tokens.',
        'Temporarily restrict WebSocket connections to known-good IP ranges if the org has such a list.',
      ],
      eradication: [
        'For affected clients, revoke their session, force re-authentication.',
        'Audit the websocket-server\'s authentication code path for vulnerabilities (insufficient token validation, missing origin checks, etc.).',
        'Verify the websocket-server is configured to require Origin header validation against known-good origins.',
      ],
      recovery: [
        'Affected clients re-authenticate, establish fresh WebSocket connections.',
        'Resume normal real-time updates.',
      ],
      verification: [
        'Monitor websocket-server logs for 7 days.',
        'Compare real-time updates against source data for sample sessions.',
      ],
      postIncident: [
        'Document the hijack mechanism and detection.',
        'Strengthen WebSocket security: Origin validation, mTLS, signed messages.',
        'Add SOAR alert on anomalous WebSocket reconnection patterns.',
      ],
      componentsInvolved: ['WebSocket server', 'AC', 'MC', 'JWT auth', 'signal_readings', 'Real-time updates'],
      relatedScenarios: ['mc_server_channel_compromise', 'ac_server_channel_compromise', 'jwt_token_theft'],
    },
  },


  // ── CRYPTOGRAPHY & KEYS ────────────────────────────────────────────────────

  {
    id: 'tier3_key_compromise',
    category: 'Cryptography & Keys',
    title: 'Tier-3 Encryption Key Compromise',
    summary: 'The encryption key protecting individual analyst burnout signals (Tier-3 data) is compromised. All historical Tier-3 data is potentially decryptable by the attacker. The platform\'s core privacy commitment to analysts is broken until rotation completes.',
    indicators: [
      'KMS audit log shows unauthorized access to the Tier-3 key',
      'Tier-3 key file (if not KMS-backed) is accessed by unauthorized process',
      'Plaintext Tier-3 data appears in network captures or attacker-controlled systems',
      'Penetration test or threat hunt identifies key exposure',
    ],
    quickRef: {
      trigger: 'KMS audit shows unauthorized Tier-3 key access, OR plaintext Tier-3 data observed where it should not exist, OR external indicator of key compromise (penetration test, threat hunt finding).',
      firstActions: [
        'Notify the privacy officer immediately. This is a privacy breach event and may trigger regulatory disclosure (GDPR Article 33 — 72-hour clock).',
        'Rotate the Tier-3 key in KMS (KMS tab → Rotate). This makes future Tier-3 data unreadable to the attacker. Past data remains at risk.',
        'Pause all FireAlive operations briefly while re-encryption runs. The platform re-encrypts existing Tier-3 data with the new key.',
        'Audit access logs for the compromised key in KMS. Identify how the attacker obtained access.',
        'If the attacker had access to encrypted Tier-3 data AND the old key, treat all Tier-3 data from key inception to rotation timestamp as exposed.',
      ],
      escalation: 'Privacy breach disclosure per the org\'s applicable framework (GDPR, HIPAA, etc.). Notify analysts that their Tier-3 data may have been exposed. Engage legal.',
    },
    fullRunbook: {
      identification: [
        'KMS audit log shows the compromise event (unauthorized key access, key export, suspicious operation pattern).',
        'Determine the time window: when did the attacker gain access? Until when? This determines what data is at risk.',
        'Identify what data was actually encrypted with the compromised key. The Tier-3 key encrypts: individual signal_readings, individual peer chat messages (NaCl box keypairs may also be affected), individual lighter-queue requests, analyst_consent_log entries.',
      ],
      containment: [
        'Rotate the Tier-3 key in KMS. Generate a new key version, mark the old one as compromised in the KMS audit log.',
        'FireAlive\'s re-encryption job runs: every existing Tier-3 ciphertext is decrypted with the old key and re-encrypted with the new key. This may take time depending on data volume.',
        'Pause new Tier-3 writes briefly during the re-encryption to prevent race conditions (signals being written under the old key while re-encryption is in progress).',
        'On completion, the old key is destroyed in KMS.',
      ],
      eradication: [
        'Determine the root cause: how did the attacker gain access to KMS? Was a KMS access policy too permissive? Did a service account get compromised?',
        'Tighten KMS access policies. Apply least-privilege: only the FireAlive server should have decrypt rights on the Tier-3 key, no human users.',
        'If the org\'s KMS is also used for other systems, audit those for the same access pattern that allowed FireAlive\'s key compromise.',
        'Verify the FireAlive server\'s KMS access credentials are securely stored (not in source control, not in shared configuration files).',
      ],
      recovery: [
        'Resume Tier-3 writes with the new key.',
        'Verify analysts can still view their own signals (the platform decrypts client-side after fetching). If decryption fails for any analyst, troubleshoot — re-encryption may have missed some records.',
        'Resume normal FireAlive operations.',
      ],
      verification: [
        'Verify KMS audit shows only authorized access to the new key.',
        'Run a Compromise Scan on the FireAlive server.',
        'Run a Regression Test to confirm encryption round-trips work end-to-end.',
        'Run a Compliance Scan to confirm data-protection controls are in compliance.',
      ],
      postIncident: [
        'Privacy breach disclosure: notify affected analysts that their Tier-3 data MAY have been exposed during the compromise window. Provide guidance on what was at risk and what FireAlive\'s response was.',
        'Disclose to regulators per applicable framework (GDPR Article 33, HIPAA Breach Notification Rule, state-level laws).',
        'Conduct a CISM Retro for affected analysts. Privacy violations are stressors — supportive recovery is part of the response.',
        'Tabletop the scenario in the next quarterly TTX.',
        'Review the Knowledge Base for relevant research on privacy breach impact and integrate findings into the org\'s threat model.',
      ],
      componentsInvolved: ['KMS', 'Tier-3 encryption', 'signal_readings', 'analyst_consent_log', 'lighter_queue_requests', 'Re-encryption job'],
      relatedScenarios: ['tier1_key_compromise', 'kms_compromise_unavailability', 'pseudonym_mapping_leak', 'tier3_data_unauthorized_access'],
    },
  },

  {
    id: 'tier1_key_compromise',
    category: 'Cryptography & Keys',
    title: 'Tier-1 Encryption Key Compromise',
    summary: 'The encryption key protecting team-aggregate burnout data (Tier-1 data) is compromised. Less catastrophic than Tier-3 (Tier-1 is aggregate, not individual), but still leaks the org\'s SOC operational state.',
    indicators: [
      'KMS audit shows unauthorized access to the Tier-1 key',
      'Plaintext team aggregate data observed in unexpected places',
      'Indicators from threat hunting or penetration testing',
    ],
    quickRef: {
      trigger: 'KMS audit shows unauthorized Tier-1 key access, OR external indicator that the key was exposed.',
      firstActions: [
        'Rotate the Tier-1 key in KMS.',
        'Re-encryption job runs against existing Tier-1 data.',
        'Audit KMS access logs for the compromised key.',
        'Determine what aggregate data the attacker may have decrypted: team_health scores, average utilization metrics, capacity overload counts, etc.',
        'Notify leadership that operational state of the SOC may have been observed by the attacker (useful intel for further attacks against the org).',
      ],
      escalation: 'Less severe than Tier-3 in privacy terms, but the attacker now has insight into the org\'s SOC operational tempo and stress patterns. Treat as operational-intel exposure.',
    },
    fullRunbook: {
      identification: [
        'KMS audit log shows the unauthorized access event for the Tier-1 key.',
        'Determine what data was protected by the compromised key: team_health aggregates, utilization metrics, capacity counts, integration health summaries.',
      ],
      containment: [
        'Rotate the Tier-1 key in KMS.',
        'Re-encryption job runs.',
        'Tighten KMS access policies for Tier-1 keys.',
      ],
      eradication: [
        'Identify how the attacker obtained KMS access (same root-cause analysis as Tier-3 compromise scenario).',
        'Apply least-privilege to KMS. Audit related service accounts.',
      ],
      recovery: [
        'Resume operations with new key.',
        'Verify Tier-1 data is still readable for legitimate users (lead\'s MC).',
      ],
      verification: [
        'Run Compromise Scan, Regression Test, Compliance Scan.',
        'Verify KMS audit shows only authorized access going forward.',
      ],
      postIncident: [
        'Document the compromise.',
        'Notify leadership about operational-intel exposure.',
        'Consider whether the org needs to assume hostile knowledge of SOC operational patterns when planning future operations.',
      ],
      componentsInvolved: ['KMS', 'Tier-1 encryption', 'team_health aggregates', 'utilization metrics'],
      relatedScenarios: ['tier3_key_compromise', 'kms_compromise_unavailability'],
    },
  },

  {
    id: 'peer_chat_e2ee_key_compromise',
    category: 'Cryptography & Keys',
    title: 'Peer Chat E2EE Key Compromise (NaCl Box)',
    summary: 'One side of an E2EE peer chat session has had their NaCl box keypair stolen. Past chat content from sessions involving that keypair can be decrypted by the attacker. Unlike server-side encryption, this is per-user keypair compromise.',
    indicators: [
      'Analyst reports their workstation was compromised and sensitive files were exfiltrated',
      'Peer chat content appears in unexpected locations (attacker-controlled forums, leak sites)',
      'AC binary integrity check fails for the affected analyst',
      'Compromise scan on the AC reveals key files were accessed',
    ],
    quickRef: {
      trigger: 'AC compromise confirmed for an analyst whose private key may have been exposed, OR peer chat content surfaces in unauthorized locations.',
      firstActions: [
        'Mark the affected analyst\'s NaCl box keypair as compromised in the peer chat key store.',
        'Generate a fresh keypair for the analyst. Distribute the new public key.',
        'Review the analyst\'s peer chat session history. Sessions involving the old keypair are decryptable by the attacker.',
        'Identify which peers the analyst chatted with during the compromise window. Their messages to the affected analyst are now readable by the attacker.',
        'Reprovision the affected analyst\'s AC.',
      ],
      escalation: 'If the chat content includes any sensitive material (which it shouldn\'t, per the peer chat use policy that distinguishes from emotional support and private matters), assess for harm and notify involved parties.',
    },
    fullRunbook: {
      identification: [
        'Confirm key compromise: the AC binary was tampered with, OR a malware infection was confirmed on the analyst\'s workstation, OR key material was exfiltrated.',
        'Determine the time window: how long has the keypair been compromised? Sessions during this window are at risk.',
        'List peer sessions for the affected analyst during the window. Each session involves another analyst — those analysts\' messages to the affected analyst are decrypted with the affected analyst\'s private key (NaCl box). The attacker can read all of them.',
        'Note: messages FROM the affected analyst TO peers are decrypted with the peer\'s private key, so those are NOT exposed unless the peer\'s keypair is also compromised.',
      ],
      containment: [
        'Mark the keypair compromised in the platform. The peer chat infrastructure refuses to use it for new sessions.',
        'Generate a fresh keypair for the analyst on the new clean AC after reprovision.',
        'Distribute the new public key to all peers via the existing key-distribution mechanism.',
      ],
      eradication: [
        'Reprovision the affected analyst\'s AC: tear down, install fresh, restore configuration via External Restore.',
        'Investigate the root compromise of the workstation: was it malware? Phishing-delivered remote access? Address the root cause.',
        'Audit the analyst\'s other credentials: client certificate, MFA seeds, any cached tokens. Rotate everything.',
      ],
      recovery: [
        'Re-enroll the cleaned AC. Analyst authenticates fresh, generates new NaCl box keypair.',
        'Resume peer chat operations with the new keypair.',
      ],
      verification: [
        'Run Compromise Scan on the new AC.',
        'Monitor for further indicators of the original compromise persisting.',
      ],
      postIncident: [
        'Document the compromise.',
        'Notify peers whose messages were exposed. They have a right to know that their messages to the affected analyst were readable by an attacker.',
        'Consider whether peer chat content review reveals any sensitive disclosures the org needs to address.',
        'Conduct a CISM Retro for the affected analyst — being compromised is stressful.',
      ],
      componentsInvolved: ['Peer chat', 'NaCl box keypairs', 'AC binary integrity', 'peer_messages table'],
      relatedScenarios: ['binary_tampering', 'tier3_key_compromise'],
    },
  },

  {
    id: 'kms_compromise_unavailability',
    category: 'Cryptography & Keys',
    title: 'KMS Provider Compromise or Unavailability',
    summary: 'The org\'s enterprise KMS (AWS KMS, Azure Key Vault, HashiCorp Vault, Thales, Entrust, etc.) is breached, malfunctioning, or temporarily unreachable. FireAlive cannot perform encryption/decryption operations until KMS is restored or fallback is engaged.',
    indicators: [
      'FireAlive logs show KMS API errors (timeouts, auth failures, decrypt failures)',
      'KMS provider\'s status page reports outage',
      'KMS provider notifies of breach',
      'New encryption operations fail; existing data cannot be decrypted',
    ],
    quickRef: {
      trigger: 'KMS API errors in FireAlive logs at high rate, OR KMS provider outage notification, OR KMS provider breach disclosure.',
      firstActions: [
        'Confirm the issue with the KMS provider (status page, support ticket, or org\'s IT team).',
        'For unavailability (no breach): wait for restoration. FireAlive will queue encryption operations briefly. If unavailability is prolonged, consider fallback.',
        'For breach: rotate ALL FireAlive keys in KMS once KMS is operationally trustworthy again. Tier-3, Tier-1, peer chat infrastructure keys (separately from per-user NaCl), backup keys, audit signing key.',
        'Assess what data was encrypted with KMS-managed keys during the breach window — that data may have been decrypted by the attacker if they extracted both ciphertext and key material from KMS.',
        'If KMS is the sole barrier and other data egress paths exist, treat the worst case: assume all encrypted data accessible to KMS during the breach window is exposed.',
      ],
      escalation: 'KMS compromise affecting Tier-3 keys is a privacy breach event. Follow the Tier-3 Key Compromise scenario for that specific key. KMS compromise affecting backup keys impacts forensic and restore workflows.',
    },
    fullRunbook: {
      identification: [
        'Verify KMS issue type: outage (recover-when-back) vs breach (rotate-everything).',
        'Pull FireAlive logs showing KMS API call patterns. Distinguish auth errors (KMS rejected our credentials), timeout errors (KMS not responding), or operational errors (KMS responded with unexpected error).',
        'Coordinate with KMS provider for the actual incident scope.',
      ],
      containment: [
        'For unavailability: keep FireAlive running but pause operations that require KMS (new Tier-3 writes, backup encryption).',
        'For breach: restrict KMS access from FireAlive while the breach is being investigated by the KMS provider. Don\'t let new operations occur on potentially-poisoned keys.',
      ],
      eradication: [
        'For breach: once KMS is restored to a trustworthy state, rotate every key FireAlive uses in KMS.',
        'Tier-3 key rotation per the Tier-3 scenario.',
        'Tier-1 key rotation per the Tier-1 scenario.',
        'Backup encryption key rotation: re-encrypt existing backups with the new key, or mark old backups as needing decryption with old (now-rotated) key context.',
        'Audit signing key rotation: existing audit log entries are signed with old key — that\'s OK (verifiable), but new entries use new key.',
        'Update FireAlive\'s KMS access credentials. The credentials it uses to call KMS may also have been exposed.',
      ],
      recovery: [
        'Resume normal operations.',
        'Verify all encryption-dependent paths still work (signal_readings writes, backup creation, audit log entries).',
      ],
      verification: [
        'Run Compromise Scan, Regression Test, Compliance Scan.',
        'Verify KMS provider has cleared the incident on their end.',
        'Monitor KMS access logs for 14 days.',
      ],
      postIncident: [
        'Document. Coordinate disclosure if private data was exposed.',
        'Consider whether the org should diversify KMS providers (multi-vendor strategy) for critical platforms.',
        'Update the threat model: KMS provider compromise is a supply-chain risk.',
      ],
      componentsInvolved: ['KMS', 'Tier-3 encryption', 'Tier-1 encryption', 'Backup encryption', 'Audit signing'],
      relatedScenarios: ['tier3_key_compromise', 'tier1_key_compromise', 'audit_signing_key_compromise'],
    },
  },

  {
    id: 'audit_signing_key_compromise',
    category: 'Cryptography & Keys',
    title: 'Audit Log Signing Key Compromise',
    summary: 'The key used to sign audit log entries has been compromised. An attacker can forge audit log entries that appear legitimate, breaking the tamper-evident chain that compliance and forensics depend on.',
    indicators: [
      'KMS audit shows unauthorized access to the audit signing key',
      'Audit log entries with valid signatures but suspicious content (events that didn\'t actually happen)',
      'Hash chain verification passes but cross-correlation with other systems shows discrepancies',
      'External indicator from threat hunt or penetration test',
    ],
    quickRef: {
      trigger: 'KMS audit shows unauthorized audit-signing-key access, OR audit log entries are confirmed forged via cross-correlation.',
      firstActions: [
        'Rotate the audit signing key in KMS immediately.',
        'Mark the compromise time window in the audit log itself (with a special administrative entry signed by the new key).',
        'Identify the suspect audit log entries during the compromise window. Cross-correlate with other systems (SIEM, SOAR, HR ticketing) to identify discrepancies.',
        'Treat audit log entries during the compromise window as untrusted for forensic and compliance purposes. Note this in the org\'s incident response and audit documentation.',
        'Investigate root cause of KMS access (same as Tier-3 scenario).',
      ],
      escalation: 'If the audit log was being relied on for an active investigation or compliance audit, escalate to legal and compliance officers. They need to know that audit data from the window is untrusted.',
    },
    fullRunbook: {
      identification: [
        'Pull KMS audit log for the audit-signing key. Identify the unauthorized access window.',
        'Within FireAlive, query audit_log entries during the suspect window. Cross-correlate with: SIEM events for FireAlive activity, SOAR action logs, HR/IAM offboarding records.',
        'Discrepancies in cross-correlation (e.g. audit log shows a config change but no SIEM event for the corresponding API call, or HR shows analyst was on leave during a recorded log-in event) flag forged entries.',
      ],
      containment: [
        'Rotate the audit signing key in KMS.',
        'Add a special audit log entry (signed with the new key) marking the compromise window. This becomes the authoritative record of what data is untrusted.',
        'Tighten KMS access for the audit signing key. Audit logs are particularly sensitive; access should be tightly restricted.',
      ],
      eradication: [
        'Investigate KMS access. Apply least privilege.',
        'Verify the FireAlive server\'s KMS credentials are securely stored.',
        'Add SOAR alerting on any access to the audit signing key.',
      ],
      recovery: [
        'New audit log entries are now signed with the new key.',
        'Verify hash chain integrity from the rotation point forward.',
      ],
      verification: [
        'Audit log integrity check passes for new entries.',
        'Verify SIEM cross-correlation aligns with FireAlive audit log going forward.',
      ],
      postIncident: [
        'Document the compromise window and suspect log entries.',
        'Consult with compliance officer about implications for any active audits or investigations relying on audit log data.',
        'Update the threat model.',
      ],
      componentsInvolved: ['KMS', 'Audit log signing', 'audit_log table', 'Hash chain'],
      relatedScenarios: ['kms_compromise_unavailability', 'audit_log_chain_gap'],
    },
  },


  // ── STORAGE & DATA ─────────────────────────────────────────────────────────

  {
    id: 'database_corruption',
    category: 'Storage & Data',
    title: 'Database Corruption (Operational)',
    summary: 'The FireAlive database file has become corrupted due to disk failure, bad write, sigkill mid-transaction, or hardware fault. Data integrity is compromised; the database needs restoration from backup.',
    indicators: [
      'Server logs show SQLite errors (database disk image is malformed, file is encrypted or is not a database)',
      'Integrity check (PRAGMA integrity_check) returns errors',
      'Server crashes on startup with database errors',
      'Specific queries fail with corruption errors while others succeed',
      'Disk subsystem hardware errors in OS logs',
    ],
    quickRef: {
      trigger: 'Server logs show database corruption errors, OR PRAGMA integrity_check fails, OR server crashes on startup with DB errors.',
      firstActions: [
        'Stop the FireAlive server immediately to prevent further writes.',
        'Activate fail-open routing in the SOAR so tickets continue to flow without burnout-aware routing while FireAlive is offline.',
        'Run PRAGMA integrity_check on the database file. If it passes, the corruption is in indexes or specific records — recoverable. If it fails, the file is structurally damaged.',
        'Identify the most recent verified-clean backup (Backup tab).',
        'Restore from backup via Restore tab → Internal restore (or External if Internal backups are also affected).',
      ],
      escalation: 'If repeated corruption occurs after restore, the underlying storage is failing. Migrate FireAlive to new disk/host before another restore. If HA was in use, consider promoting the passive node and rebuilding the active.',
    },
    fullRunbook: {
      identification: [
        'Examine server logs for SQLite-specific errors. Common patterns: "database disk image is malformed", "file is encrypted or is not a database", "no such table" for tables that should exist.',
        'Run PRAGMA integrity_check;  on the database. Output should be "ok". Anything else indicates corruption.',
        'Check disk subsystem logs (dmesg, smartctl) for hardware errors. Disk failure is a common root cause.',
        'Determine the corruption scope: full file, specific tables, specific records.',
      ],
      containment: [
        'Stop the FireAlive server. Prevent further writes that could compound corruption.',
        'Snapshot the corrupted database file to forensic storage (in case it needs analysis later).',
        'Activate SOAR fail-open routing so the SOC continues operating while FireAlive is offline.',
        'Notify analysts via out-of-band channel that FireAlive is offline temporarily; their AC clients will reconnect automatically when service resumes.',
      ],
      eradication: [
        'For partial corruption (PRAGMA integrity_check shows specific issues): try SQLite recovery procedures: VACUUM INTO a new file, then verify integrity. If recovery succeeds, the new file is the production database.',
        'For full corruption: discard the corrupted file. Identify the most recent verified-clean backup.',
        'If the underlying disk is failing, migrate to new storage before restore. Don\'t restore to a failing disk.',
      ],
      recovery: [
        'Restore from the most recent verified-clean backup via Restore tab → Internal (or External).',
        'After restore, run PRAGMA integrity_check on the restored database. Confirm "ok" before resuming operations.',
        'Start the FireAlive server. Watch logs for any database errors during startup.',
        'Resume normal operations: deactivate SOAR fail-open routing, allow burnout-aware routing to resume.',
      ],
      verification: [
        'Run a Regression Test (Regression Test tab) to confirm DB-dependent features (auth, signal recording, etc.) work end-to-end.',
        'Verify analyst clients reconnect successfully (Integrations Health tab).',
        'Verify recent activity is captured correctly in the audit log going forward.',
        'Monitor for re-corruption for 7 days. If it recurs, the storage is failing.',
      ],
      postIncident: [
        'Document the corruption: file size, error patterns, root cause if determined.',
        'Calculate data loss: how recent was the last clean backup? What activity happened between backup and corruption that is now lost?',
        'If data loss is significant, communicate to the team: "FireAlive lost X hours of data due to storage failure on date Y. The team metrics from that window are unrecoverable."',
        'Review backup frequency. If data loss is more than the org tolerates, increase backup frequency in Backup Schedules tab.',
        'Consider HA + active/active deployment for orgs that cannot tolerate this kind of downtime.',
      ],
      componentsInvolved: ['SQLite database', 'Backup system', 'Restore feature', 'Storage subsystem', 'SOAR fail-open'],
      relatedScenarios: ['backup_tampering_corruption', 'server_crash_ha_degraded', 'audit_log_chain_gap'],
    },
  },

  {
    id: 'audit_log_chain_gap',
    category: 'Storage & Data',
    title: 'Audit Log Chain Gap Detected',
    summary: 'The audit log\'s SHA-256 hash chain shows missing entries — a gap where the cryptographic linkage between consecutive entries is broken. Indicates either tampering (entries deleted by an attacker) or a partition event (FireAlive was offline and lost entries).',
    indicators: [
      'Log Integrity tab shows status RED with chain gap detected',
      'Verifying audit log fails with chain inconsistency errors',
      'SOAR alerting fires on the FireAlive log-integrity health check',
      'Specific time window in the audit log shows no entries when activity is known to have occurred',
    ],
    quickRef: {
      trigger: 'Log Integrity status RED, OR SOAR alert on chain integrity, OR forensic review identifies missing entries.',
      firstActions: [
        'Open Log Integrity tab. Identify the specific gap range.',
        'Determine cause: was FireAlive offline during this window? Check server uptime records, system logs, OS journal. Offline period explains gap → partition, not tampering.',
        'If FireAlive was online: gap is suspicious. Treat as potential tampering. Engage forensics.',
        'If gap is partition (FireAlive was offline): document the gap, restore audit log continuity by adding a special "audit-resume" entry signed by the audit signing key.',
        'If gap is tampering: snapshot the audit log file for forensic analysis. Investigate who had write access during the gap window.',
      ],
      escalation: 'Tampering of the audit log compromises every compliance and forensic capability of the platform. Treat as P1 incident, engage security operations, audit signing key may also be at risk (see related scenario).',
    },
    fullRunbook: {
      identification: [
        'Pull the audit log entries surrounding the gap. Note the timestamps of the last entry before gap and first entry after gap.',
        'Compare the gap window against server uptime records. If the server was offline during this period, the gap is partition (operational, not security).',
        'If the server was online but no entries were recorded, this is anomalous. Possible causes: tampering (entries deleted), FireAlive process died and restarted without recording entries, audit middleware was disabled or misconfigured.',
        'Check SOAR alerting for events that should have been logged during the gap. If SOAR has corresponding events, the activity happened but FireAlive\'s audit log is missing them.',
      ],
      containment: [
        'For partition: low containment needed; the gap is honest operational data loss. Document and add audit-resume entry.',
        'For tampering: stop the FireAlive server. Snapshot the database file for forensics. The corruption may extend beyond the apparent gap.',
        'For tampering: rotate the audit signing key (per the audit_signing_key_compromise scenario). The attacker may have the key.',
      ],
      eradication: [
        'For partition: document the gap and proceed.',
        'For tampering: investigate root cause. Who had access? Was a container compromised? Was the database accessed directly bypassing the application layer? Address the root cause.',
        'Audit other tables for tampering. The attacker may have modified other data while they had access.',
      ],
      recovery: [
        'For partition: add an audit-resume entry. Resume normal operations.',
        'For tampering: restore from backup if other tables were tampered with. Document that the audit log has a known gap.',
      ],
      verification: [
        'Log Integrity status returns to GREEN after the audit-resume entry.',
        'Run hash chain verification end-to-end.',
        'Run Compliance Scan to verify audit-trail controls.',
      ],
      postIncident: [
        'Document the gap: window, root cause, response.',
        'For partition gaps: review whether the org\'s compliance framework requires action on operational gaps. Some frameworks tolerate documented gaps; others require detailed explanation.',
        'For tampering: full security incident response. Disclose to compliance officer.',
        'Strengthen audit log path: ensure the audit middleware is enforced on every API request, not just selectively.',
      ],
      componentsInvolved: ['Log Integrity tab', 'Audit middleware', 'audit_log table', 'Hash chain', 'Audit signing key'],
      relatedScenarios: ['audit_signing_key_compromise', 'database_corruption', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'backup_tampering_corruption',
    category: 'Storage & Data',
    title: 'Backup Tampering or Corruption',
    summary: 'A stored FireAlive backup file has been altered, corrupted, or destroyed. If the backup is needed for recovery, restoring from it would yield compromised state.',
    indicators: [
      'Backup integrity hash mismatch when verified',
      'Backup file size is unexpected',
      'Backup file timestamp doesn\'t match the recorded creation time',
      'Backup destination shows unauthorized access',
      'Restore from backup fails or produces unexpected state',
    ],
    quickRef: {
      trigger: 'Backup integrity verification fails, OR backup destination access logs show unauthorized access, OR restore from backup produces unexpected results.',
      firstActions: [
        'Mark the affected backup file as untrusted in the Backup tab.',
        'Identify the next-most-recent verified-clean backup.',
        'Investigate access to the backup destination: how did unauthorized access occur? Was the destination credentials compromised?',
        'Rotate the backup destination credentials (S3 keys, NAS credentials, SFTP keys, etc.).',
        'If the affected backup was about to be used for restore (e.g. responding to corruption), use the older verified-clean backup instead and document the data loss difference.',
      ],
      escalation: 'If multiple backups are affected, the org\'s entire backup infrastructure may be compromised. Pause backup operations while investigating.',
    },
    fullRunbook: {
      identification: [
        'Verify the backup integrity hash against the recorded hash in the backups table. Mismatch = tampered or corrupted.',
        'Check the backup destination\'s access logs (S3 access logs, NAS audit, SFTP server logs) for the suspect time window.',
        'Compare the backup file\'s size and timestamp against expected values. Unexpected values indicate manipulation.',
        'Test-restore the backup in a sandboxed environment to verify what state it produces.',
      ],
      containment: [
        'Mark the backup as untrusted. The platform will not offer it as a restore option.',
        'Identify and verify the next-most-recent clean backup. Verify its integrity hash. If clean, that\'s the rollback point.',
        'Rotate backup destination credentials. The credentials FireAlive uses to write backups may have been exposed.',
        'If backups are stored on shared infrastructure (S3, NAS), assume other backups in the same destination may also be at risk. Verify each.',
      ],
      eradication: [
        'Investigate the destination access. Was an S3 bucket policy too permissive? Did NAS credentials leak? Did SFTP keys get exposed?',
        'Apply least-privilege to backup destination: only the FireAlive server should have write access to the backup location.',
        'Add object-lock or immutability features (S3 Object Lock, write-once-read-many, append-only NAS) to backup destinations to prevent future tampering.',
      ],
      recovery: [
        'If recovery from backup was needed, use the verified-clean older backup and accept the data loss.',
        'Resume normal backup operations.',
      ],
      verification: [
        'Verify next backup completes successfully and integrity-hash-verifies.',
        'Run Compliance Scan to verify backup controls.',
        'Verify the backup destination\'s access logs going forward show only FireAlive\'s service-account access.',
      ],
      postIncident: [
        'Document the tampering or corruption mechanism.',
        'Consider geographic/provider diversity for backups: multi-region S3, separate provider for off-site backup.',
        'Tabletop the scenario in the next quarterly TTX.',
      ],
      componentsInvolved: ['Backup tab', 'Backup destinations (S3, NAS, SFTP, Azure)', 'Backup integrity hashes', 'backups table'],
      relatedScenarios: ['database_corruption', 'restore_compromise_recovery'],
    },
  },

  {
    id: 'tier3_data_unauthorized_access',
    category: 'Storage & Data',
    title: 'Tier-3 Data Unauthorized Access',
    summary: 'Tier-3 individual analyst burnout data has been accessed by someone bypassing the application layer — directly through the database file, hypervisor admin access, or attacker with disk access. They see encrypted blobs initially, but combined with Tier-3 key compromise, this becomes a full Tier-3 read.',
    indicators: [
      'Database file timestamps show access during periods FireAlive itself was not querying',
      'Disk-level snapshot or backup access logs show unauthorized reads',
      'Threat hunting identifies database files in attacker-controlled storage',
      'Insider-threat indicators: DBA, sysadmin, or hypervisor admin accessing FireAlive\'s data',
    ],
    quickRef: {
      trigger: 'Database file access logs show unauthorized reads, OR FireAlive\'s disk/snapshot is found in attacker hands, OR insider threat investigation reveals access.',
      firstActions: [
        'Determine whether the Tier-3 encryption key is also compromised. If yes, the attacker has plaintext Tier-3 data — escalate to Tier-3 Key Compromise scenario immediately.',
        'If only ciphertext was accessed (key remains protected), the attacker has encrypted blobs they can\'t decrypt. Still investigate to confirm key safety.',
        'Audit the database access: who has filesystem-level access? DBAs, sysadmins, hypervisor admins, backup systems, monitoring agents?',
        'Restrict filesystem access to FireAlive\'s database. Only the FireAlive server process should read/write the file.',
        'Verify the Tier-3 key has not been exposed alongside the data. Check KMS audit for the same actor.',
      ],
      escalation: 'If Tier-3 key + ciphertext are both confirmed exposed, follow Tier-3 Key Compromise scenario for full disclosure workflow.',
    },
    fullRunbook: {
      identification: [
        'Examine OS-level audit (auditd, Windows audit) for the FireAlive database file. Identify access events outside FireAlive\'s service account.',
        'Cross-correlate access events with KMS audit. If the same actor accessed both the database file and the Tier-3 key, full compromise is likely.',
        'Identify the actor: insider with privileged access, attacker with elevated host access, third-party tool with broader access than needed.',
      ],
      containment: [
        'Restrict filesystem access to the FireAlive database. Use OS-level ACLs to ensure only the FireAlive service account can read/write.',
        'If running in a virtualized environment, restrict hypervisor admin access to the FireAlive VM\'s storage. Hypervisor admins should not be able to snapshot or read the FireAlive disk without dual-approval.',
        'Encrypt the disk at rest if not already (LUKS, BitLocker, cloud-provider disk encryption).',
        'Verify backup destinations have similar access restrictions.',
      ],
      eradication: [
        'For insider threat: follow the org\'s insider threat response. The Pseudonyms tab\'s rotate function may need to be triggered to invalidate any pseudonym-name correlations the insider made.',
        'For external attacker with host access: full host compromise response. The host needs to be wiped and reprovisioned.',
        'Tighten privilege boundaries broadly. Apply least-privilege.',
      ],
      recovery: [
        'After the access path is closed, resume normal operations.',
        'If Tier-3 key was compromised, follow that scenario\'s recovery (re-encryption with new key).',
      ],
      verification: [
        'Audit logs show no unauthorized database file access for 7 days.',
        'Run Compromise Scan on the FireAlive host.',
        'Run Compliance Scan to verify data-protection controls.',
      ],
      postIncident: [
        'Document the access pattern.',
        'Privacy disclosure: even if only ciphertext was accessed, the org should consider whether to disclose to analysts that their (encrypted) data was accessed by an unauthorized party. Different jurisdictions have different requirements.',
        'Update the threat model: filesystem-level access bypasses the application layer.',
        'Consider deploying FireAlive in an enclave or with full-disk encryption with KMS-managed disk keys to prevent this attack vector.',
      ],
      componentsInvolved: ['Database file', 'OS-level access controls', 'KMS', 'Tier-3 encryption', 'Filesystem permissions'],
      relatedScenarios: ['tier3_key_compromise', 'pseudonym_mapping_leak'],
    },
  },

  {
    id: 'ir_policies_tampering',
    category: 'Storage & Data',
    title: 'IR Policies Content Tampering',
    summary: 'Uploaded organizational IR policies have been altered server-side, causing the IR Simulator to train analysts on incorrect procedures. Analysts learn wrong responses; in a real incident, they apply incorrect procedures.',
    indicators: [
      'ir_policies table content_hash mismatch with original upload hash',
      'Analyst feedback that simulator scenarios reflect incorrect procedures',
      'ir_policies last_modified timestamp doesn\'t match expected upload schedule',
      'Audit log shows unauthorized writes to ir_policies',
    ],
    quickRef: {
      trigger: 'Analyst feedback that simulator scenarios are wrong, OR ir_policies content_hash mismatch, OR audit log shows unauthorized writes.',
      firstActions: [
        'Pause the IR Simulator (Feature Toggles tab → ooda_simulator off).',
        'Compare ir_policies records\' content_hash with the original upload hash. Identify which policies have been altered.',
        'Review the audit log for ir_policies write events. Identify who/what made the changes during the suspect window.',
        'For each tampered policy, restore from the lead\'s original-source documents. Re-upload the correct versions.',
        'Re-generate scenarios from the restored policies. Discard previously-generated scenarios that derived from tampered policies.',
      ],
      escalation: 'If tampering occurred over a long window and many analysts trained on incorrect procedures, the team\'s IR readiness is degraded. Schedule retraining sessions and TTXs to re-establish correct procedures.',
    },
    fullRunbook: {
      identification: [
        'Compare ir_policies.content_hash for each row with the source-of-truth hash (computed from the original document the lead uploaded).',
        'Mismatches indicate tampering. Identify the rows.',
        'Pull audit log for ir_policies write events. Identify the actor and time of each unauthorized write.',
        'Identify which IR Simulator scenarios were generated from tampered policies. Those scenarios are corrupt.',
      ],
      containment: [
        'Pause the IR Simulator feature.',
        'Mark tampered ir_policies rows as untrusted.',
        'Mark scenarios generated from tampered policies as untrusted.',
      ],
      eradication: [
        'Restore correct ir_policies content from the original-source documents (the lead\'s authoritative copies).',
        'Investigate how the unauthorized writes occurred. Was a lead account compromised? Was the database written to bypassing the application layer?',
        'Address root cause (lead account compromise scenario, or database access scenario).',
      ],
      recovery: [
        'Re-generate IR Simulator scenarios from the restored ir_policies.',
        'Resume the IR Simulator feature.',
        'Notify analysts that their previous practice may have been against incorrect procedures and they should retake key scenarios on the corrected versions.',
      ],
      verification: [
        'ir_policies content_hash matches expected hashes.',
        'Audit log shows only authorized writes going forward.',
        'Sample analyst practice sessions to verify correct procedures.',
      ],
      postIncident: [
        'Document the tampering and impact.',
        'Schedule retraining sessions for analysts who trained on incorrect procedures during the tampering window.',
        'Run a TTX scenario reflecting the actual procedures so the team can re-internalize correct response patterns.',
        'Tighten ir_policies access: only the lead should be able to write, audit log should record every change.',
      ],
      componentsInvolved: ['ir_policies table', 'IR Simulator', 'Audit log', 'Content hash verification'],
      relatedScenarios: ['jwt_token_theft', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'pseudonym_mapping_leak',
    category: 'Storage & Data',
    title: 'Pseudonym Mapping Leak',
    summary: 'The encrypted file mapping UUIDs to pseudonyms to real names — held offline by the lead — has been leaked. An adversary can now deanonymize all FireAlive burnout data, fundamentally breaking the platform\'s privacy commitment.',
    indicators: [
      'Lead reports the mapping file was lost, stolen, or exposed',
      'Threat hunting finds the mapping file in attacker-controlled storage',
      'Pseudonyms appear in attacker-known contexts (e.g. mentioned in an extortion attempt)',
    ],
    quickRef: {
      trigger: 'Lead reports mapping leak, OR threat hunt finds the file in unauthorized location, OR adversary references analyst pseudonyms or real-name correlations in extortion/threat communications.',
      firstActions: [
        'Privacy officer notified IMMEDIATELY. This is a major privacy event.',
        'Rotate ALL pseudonyms in the Pseudonyms tab. Each analyst gets a fresh pseudonym; UUIDs stay the same so historical data is preserved (under new pseudonym labels).',
        'Generate fresh mapping file. Lead exports it as encrypted. Store on different physical media than the leaked one (different USB key, different safe).',
        'Audit how the original file was accessed/leaked. The lead\'s storage practice for the file is the root question: was the safe compromised? Was the file copied to a network drive?',
        'Notify analysts that pseudonyms are being rotated. Inform them of the leak and the response.',
      ],
      escalation: 'Privacy breach disclosure per applicable framework (GDPR, HIPAA, PIPEDA, etc.). Engage legal. Conduct CISM Retros for affected analysts — being deanonymized in burnout data is a stressor.',
    },
    fullRunbook: {
      identification: [
        'Confirm the leak: what was leaked, when, to whom, in what format.',
        'Determine: was the entire mapping leaked, or partial? Was it the encrypted file (still recoverable safety if encryption key not exposed) or the decrypted version?',
        'Identify how the leak occurred: physical theft of the storage medium, copying to network storage, accidental sharing, insider exfiltration.',
      ],
      containment: [
        'Rotate all pseudonyms immediately.',
        'Generate fresh mapping file.',
        'Lead stores new mapping file with stricter access (different safe, hardware token, etc.).',
        'Notify analysts of the rotation. Their old pseudonyms are now historical data; new pseudonyms are active.',
      ],
      eradication: [
        'Address the root cause of the leak: improve the lead\'s storage practice for the mapping file.',
        'If the leak was via insider, follow the org\'s insider threat response.',
        'If the leak was via cloud-storage misconfiguration, tighten the storage location.',
      ],
      recovery: [
        'Resume normal operations with new pseudonyms.',
        'Verify all FireAlive features still work with rotated pseudonyms (some labels in UI may change but data continuity is preserved).',
      ],
      verification: [
        'Verify pseudonym rotation completed for all analysts.',
        'Verify historical Tier-3 data is still readable by analysts (their AC fetches by UUID, not pseudonym).',
        'Run a Compliance Scan to verify privacy controls.',
      ],
      postIncident: [
        'Privacy breach disclosure.',
        'Notify each affected analyst: their previous pseudonym was compromised, their identity may have been correlated with their burnout signals during the leak window.',
        'Conduct CISM Retros.',
        'Update the org\'s policy on the mapping file: storage requirements, access procedures, periodic verification.',
      ],
      componentsInvolved: ['Pseudonyms tab', 'Pseudonym mapping file', 'Lead\'s offline storage'],
      relatedScenarios: ['pseudonym_deanonymization_via_correlation', 'tier3_key_compromise', 'tier3_data_unauthorized_access'],
    },
  },


  // ── INTEGRATIONS ───────────────────────────────────────────────────────────

  {
    id: 'soar_credential_compromise',
    category: 'Integrations',
    title: 'SOAR Write-Credential Compromise',
    summary: 'FireAlive\'s SOAR API key (which has WRITE access for ticket assignment) has been stolen. An attacker can write false ticket assignments through FireAlive\'s SOAR identity, potentially mass-reassigning tickets to nobody, overloading specific analysts, or hiding tickets from analysts entirely.',
    indicators: [
      'SOAR audit shows ticket assignments from FireAlive\'s service account at unusual times or volumes',
      'Tickets appearing in SOAR with FireAlive as origin that don\'t correspond to FireAlive routing decisions',
      'SOAR receives API calls from IPs outside FireAlive\'s network range',
      'FireAlive integration_config table shows the SOAR credential was modified outside the audit log',
    ],
    quickRef: {
      trigger: 'SOAR audit shows anomalous FireAlive-attributed activity, OR ticket distributions that don\'t match FireAlive\'s routing engine\'s decisions, OR API calls from unexpected sources.',
      firstActions: [
        'Rotate the SOAR API key immediately (Routing & SOAR tab → Rotate Credentials).',
        'Pause burnout-aware routing (Routing & SOAR tab) until investigation completes — fall back to SOAR\'s native distribution.',
        'Audit SOAR\'s recent activity attributed to FireAlive. Identify unauthorized assignments. Roll them back where possible.',
        'On the FireAlive side, audit how the credential was exposed. Was the lead account compromised (allowing read of integration_config)? Was the credential stored insecurely?',
        'Verify the source IP allowlist for SOAR API calls. If FireAlive\'s SOAR access is allowlisted to specific IPs, attacker calls from outside that range should have been blocked.',
      ],
      escalation: 'If the compromised SOAR key has access beyond ticket assignment (e.g. orchestration of other security tools), the attacker can pivot. Treat as broader incident. Engage SOAR vendor for assistance.',
    },
    fullRunbook: {
      identification: [
        'Pull SOAR audit log filtered by FireAlive\'s API key. Identify the time window of suspect activity.',
        'Compare with FireAlive\'s routing decisions for the same window. If FireAlive\'s logs show no routing decisions matching the SOAR-recorded assignments, those assignments came from outside FireAlive — credential theft confirmed.',
        'Examine source IP / User-Agent patterns of the SOAR calls. Unfamiliar source = external attacker.',
      ],
      containment: [
        'Rotate the SOAR API key. Generate a new key on the SOAR side, update FireAlive\'s integration_config.',
        'Pause burnout-aware routing during investigation.',
        'Restrict the SOAR credential\'s scope: if currently has broad write access, narrow to "ticket assignment only". Other capabilities should require separate credentials with additional approval.',
      ],
      eradication: [
        'Investigate how the credential was exposed. Common paths: lead account compromise (attacker read integration_config), credential stored in source control or shared documentation, credential leaked via misconfiguration.',
        'Audit other integration credentials for the same exposure pattern. Rotate any that may also be at risk.',
        'Enable IP-allowlisting on the SOAR side: only FireAlive\'s known IP range can use the API key.',
      ],
      recovery: [
        'Resume burnout-aware routing with the new credential.',
        'Verify routing engine\'s assignments correctly appear in SOAR.',
        'Roll back any unauthorized assignments still in SOAR (or coordinate with the SOAR\'s ticket distribution to manually fix).',
      ],
      verification: [
        'Compare SOAR audit log with FireAlive routing decisions for 7 days. They should match continuously.',
        'Run a Regression Test (Regression Test tab) to confirm the SOAR integration works end-to-end.',
        'Run a Compliance Scan.',
      ],
      postIncident: [
        'Document the credential exposure path.',
        'Tighten secret management: ensure all integration credentials are stored only in protected configuration, never in source control or shared docs.',
        'Tabletop the scenario in the next quarterly TTX.',
      ],
      componentsInvolved: ['Routing & SOAR tab', 'SOAR integration', 'integration_config table', 'Burnout-aware routing engine'],
      relatedScenarios: ['ticketing_credential_compromise', 'jwt_token_theft', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'ticketing_credential_compromise',
    category: 'Integrations',
    title: 'Ticketing Read-Credential Compromise',
    summary: 'FireAlive\'s ticketing system credential (READ-ONLY access for queue metadata) has been stolen. Less severe than SOAR write-compromise but allows the attacker to enumerate ticket queues and observe SOC operational state.',
    indicators: [
      'Ticketing audit shows reads from FireAlive\'s service account at unusual times',
      'Read activity from IPs outside FireAlive\'s network range',
      'Volume of reads exceeds normal patterns (attacker harvesting queue data)',
    ],
    quickRef: {
      trigger: 'Ticketing audit shows anomalous read patterns, OR API calls from unexpected sources.',
      firstActions: [
        'Rotate the ticketing API key (Routing & SOAR tab).',
        'Pause burnout-aware routing temporarily — without ticketing reads, FireAlive can\'t see queue metadata.',
        'Audit ticketing access logs. Identify what queue data the attacker harvested.',
        'Investigate exposure path on the FireAlive side.',
      ],
      escalation: 'If the attacker now has insight into the SOC\'s ticket queue (alert volume, alert types, response patterns), they can plan timed attacks for when the SOC is overloaded. Treat as operational-intel exposure.',
    },
    fullRunbook: {
      identification: [
        'Ticketing audit log shows the suspect read pattern.',
        'Identify what data was readable: queue contents, alert metadata, severity distributions, assignee identities.',
        'Identify the exposure window.',
      ],
      containment: [
        'Rotate the ticketing API key.',
        'Restrict scope: read-only is already the principle here, but verify the credential doesn\'t have any unintended write capabilities.',
        'Enable IP-allowlisting on ticketing side.',
      ],
      eradication: [
        'Investigate exposure path.',
        'Audit related credentials.',
      ],
      recovery: [
        'Resume burnout-aware routing with new credential.',
        'Verify queue metadata reads succeed.',
      ],
      verification: [
        'Monitor ticketing audit for 7 days.',
        'Run Regression Test.',
      ],
      postIncident: [
        'Document.',
        'Notify leadership about operational-intel exposure.',
        'Consider whether to make this a known threat in next TTX.',
      ],
      componentsInvolved: ['Routing & SOAR tab', 'Ticketing integration', 'integration_config table'],
      relatedScenarios: ['soar_credential_compromise'],
    },
  },

  {
    id: 'siem_cef_feed_poisoning',
    category: 'Integrations',
    title: 'SIEM CEF Feed Poisoning',
    summary: 'An adversary injects false CEF events into the SIEM stream that appear to come from FireAlive, polluting the SOC\'s monitoring with fabricated FireAlive activity (or hiding actual FireAlive activity that should have alerted).',
    indicators: [
      'SIEM shows FireAlive-attributed events that don\'t correlate with audit log entries',
      'Expected FireAlive events missing from SIEM (suppression of real events)',
      'CEF events from FireAlive arriving from unexpected source IPs',
      'CEF event format inconsistencies (subtle field-name or escaping anomalies)',
    ],
    quickRef: {
      trigger: 'SIEM-to-FireAlive event correlation drops below expected threshold, OR SIEM shows FireAlive events that have no FireAlive audit log corollary.',
      firstActions: [
        'Cross-correlate SIEM\'s recent FireAlive events with FireAlive\'s audit log. Identify mismatches.',
        'Restrict SIEM\'s ingestion of FireAlive CEF to authenticated channel only (mTLS, signed payloads).',
        'Rotate any credentials FireAlive uses to push to SIEM.',
        'Enable IP-allowlisting on SIEM\'s FireAlive ingestion: only accept from FireAlive\'s known IPs.',
        'Audit SIEM-side detection rules that depend on FireAlive events. Some may have triggered on fabricated events; others may have failed to trigger on real events that were suppressed.',
      ],
      escalation: 'If detection rules failed to fire because attacker suppressed real events, the SOC\'s broader threat detection may have missed real incidents. Engage broader IR.',
    },
    fullRunbook: {
      identification: [
        'Sample SIEM events attributed to FireAlive over a recent window. Look up each in FireAlive\'s audit log for confirmation.',
        'Identify events in SIEM with no matching audit log entry (fabricated) and events in audit log with no matching SIEM entry (suppressed).',
        'Examine source IPs of CEF events received by SIEM. Unfamiliar IPs suggest external injection.',
      ],
      containment: [
        'Restrict SIEM\'s FireAlive ingestion to authenticated, signed CEF only. Reject unauthenticated CEF claiming to be from FireAlive.',
        'Rotate FireAlive\'s CEF push credentials.',
        'Enable IP-allowlisting on the SIEM side.',
      ],
      eradication: [
        'Audit SIEM-side detection rules. Identify which fired on fabricated events (false positives that consumed analyst attention) and which failed to fire on suppressed events (missed detections).',
        'For missed detections: the org may have unaddressed incidents. Backtrack from FireAlive audit log to identify what should have alerted.',
        'Audit the network path between FireAlive and SIEM. Was a network appliance compromised allowing injection?',
      ],
      recovery: [
        'Resume CEF push from FireAlive with new credentials and authenticated transport.',
        'Verify SIEM correctly ingests authenticated FireAlive events.',
        'Re-examine and re-process the missed-detection events through the org\'s incident response workflow.',
      ],
      verification: [
        'Continuous correlation of SIEM FireAlive events with audit log for 7 days.',
        'Run Compliance Scan.',
      ],
      postIncident: [
        'Document.',
        'Update SIEM detection logic: distinguish authenticated FireAlive events from inbound CEF claims.',
        'Tabletop the scenario.',
      ],
      componentsInvolved: ['SIEM Integration tab', 'CEF stream', 'Metrics collector', 'Audit log', 'SIEM detection rules'],
      relatedScenarios: ['mc_server_channel_compromise'],
    },
  },

  {
    id: 'edr_integration_disabled',
    category: 'Integrations',
    title: 'EDR / Threat-Hunting Integration Disabled',
    summary: 'The EDR or threat-hunting integration that scans files uploaded to FireAlive (config restores, IR policy uploads, IaC imports, app updates) has been disabled. An attacker can upload malicious files that bypass the security check.',
    indicators: [
      'EDR Integration tab shows status DISABLED unexpectedly',
      'Audit log shows EDR_DISABLED event or feature toggle change for edr_inspection',
      'Threat hunting integration health checks fail',
      'Files uploaded during the disabled window did not produce EDR scan log entries',
    ],
    quickRef: {
      trigger: 'EDR Integration tab status DISABLED unexpectedly, OR threat hunt health check fails, OR audit log shows edr_inspection toggle change.',
      firstActions: [
        'Re-enable EDR integration immediately (EDR Integration tab → Enable).',
        'Verify the EDR provider connection is healthy. If credentials were also tampered with, rotate.',
        'Identify all file uploads during the disabled window. Each is a potential attack delivery vector.',
        'Submit each uploaded file to the EDR for retroactive scanning. Quarantine any flagged file and investigate the uploader.',
        'Review the audit log for who disabled EDR. Treat as potential insider or compromise.',
      ],
      escalation: 'If a malicious file was uploaded and not scanned, the file may have already executed in FireAlive\'s context. Treat as a host compromise: stop the server, snapshot for forensics, restore from clean backup.',
    },
    fullRunbook: {
      identification: [
        'Audit log shows the EDR disable event. Identify the actor (user_id) and timestamp.',
        'Identify all file upload events between EDR-disable and EDR-re-enable timestamps.',
        'Cross-reference with EDR scan log for the same window. Files uploaded but not scanned are unscanned and potentially malicious.',
      ],
      containment: [
        'Re-enable EDR integration.',
        'Rotate EDR credential if it was tampered with.',
        'Quarantine any unscanned uploaded files. Don\'t let them execute or propagate.',
        'For files that have already been processed (e.g. an IR policy upload that was parsed), assume the policy data may be malicious — pause the IR Simulator and investigate.',
      ],
      eradication: [
        'Submit each unscanned file to the EDR for retroactive scanning.',
        'For files flagged as malicious: investigate the uploader (was their account compromised?), wipe the file, audit any downstream effects.',
        'Investigate who disabled EDR and why. If insider abuse, follow the org\'s insider response.',
      ],
      recovery: [
        'Verify EDR integration is healthy and scanning all uploads.',
        'Resume IR Simulator and other features that depend on uploaded files.',
        'Re-process any previously-scanned-clean files normally.',
      ],
      verification: [
        'Test EDR integration: upload a known-EICAR-test file. EDR should detect and reject.',
        'Run Compromise Scan on the FireAlive server.',
      ],
      postIncident: [
        'Document who disabled EDR and the response.',
        'Consider making EDR disable require dual-approval (lead + security officer).',
        'Add a SOAR alert that fires when EDR integration goes from enabled to disabled.',
      ],
      componentsInvolved: ['EDR Integration tab', 'Threat Hunting Integrations tab', 'File upload paths', 'Feature toggles'],
      relatedScenarios: ['binary_tampering', 'compromised_app_update', 'config_drift_unauthorized_changes'],
    },
  },


  // ── APPLICATION INTEGRITY ──────────────────────────────────────────────────

  {
    id: 'binary_tampering',
    category: 'Application Integrity',
    title: 'Binary Tampering of MC, AC, or Server',
    summary: 'FireAlive\'s binary files have been altered after install. The integrity check fails on startup. Could be supply-chain attack, in-place modification by an attacker with host access, or tampered update package.',
    indicators: [
      'Integrity check FAIL on app startup (server, MC, or AC)',
      'Binary file hashes don\'t match the manifest',
      'Modification timestamps on FireAlive files have changed without an update event',
      'Process behavior anomalies (unexpected network connections, file accesses, child processes)',
    ],
    quickRef: {
      trigger: 'Startup integrity check fails, OR binary hash mismatch detected, OR runtime monitor flags binary modification.',
      firstActions: [
        'Stop the affected component immediately (server, MC, or AC).',
        'Snapshot the modified binaries for forensic analysis. Don\'t let them run.',
        'Identify which files were modified and when. Compare modification timestamps with deployment history.',
        'Reprovision the affected component: tear down completely, reinstall fresh from verified-clean source.',
        'For server: use HA failover to passive while rebuilding active. For MC/AC: reprovision the workstation per Compromise Scan + Restore workflow.',
      ],
      escalation: 'If multiple components show binary tampering simultaneously, the deployment infrastructure or update channel is compromised. Pause all FireAlive deployments. Engage security operations broadly.',
    },
    fullRunbook: {
      identification: [
        'Examine the integrity check\'s failure output. Identify which specific files have hash mismatches.',
        'Check file modification timestamps. When were the files altered?',
        'Cross-reference with deployment history: was there a recent update? An auto-update via the Updates tab? A manual configuration change?',
        'Check OS-level audit (auditd, Windows audit) for who/what wrote to the file.',
        'For runtime-detected tampering: the runtime-monitor service flags FIM (file integrity monitoring) violations. Pull its alert history.',
      ],
      containment: [
        'Stop the affected component. Don\'t allow tampered binaries to continue running.',
        'Snapshot the binaries for forensics.',
        'For the server: trigger HA failover to passive node (HA tab), let the passive handle traffic while the active is rebuilt.',
        'For an MC: pause all administrative actions from that MC. Lead may need to operate from a backup MC during reprovision.',
        'For an AC: the analyst is offline temporarily. Their queue routing reverts to fail-open mode for them.',
      ],
      eradication: [
        'For server: reinstall from verified-clean source, restore configuration via External Restore.',
        'For MC: reinstall, External Restore for configuration.',
        'For AC: reinstall via the lead\'s Client Provisioning workflow, then analyst re-authenticates.',
        'Investigate the root cause. Was it: (a) compromised update channel, (b) supply-chain attack on dependencies, (c) attacker with host access?',
        'For (a): rotate update channel credentials, audit Updates tab integration.',
        'For (b): review npm audit output, pin specific versions of dependencies, consider a bill-of-materials review.',
        'For (c): host compromise response. The host needs cleanup before FireAlive returns.',
      ],
      recovery: [
        'After reprovision and restore, restart the component.',
        'Verify integrity check passes on startup.',
        'Resume normal operations.',
        'For the server with HA: failover back from passive (or leave passive running if you prefer).',
      ],
      verification: [
        'Run Compromise Scan.',
        'Run Regression Test.',
        'Monitor runtime-monitor service for further alerts.',
        'Verify update channel integrity if the root cause was update tampering.',
      ],
      postIncident: [
        'Document the tampering: what files, what root cause, what response.',
        'If supply chain: review and tighten dependency management.',
        'If host compromise: coordinate with the host\'s broader incident response.',
        'If update channel: tighten controls. Consider signed updates with verification.',
        'Tabletop in next quarterly TTX.',
      ],
      componentsInvolved: ['Integrity check', 'Runtime monitor', 'Binary files', 'Update channel', 'Reprovisioning workflow'],
      relatedScenarios: ['compromised_app_update', 'config_drift_unauthorized_changes', 'supply_chain_npm_attack'],
    },
  },

  {
    id: 'compromised_app_update',
    category: 'Application Integrity',
    title: 'Compromised App Update',
    summary: 'A FireAlive update pushed through the Updates tab was malicious. The lab-staging workflow may not have caught it (insufficient testing, or specifically-evasive malicious behavior).',
    indicators: [
      'Post-update integrity check fails',
      'Post-update behavior anomalies (new network connections, unexpected file accesses)',
      'Post-update SOAR alerts on FireAlive activity',
      'Lab-staging tests passed but production deployment fails or behaves anomalously',
    ],
    quickRef: {
      trigger: 'Recent update (within last 7 days) followed by integrity check failures or behavior anomalies.',
      firstActions: [
        'Halt any further rollout of the update if it\'s still being deployed across the org.',
        'On affected hosts: stop FireAlive components.',
        'Roll back the update on affected hosts. Restore the previous version via the Updates tab\'s rollback function (if available) or via Restore tab.',
        'Investigate the update package: was it from the official upstream? Was it tampered with in transit? Was the upstream itself compromised?',
        'Coordinate with FireAlive maintainers (upstream) — if the update came from upstream, the entire user base may be affected.',
      ],
      escalation: 'A compromised update affecting many orgs is a supply-chain attack. Coordinate with upstream maintainers, FireAlive\'s mailing list, and the broader user community for rapid mitigation.',
    },
    fullRunbook: {
      identification: [
        'Identify when the update was applied. Compare against integrity-check-fail and anomaly timestamps.',
        'Examine the update package itself. Compare its hash against the published hash from the upstream.',
        'If hashes match upstream, the upstream may be compromised. If they don\'t match, the package was tampered with in transit or storage.',
        'Examine the lab-staging test results. Did they pass legitimately, or were tests evaded?',
      ],
      containment: [
        'Halt update rollout.',
        'Stop affected components.',
        'Rollback to previous version.',
        'For production deployments using the update channel: pause auto-updates entirely until investigation completes.',
      ],
      eradication: [
        'If update came from a tampered intermediate: rotate update channel credentials, secure the update mirror.',
        'If upstream was compromised: coordinate with upstream maintainers, treat all of upstream\'s recent updates as suspect.',
        'Reprovision affected hosts per Binary Tampering scenario.',
      ],
      recovery: [
        'Resume operations on the previous (non-compromised) version.',
        'Wait for clean update before re-enabling auto-updates.',
        'Verify integrity check passes on rollback version.',
      ],
      verification: [
        'Run Compromise Scan, Regression Test, Compliance Scan.',
        'Monitor for further indicators.',
      ],
      postIncident: [
        'Document the compromise.',
        'Update the lab-staging test suite to specifically test for the malicious behavior pattern observed.',
        'Tighten update channel security: signed packages, multiple verification steps, dual-approval on production deployment.',
        'Coordinate with upstream and broader community on disclosure.',
      ],
      componentsInvolved: ['Updates tab', 'Lab staging', 'Update channel', 'Integrity check', 'Rollback workflow'],
      relatedScenarios: ['binary_tampering', 'supply_chain_npm_attack', 'fuse_counter_rollback_attempt'],
    },
  },

  {
    id: 'config_drift_unauthorized_changes',
    category: 'Application Integrity',
    title: 'Configuration Drift / Unauthorized Config Changes',
    summary: 'Critical FireAlive settings (routing thresholds, feature toggles, integration credentials) have been changed without lead authorization. May indicate insider abuse, account compromise, or attacker with database access.',
    indicators: [
      'Configuration values differ from expected/documented baseline',
      'Audit log shows config changes by user_ids that shouldn\'t have made them',
      'Config changes occurred during periods the responsible lead was offline',
      'Feature toggles show unexpected states (critical features disabled)',
    ],
    quickRef: {
      trigger: 'Config values don\'t match expected baseline, OR audit log shows config changes attributed to actors who shouldn\'t make them, OR critical feature toggles are in unexpected states.',
      firstActions: [
        'Identify the changes: what was changed, when, by whom.',
        'For each unauthorized change, revert to the expected value. Use Restore tab to restore configuration from a known-good backup.',
        'Investigate the actor. If a user account is implicated, treat as account compromise and follow JWT theft scenario.',
        'If the changes were made via direct database access bypassing the app, follow the database access scenario.',
        'Disable the dual-approval option in any feature that doesn\'t already have it. For critical config changes, require two-person authorization.',
      ],
      escalation: 'If integration credentials were changed (e.g. SOAR endpoint pointed to attacker-controlled URL), the attacker may have established persistence. Treat as broader incident.',
    },
    fullRunbook: {
      identification: [
        'Compare current configuration values against the expected baseline. Use the team_config table as source of truth.',
        'Pull audit log entries for config writes during the suspect window. Each unauthorized change shows which user/key made the change.',
        'Determine whether the change pattern matches a single actor (compromise of one account), multiple actors (broader compromise), or no actor (database direct access).',
      ],
      containment: [
        'Revert each unauthorized change.',
        'If integration credentials were changed: rotate to fresh credentials immediately. Don\'t trust the changed values.',
        'If feature toggles were changed (e.g. EDR was disabled): re-enable critical features.',
        'Disable the implicated user accounts pending investigation.',
      ],
      eradication: [
        'Address root cause: account compromise (JWT theft scenario), database direct access (database access scenario), or insider abuse (org\'s insider response).',
        'Tighten config-write paths: require dual-approval for high-risk changes. Audit log entries for config changes should include reason fields.',
        'Add Tripwire-style alerts on critical config changes.',
      ],
      recovery: [
        'Restore configuration to expected baseline.',
        'Verify all integrations work with restored credentials.',
        'Resume normal operations.',
      ],
      verification: [
        'Continuous comparison of config values with baseline for 7 days.',
        'Audit log review of config changes for that period.',
      ],
      postIncident: [
        'Document.',
        'Strengthen change management for FireAlive configuration: require change tickets, dual-approval, scheduled-change windows.',
        'Tabletop the scenario.',
      ],
      componentsInvolved: ['team_config table', 'Feature Toggles', 'Integration configs', 'Audit log'],
      relatedScenarios: ['jwt_token_theft', 'tier3_data_unauthorized_access', 'soar_credential_compromise'],
    },
  },

  {
    id: 'fuse_counter_rollback_attempt',
    category: 'Application Integrity',
    title: 'Fuse Counter Rollback Attempt',
    summary: 'An adversary or operator attempts to downgrade FireAlive to an earlier version with a known vulnerability. The anti-rollback fuse refuses startup; this is the system working as designed.',
    indicators: [
      'Server fails to start with fuse counter mismatch error',
      'Logs show "FuseCounter rollback rejected — current DB fuse N, attempting to start version with fuse M < N"',
      'Operations team reports unable to deploy older version',
    ],
    quickRef: {
      trigger: 'Server startup logs show fuse counter rejection, OR ops team reports inability to start older version.',
      firstActions: [
        'Confirm the rollback attempt: which version was being deployed, which version was previously running?',
        'If legitimate (ops team trying to address a bug in current version): follow the proper rollback workflow which involves resetting the fuse counter, NOT bypassing the check.',
        'If suspicious (no authorized rollback in progress): treat as compromise indicator. The attacker may be trying to deploy a vulnerable version to exploit later.',
        'Investigate who initiated the deployment.',
        'Maintain the current version (don\'t roll back). The fuse counter is protecting the install.',
      ],
      escalation: 'If unauthorized rollback attempt: full security incident. Treat the deployment infrastructure as potentially compromised.',
    },
    fullRunbook: {
      identification: [
        'Examine server startup logs. The rollback rejection message includes the attempting version, current DB fuse counter, and the discrepancy.',
        'Identify who initiated the deployment via the deployment logs (Updates tab audit log if the Updates feature was used; CI/CD logs if directly deployed).',
        'Determine if this was authorized. If yes, follow the legitimate rollback workflow. If no, treat as security incident.',
      ],
      containment: [
        'Block further deployment attempts. Pause auto-updates.',
        'For unauthorized: investigate the deployment infrastructure. Was the CI/CD pipeline compromised? Did an attacker have access to deployment systems?',
      ],
      eradication: [
        'For unauthorized: address the deployment infrastructure compromise. Rotate deployment credentials, audit access, tighten access controls.',
        'For authorized rollback: follow the proper workflow. The fuse counter can be reset by an admin with explicit acknowledgment of the security implications. The reset is logged in the audit trail.',
      ],
      recovery: [
        'For authorized: complete the rollback with documentation of why and what security mitigations are in place to compensate for the older version\'s known issues.',
        'For unauthorized: maintain the current version. Restore deployment infrastructure security.',
      ],
      verification: [
        'Server starts successfully with the appropriate version.',
        'Audit log shows the fuse counter event (rejection or authorized reset).',
      ],
      postIncident: [
        'Document.',
        'Review whether the org needs to update its rollback policy. If rollback is occasionally needed, the workflow should be well-documented and exercised.',
        'For unauthorized: full deployment infrastructure review.',
      ],
      componentsInvolved: ['Server startup', 'Fuse counter', 'package.json', 'Audit log', 'Deployment infrastructure'],
      relatedScenarios: ['compromised_app_update', 'binary_tampering'],
    },
  },

  {
    id: 'supply_chain_npm_attack',
    category: 'Application Integrity',
    title: 'Supply Chain Attack on npm Dependencies',
    summary: 'A FireAlive npm dependency (better-sqlite3, jsonwebtoken, helmet, etc.) has shipped a malicious version that gets pulled during update or fresh install. The malicious code runs with FireAlive\'s privileges.',
    indicators: [
      'Post-install behavior anomalies in FireAlive (network connections to unexpected hosts, file access patterns)',
      'npm audit reports new vulnerabilities or malicious packages',
      'Dependency hash mismatch (package-lock.json integrity field doesn\'t match installed package)',
      'Industry alerts about specific npm packages being compromised',
    ],
    quickRef: {
      trigger: 'npm audit alert on FireAlive dependencies, OR industry CVE/disclosure for a package FireAlive uses, OR post-install behavior anomalies.',
      firstActions: [
        'Identify the affected dependency and version.',
        'Check FireAlive\'s package-lock.json: what version is locked? Did the install actually pull that version?',
        'Verify the integrity hash in package-lock.json matches the installed package.',
        'If a malicious version was installed: stop FireAlive. Don\'t let the malicious code continue running.',
        'Investigate downstream effects: what data did the malicious code access? What network connections did it make?',
      ],
      escalation: 'Supply chain attacks on widely-used packages affect many users. Coordinate with FireAlive maintainers and the npm community for response.',
    },
    fullRunbook: {
      identification: [
        'npm audit output identifies vulnerable or malicious packages.',
        'Compare installed package hashes against the integrity field in package-lock.json. Mismatches indicate the installed package differs from what was locked.',
        'Cross-reference with industry advisories: was this dependency in a recent supply-chain incident?',
        'Examine FireAlive\'s outbound network connections. Malicious npm packages often beacon to attacker-controlled hosts.',
      ],
      containment: [
        'Stop FireAlive components running with the malicious dependency.',
        'Pin the dependency to a known-clean version in package.json. Update package-lock.json with the clean version\'s integrity hash.',
        'Reinstall dependencies (npm ci with the cleaned package-lock.json).',
        'Verify the reinstalled package matches the expected hash.',
      ],
      eradication: [
        'Reprovision affected hosts: the malicious code may have left persistence beyond just the dependency itself. Treat as host compromise.',
        'Audit other dependencies for similar issues. Run npm audit fix.',
        'Rotate any credentials that may have been exposed during the malicious code\'s execution: KMS access tokens, integration credentials, JWT signing keys.',
      ],
      recovery: [
        'Resume operations after reprovision and clean install.',
        'Verify integrity check passes.',
      ],
      verification: [
        'Run Compromise Scan, Regression Test, Compliance Scan.',
        'Monitor outbound network connections for 14 days.',
        'Run npm audit periodically.',
      ],
      postIncident: [
        'Document.',
        'Review dependency management: pin specific versions, use lockfiles, audit on every install, consider using npm/pnpm/yarn audit in CI.',
        'Consider a software bill of materials (SBOM) for FireAlive deployments.',
        'Tabletop in next quarterly TTX.',
      ],
      componentsInvolved: ['npm dependencies', 'package-lock.json', 'Integrity verification', 'Outbound network'],
      relatedScenarios: ['binary_tampering', 'compromised_app_update'],
    },
  },


  // ── BURNOUT-SPECIFIC ABUSE ─────────────────────────────────────────────────

  {
    id: 'false_signal_injection_mass_tripwire',
    category: 'Burnout-Specific Abuse',
    title: 'False Burnout Signal Injection (Mass Tripwire Trip)',
    summary: 'An adversary uses compromised AC clients (or compromised server credentials) to inject false elevated burnout signals across multiple analysts. Burnout-aware routing reduces tickets across the team. Tripwire fires when too many analysts simultaneously hit reduced routing — this is the system working as designed against this attack.',
    indicators: [
      'Tripwire alert: %% of analysts simultaneously entered reduced routing within a short window',
      'signal_readings table shows synchronized signal spikes across multiple analysts',
      'Reduced-routing requests originating from unusual sources (not analyst-initiated)',
      'Signal patterns not corresponding to actual SOC workload',
    ],
    quickRef: {
      trigger: 'Tripwire fires per Tripwire tab\'s configuration, OR pattern of synchronized burnout-signal elevations across multiple analysts.',
      firstActions: [
        'Tripwire has already auto-disabled burnout-aware routing. Don\'t override — tickets are flowing via fail-open. The team is still defending the network.',
        'Open the Tripwire tab and Compromise Scan tab to investigate.',
        'Run Compromise Scan on all analyst clients. Identify which ones may be compromised.',
        'Examine signal_readings for the affected analysts. Patterns that are nearly identical across analysts (same metrics, same magnitudes, same timestamps) indicate injection rather than legitimate variation.',
        'Mark suspect signal_readings as untrusted in the Burnout Engine config so they don\'t poison baselines.',
      ],
      escalation: 'If many ACs show compromise indicators, this is a mass AC compromise scenario. The org\'s SOC tooling stack itself may be under attack. Engage broader IR.',
    },
    fullRunbook: {
      identification: [
        'Tripwire fires; capture the trigger pattern (how many analysts, in what window, what signals).',
        'Pull signal_readings for the affected analysts. Look for: synchronized spikes, identical metric patterns, signals at unusual times.',
        'Run Compromise Scan on each AC. Identify integrity failures, configuration drift, or anomalous behavior.',
        'Cross-reference with auth_log: did the AC clients show unusual authentication patterns recently?',
      ],
      containment: [
        'Tripwire has disabled burnout-aware routing. Leave it disabled until investigation completes.',
        'For each AC showing compromise: disconnect, snapshot for forensics, reprovision.',
        'Mark the suspect signal window as untrusted in the Burnout Engine. Discard the data.',
        'If credentials were also compromised on affected ACs, rotate.',
      ],
      eradication: [
        'Mass AC reprovision per the related scenario.',
        'Investigate: how did the attacker compromise multiple ACs? Common path or single root cause?',
        'Address the root cause: phishing campaign that hit multiple analysts? Network compromise affecting that segment? Compromised analyst account that was reused for AC enrollment?',
      ],
      recovery: [
        'After ACs are reprovisioned and analysts re-authenticate, signal collection resumes.',
        'Burnout Engine baselines re-establish on-device over the fixed ~90-day establishment window (frozen once set, not a rolling mean).',
        'After baselines are clean, re-enable burnout-aware routing.',
      ],
      verification: [
        'Monitor signal_readings for synchronized patterns for 14 days. Should not recur.',
        'Run Compromise Scan periodically.',
        'Run Tripwire-test scenarios in TTX to verify detection still works.',
      ],
      postIncident: [
        'Document the attack: how many ACs, what timeframe, what indicators, what response.',
        'Conduct CISM Retros for analysts whose ACs were compromised.',
        'Tighten AC enrollment: tighter posture checks, mTLS, certificate pinning.',
        'Review Tripwire threshold: was it sensitive enough? Did it fire fast enough?',
      ],
      componentsInvolved: ['Tripwire tab', 'AC clients', 'signal_readings', 'Burnout Engine', 'Routing engine', 'Compromise Scan'],
      relatedScenarios: ['false_de_escalation_capacity_spoof', 'mass_ac_reprovision_needed', 'ac_server_channel_compromise'],
    },
  },

  {
    id: 'false_de_escalation_capacity_spoof',
    category: 'Burnout-Specific Abuse',
    title: 'False De-Escalation Injection (Capacity Spoof)',
    summary: 'Inverse of false signal injection. The attacker injects FAKE healthy signals so the routing engine sends MORE tickets than analysts can actually handle. Real burnout occurs while the system thinks everyone is fine. Tickets pile up; legitimate alerts get missed.',
    indicators: [
      'Analysts report being overwhelmed but the dashboard shows healthy aggregate metrics',
      'Ticket completion rate dropping while assignment rate stays high',
      'SLA degradation despite system showing capacity available',
      'signal_readings show very low values across the board (suspicious uniformity in healthy direction)',
    ],
    quickRef: {
      trigger: 'Mismatch between dashboard health and ground-truth SOC operational state, OR analysts report being overwhelmed despite system showing healthy.',
      firstActions: [
        'Verify the mismatch: ask leads in person whether their analysts feel overwhelmed despite metrics showing healthy.',
        'Pause burnout-aware routing temporarily. Let SOAR\'s native distribution handle assignment.',
        'Investigate signal_readings for affected analysts. Compare against baseline patterns. Suspiciously-healthy uniform values suggest spoofing.',
        'Run Compromise Scan on AC clients. Same investigation pattern as false signal injection scenario.',
        'Mark the suspect signal window as untrusted; discard data; re-baseline.',
      ],
      escalation: 'This attack is harder to detect than false elevation because it doesn\'t trip Tripwire — Tripwire fires on synchronized REDUCED routing, not on synchronized HEALTHY signals. Deep investigation required.',
    },
    fullRunbook: {
      identification: [
        'Compare dashboard team_health metrics against ground-truth indicators: ticket completion rate, SLA performance, analyst-reported feelings.',
        'Pull signal_readings for the affected period. Compare against historical baselines. Suspiciously uniform "healthy" values across analysts is the indicator.',
        'Cross-reference: real workload (ticket assignment rate) vs. claimed capacity (signals showing healthy). Workload increasing while signals stay low = spoofed.',
      ],
      containment: [
        'Pause burnout-aware routing.',
        'Reprovision affected AC clients per false signal injection scenario.',
        'Mark suspect signal data as untrusted.',
      ],
      eradication: [
        'Same as false signal injection: address the root compromise vector.',
        'Re-enable burnout-aware routing only after baselines are re-established with clean data.',
      ],
      recovery: [
        'After clean baselines, resume burnout-aware routing.',
        'Conduct CISM Retros for analysts who experienced the burnout-without-detection period — they were burning out without the system\'s help.',
      ],
      verification: [
        'Continuous comparison of dashboard metrics with operational ground truth for 14 days.',
        'Run Compromise Scan periodically.',
      ],
      postIncident: [
        'Document.',
        'Add detection logic: mismatch between signal-claimed health and operational metrics (ticket completion rate, SLA) should fire an alert independently of the Tripwire.',
        'Tabletop the scenario.',
      ],
      componentsInvolved: ['Routing engine', 'signal_readings', 'Burnout Engine', 'team_health metrics', 'SLA monitoring'],
      relatedScenarios: ['false_signal_injection_mass_tripwire', 'mass_ac_reprovision_needed'],
    },
  },

  {
    id: 'helper_pay_fraud',
    category: 'Burnout-Specific Abuse',
    feature_required: 'helper_pay',
    title: 'Helper Pay Manipulation / Fake Skill-Share Sessions',
    summary: 'Once Helper Pay ships, an adversary or insider creates fake peer sessions or fake ratings to drain the org\'s PTO/bonus budget through fraudulent Helper Pay redemptions.',
    indicators: [
      'Peer sessions appearing in peer_sessions table with no corresponding peer chat activity',
      'High volumes of 5-star ratings between same pair of analysts',
      'Helper points accruing rapidly against a specific analyst',
      'Redemption requests far exceeding historical patterns',
      'Sessions occurring during periods when the involved analysts were offline',
    ],
    quickRef: {
      trigger: 'Helper Pay leaderboard shows anomalous accrual rate, OR redemption queue exceeds expected volume, OR audit reveals fake peer sessions.',
      firstActions: [
        'Pause Helper Pay redemption processing (Peer Skill-Share Configuration → Pause Redemptions).',
        'Audit peer_sessions table for the suspect window. Cross-reference with peer_messages: real sessions have message activity.',
        'Audit peer_session_ratings for the suspect window. Sessions without corresponding messages OR ratings without corresponding sessions are fraudulent.',
        'Review which analysts received fraudulent points. Their Helper Pay balance should be adjusted to remove the fraudulent accruals.',
        'Investigate who created the fake sessions. Likely an insider with peer-session creation access, or a compromised account.',
      ],
      escalation: 'If fraud is significant, this is potentially a financial/HR matter. Engage HR and the analyst\'s manager. The org\'s anti-fraud policies apply.',
    },
    fullRunbook: {
      identification: [
        'Cross-reference peer_sessions with peer_messages. Sessions with zero or near-zero message volume are suspicious.',
        'Cross-reference peer_session_ratings with peer_sessions. Each rating should reference a real session.',
        'Cross-reference session timestamps with auth_log. Were both analysts authenticated and active during the session?',
        'Examine helper_points_ledger. Identify the accruals that came from fraudulent sessions.',
      ],
      containment: [
        'Pause Helper Pay redemption processing.',
        'Disable session-creation for the implicated analyst account(s) pending investigation.',
        'Reverse fraudulent point accruals in helper_points_ledger via append-only ledger entries (the ledger is append-only; reversal is a new entry, not a delete).',
      ],
      eradication: [
        'Investigate the fraud mechanism. Insider creating fake sessions? Compromised account?',
        'For insider: HR investigation per the org\'s policy.',
        'For compromised account: JWT theft scenario response.',
        'Tighten anti-fraud controls in Helper Pay: stronger validation that peer sessions are real (minimum message count, minimum duration, periodic random verification samples).',
      ],
      recovery: [
        'Resume Helper Pay redemption processing.',
        'Reverse any redemptions that were paid out from fraudulent accruals.',
      ],
      verification: [
        'Continuous monitoring of peer_sessions cross-referenced with peer_messages for 30 days.',
        'Sample-audit Helper Pay accruals.',
      ],
      postIncident: [
        'Document the fraud mechanism.',
        'Strengthen Helper Pay anti-fraud controls: minimum-message thresholds, time-of-session validation, post-session verification samples.',
        'Communicate to analysts that fraud was detected and addressed. Maintain trust in the system.',
      ],
      componentsInvolved: ['Peer Skill-Share Configuration', 'Helper Pay', 'peer_sessions', 'peer_messages', 'peer_session_ratings', 'helper_points_ledger', 'helper_redemptions'],
      relatedScenarios: ['peer_chat_abuse_data_exfil'],
    },
  },

  {
    id: 'peer_chat_abuse_data_exfil',
    category: 'Burnout-Specific Abuse',
    title: 'Peer Chat Platform Abused for Harassment or Data Exfiltration',
    summary: 'The peer chat infrastructure (E2EE between analysts) is used contrary to its purpose. Either: (1) analysts using it for harassment or sensitive non-technical content (use-policy violation, server can\'t see content due to E2EE); or (2) malicious insider using it to exfiltrate data via the chat channel.',
    indicators: [
      'Tier-3 abuse flag activity (analysts flagging peer sessions as inappropriate)',
      'Tier-2 or Tier-3 flag indicates personal attacks, harassment, or worse',
      'Peer chat session message counts unusually high for specific analyst pairs (potential exfil channel)',
      'Suspicious file-attachment patterns in peer chat (if attachments are enabled)',
    ],
    quickRef: {
      trigger: 'Tier-2 or Tier-3 peer abuse flag is filed via the Peer Conduct tab, OR audit reveals abuse pattern.',
      firstActions: [
        'Open Peer Conduct tab. Review the flag.',
        'For Tier-2: contact the flagged peer for a conduct discussion. Their identity is revealed to you (the lead) per the policy.',
        'For Tier-3: contact HR with the evidence. Both flagger and flagged identities are revealed for HR investigation.',
        'For data exfiltration suspicion: review the affected analyst\'s chat patterns. Note that E2EE means the server cannot decrypt content; investigation requires endpoint inspection (with appropriate authorization).',
        'If the analyst\'s account is compromised (rather than malicious), follow JWT theft scenario.',
      ],
      escalation: 'Tier-3 flags often warrant HR involvement and may require escalation to legal depending on the content. Follow the org\'s harassment/anti-abuse policies. For data exfiltration: engage security operations.',
    },
    fullRunbook: {
      identification: [
        'For abuse flag: review the flag content and tier. The flagger has provided context.',
        'Cross-reference peer_messages metadata (timestamps, message counts, but not content due to E2EE) for the involved sessions.',
        'For exfil suspicion: examine peer chat patterns for the suspect analyst. High message volume, sessions with non-technical-knowledge peers, sessions outside business hours.',
      ],
      containment: [
        'For Tier-3 abuse: temporarily restrict the flagged peer\'s ability to initiate or accept new sessions while HR investigates.',
        'For exfiltration: disable the analyst\'s account pending investigation.',
        'For both: preserve the chat metadata (peer_sessions, peer_messages timing) for forensic analysis. Note: E2EE prevents content recovery server-side.',
      ],
      eradication: [
        'Follow HR\'s investigation and disciplinary process.',
        'For exfiltration: forensic inspection of the analyst\'s endpoint to determine what was exfiltrated. May require authorization and coordination with org\'s legal team.',
        'If a pattern of abuse is identified across multiple flags, review whether the peer chat use policy needs strengthening.',
      ],
      recovery: [
        'Re-enable the affected accounts after investigation completes (or follow termination/discipline process).',
        'Resume normal peer chat operations.',
      ],
      verification: [
        'Monitor for further flags in the Peer Conduct tab.',
        'For exfiltration: monitor outbound network from the affected endpoint for 14 days.',
      ],
      postIncident: [
        'Document.',
        'Conduct CISM Retros for analysts affected by abuse. Being targeted in the peer-support channel is stressful.',
        'Review whether the peer chat use policy needs strengthening.',
        'Tabletop the scenario in next quarterly TTX.',
      ],
      componentsInvolved: ['Peer Conduct tab', 'Tier-3 abuse flagging', 'peer_sessions', 'peer_messages', 'NaCl box E2EE'],
      relatedScenarios: ['helper_pay_fraud', 'peer_chat_e2ee_key_compromise'],
    },
  },

  {
    id: 'pseudonym_deanonymization_via_correlation',
    category: 'Burnout-Specific Abuse',
    title: 'Pseudonym Deanonymization via Behavioral Correlation',
    summary: 'Pseudonyms protect analyst identity at the database layer. But an attacker with sufficient observation can correlate signals with shift schedules, ticket assignments, and other side-channels to infer pseudonym-to-real-name mappings without ever obtaining the offline mapping file.',
    indicators: [
      'Adversary references analyst real names alongside pseudonym data in extortion or threat communications',
      'Threat hunting identifies adversary correlations',
      'External research or audit identifies correlation pathways',
    ],
    quickRef: {
      trigger: 'External indicator that pseudonyms have been correlated with real identities, OR red-team exercise demonstrates feasibility.',
      firstActions: [
        'Rotate all pseudonyms (Pseudonyms tab). New pseudonym-to-UUID mappings break the existing correlation.',
        'Review what data the adversary used to make correlations. Possible sources: shift schedules, ticket assignment patterns, AC IP addresses, peer chat metadata, audit log entries.',
        'Restrict access to whichever side-channel data the adversary used. For example, if shift schedules in the integration with HR scheduling are visible to too many users, narrow the access.',
        'Notify analysts whose pseudonyms were deanonymized.',
        'Privacy officer notified. Privacy breach disclosure depending on framework.',
      ],
      escalation: 'If correlation was performed by an insider, follow the org\'s insider response. If by an external attacker, treat as broader compromise indicating they have access to multiple data sources.',
    },
    fullRunbook: {
      identification: [
        'Confirm deanonymization via the source indicator. Was it a specific real-name + pseudonym pair revealed in attacker communications? A research finding showing systematic correlation?',
        'Identify correlation pathways. What data, when combined, would deanonymize? Common candidates: shift schedule (when each analyst works) + signal_readings (timestamped) = correlate analyst names to pseudonyms via active periods. Or ticket_assignments (real-name + ticket) + signal_readings (pseudonym + ticket effects) = correlate.',
        'Estimate the deanonymization scope: was it one pseudonym-to-name pair, or systematic across all analysts?',
      ],
      containment: [
        'Rotate all pseudonyms. Fresh assignments break the existing correlations the adversary built.',
        'Restrict access to the side-channel data used. Examples: don\'t expose ticket-to-analyst mappings broadly, restrict shift schedule visibility to need-to-know.',
        'Audit other side-channels: anything that ties identifiable user actions to data attributed to pseudonyms is a correlation risk.',
      ],
      eradication: [
        'Implement correlation-prevention measures: salting timestamps in signal_readings to reduce correlation precision, time-bucketing signals into broader intervals, removing individual-identifiable side-channels from broadly-accessible APIs.',
        'Tighten cross-database joins: just because the lead can see ticket assignments and pseudonymized signals doesn\'t mean those should be joinable in queries available to anyone else.',
      ],
      recovery: [
        'Resume operations with new pseudonyms and tightened correlation prevention.',
        'Verify analysts can still access their own data correctly.',
      ],
      verification: [
        'Red-team exercise: attempt to deanonymize using the same techniques the adversary used. The new pseudonyms + correlation prevention should prevent this.',
        'Run Compliance Scan to verify privacy controls.',
      ],
      postIncident: [
        'Document the correlation pathway.',
        'Privacy breach disclosure if applicable.',
        'Conduct CISM Retros for affected analysts.',
        'Update the threat model: pseudonyms are not enough alone; correlation prevention is part of the privacy commitment.',
        'Add this scenario to the next TTX.',
      ],
      componentsInvolved: ['Pseudonyms tab', 'Pseudonym mapping', 'signal_readings', 'ticket_assignments', 'Shift schedule integration', 'Cross-system correlations'],
      relatedScenarios: ['pseudonym_mapping_leak', 'tier3_data_unauthorized_access'],
    },
  },


  // ── OPERATIONAL FAILURES ───────────────────────────────────────────────────

  {
    id: 'server_crash_ha_degraded',
    category: 'Operational Failures',
    title: 'Server Crash with Degraded HA',
    summary: 'The FireAlive server crashes AND the HA failover fails (passive doesn\'t promote, or both nodes are down). The platform is offline. Tickets revert to fail-open routing in SOAR; the SOC continues defending the network without burnout-aware routing.',
    indicators: [
      'MC reports cannot reach server',
      'AC clients show disconnected status',
      'Health check endpoints return 5xx or timeout',
      'HA passive node also unreachable',
      'Process supervisor logs show server crash and failed restart',
    ],
    quickRef: {
      trigger: 'Server unreachable from MC and ACs simultaneously, AND HA passive does not respond to traffic either.',
      firstActions: [
        'Verify SOAR fail-open routing is active. Tickets should be flowing via SOAR\'s native distribution. If not, manually activate fail-open in SOAR.',
        'Connect to the server host(s) via out-of-band means (SSH, console, IPMI). Determine the failure mode: process crashed and won\'t restart, host crashed, network partition, disk failure, hardware failure.',
        'For process crash: review server logs. Identify the cause. Restart the process.',
        'For host crash: check whether the host is recoverable or needs reprovision. If using HA, attempt to promote the passive (or check why it didn\'t auto-promote).',
        'For both nodes down: this is a serious operational failure. Recovery from backup may be needed. Engage platform engineering.',
      ],
      escalation: 'Multi-hour outage of FireAlive while the SOC continues operating in fail-open is acceptable for short windows. If the outage extends beyond hours, the org\'s burnout protection is suspended for that period — communicate to the team.',
    },
    fullRunbook: {
      identification: [
        'Health check status: server endpoint, HA passive endpoint, MC connectivity, AC connectivity.',
        'Out-of-band access to server host(s): SSH, IPMI, cloud-provider console.',
        'OS-level diagnostics: process status, system logs, disk health, network reachability.',
        'HA-specific: review HA tab\'s last health check log. What did it observe before the active became unreachable?',
      ],
      containment: [
        'Verify SOAR fail-open routing is active. The SOC must keep operating. If fail-open is not active for any reason, manually configure SOAR to distribute tickets without consulting FireAlive.',
        'Notify analysts via out-of-band channel that FireAlive is offline temporarily.',
        'Notify leadership about the operational outage and expected recovery time.',
      ],
      eradication: [
        'For process crash: examine logs to identify root cause. Common: out-of-memory, panic from unhandled exception, killed by OS, segfault from native dependency. Address the cause before restart.',
        'For host crash: check disk and hardware. Reprovision the host if hardware is suspect.',
        'For HA failure: investigate why the passive didn\'t auto-promote. Health-check configuration error, replication lag, network partition, configuration drift between active and passive. Fix the underlying issue.',
        'For both down: identify the common-mode failure. Same cloud provider failure? Same network segment? Same dependency that failed? Address the root cause.',
      ],
      recovery: [
        'Restart server process if recoverable.',
        'For HA: promote passive if it\'s healthy and the active is down. New passive needs to be provisioned eventually.',
        'For both down: restore from backup on a fresh host.',
        'Verify integrity check passes on startup.',
        'Verify clients reconnect.',
        'Deactivate SOAR fail-open routing once burnout-aware routing is restored.',
      ],
      verification: [
        'Run Compromise Scan, Regression Test.',
        'Monitor server health metrics for 24 hours post-recovery.',
        'Verify HA passive is operational and replicating.',
      ],
      postIncident: [
        'Document the crash: cause, time-to-recover, scope of impact.',
        'Calculate downtime metrics. Review against SLAs/SLOs the org has for FireAlive.',
        'Conduct a post-mortem. What can be improved? Better monitoring? Better HA testing? Better operational runbooks?',
        'Conduct CISM Retros for the lead and analysts who experienced the outage.',
      ],
      componentsInvolved: ['Server', 'HA tab', 'SOAR fail-open routing', 'Process supervisor', 'Host infrastructure'],
      relatedScenarios: ['network_partition', 'database_corruption', 'restore_compromise_recovery'],
    },
  },

  {
    id: 'network_partition',
    category: 'Operational Failures',
    title: 'Network Partition (Clients Cannot Reach Server)',
    summary: 'Persistent network failure between MC/AC clients and the FireAlive server. Clients keep their local state and audit logs but cannot sync. Tickets continue flowing via SOAR fail-open routing.',
    indicators: [
      'Multiple AC clients simultaneously report disconnected from server',
      'MC reports cannot reach server',
      'Server appears healthy from its own host\'s perspective',
      'Network route between clients and server is down (traceroute, ping)',
      'Cloud or on-prem network alerts on relevant network segment',
    ],
    quickRef: {
      trigger: 'Multiple clients simultaneously disconnected, server appears healthy, network alerts indicate path failure.',
      firstActions: [
        'Confirm SOAR fail-open routing is active.',
        'Coordinate with network engineering to identify and remediate the network issue.',
        'Notify analysts and lead via out-of-band channel about the outage.',
        'On client side: AC and MC continue local audit logging. They will sync when network is restored.',
        'Monitor for restoration. As clients reconnect, they\'ll backfill their local audit log entries.',
      ],
      escalation: 'If the partition is in a region-wide cloud failure, the org may need broader IR. The SOC continues operating; FireAlive is just degraded.',
    },
    fullRunbook: {
      identification: [
        'Confirm partition: server is reachable from its own host but not from client subnets.',
        'Use traceroute, ping, or cloud-provider tools to identify the failed network segment.',
        'Verify cloud provider status if FireAlive is cloud-hosted.',
      ],
      containment: [
        'SOAR fail-open routing is the containment for ticket distribution.',
        'Coordinate with network engineering for repair.',
        'Notify users via out-of-band.',
      ],
      eradication: [
        'Network engineering repairs the network path.',
        'No FireAlive-specific eradication needed beyond verifying the platform is healthy after partition.',
      ],
      recovery: [
        'As partition heals, clients automatically reconnect.',
        'Local audit logs accumulated during partition are pushed to server. Hash chain may show a gap during the partition; that gap is documented as partition (not tampering).',
        'Burnout-aware routing resumes.',
      ],
      verification: [
        'All clients reconnect successfully.',
        'Audit log shows the partition gap with audit-resume entry (per audit chain gap scenario).',
        'Run Regression Test.',
      ],
      postIncident: [
        'Document the partition: duration, scope, repair steps.',
        'Review whether the network architecture has single points of failure that should be addressed.',
        'Consider regional redundancy if a regional outage caused this.',
      ],
      componentsInvolved: ['Network infrastructure', 'Server', 'Clients (MC, AC)', 'SOAR fail-open routing', 'Audit log chain'],
      relatedScenarios: ['server_crash_ha_degraded', 'audit_log_chain_gap'],
    },
  },

  {
    id: 'mass_ac_reprovision_needed',
    category: 'Operational Failures',
    title: 'Mass AC Reprovisioning Needed',
    summary: 'Compromise Scan reveals widespread AC compromise. Many or all analyst clients need to be wiped and reprovisioned without disrupting ongoing SOC operations.',
    indicators: [
      'Compromise Scan flags 10+ ACs simultaneously',
      'Mass binary tampering detected',
      'Tripwire fires repeatedly with multiple ACs implicated each time',
      'Threat hunt identifies infection across many endpoints',
    ],
    quickRef: {
      trigger: 'Compromise Scan flags many ACs, OR mass infection detected externally.',
      firstActions: [
        'Activate SOAR fail-open routing (so the team continues to receive tickets even as ACs go offline).',
        'Pause burnout-aware routing entirely until reprovision completes.',
        'Identify scope: which ACs, what compromise indicators, what root cause is suspected.',
        'Coordinate with the analysts: their workstations are affected. They may need to switch to alternate equipment temporarily.',
        'Begin reprovision in batches: don\'t reprovision the entire team at once (some need to be available to handle tickets via fail-open).',
      ],
      escalation: 'If the root cause is a network-segment compromise or supply-chain attack, broader IR is needed. Engage security operations.',
    },
    fullRunbook: {
      identification: [
        'Compromise Scan results identify the affected ACs.',
        'Examine each AC\'s compromise indicators: which checks failed, what was the failure pattern.',
        'Identify common root cause: same network segment, same time of compromise, same workstation image, same software dependency.',
      ],
      containment: [
        'SOAR fail-open active.',
        'Pause burnout-aware routing.',
        'Coordinate with affected analysts about temporary workflow.',
        'Quarantine affected ACs from the network where possible. They shouldn\'t communicate with FireAlive or the SOC tooling until reprovisioned.',
      ],
      eradication: [
        'For each affected AC: tear down (wipe), reinstall fresh from verified-clean source, External Restore for analyst-specific configuration.',
        'Address the root cause: if network compromise, secure the network. If workstation image compromise, refresh the image. If dependency compromise, address the supply chain.',
        'Audit other endpoints in the org for similar compromise indicators.',
      ],
      recovery: [
        'Each reprovisioned AC enrolls fresh, analyst re-authenticates with IAM + MFA.',
        'New baselines must re-establish over the fixed ~90-day establishment window before burnout-aware routing resumes for that analyst.',
        'After all baselines are established, resume burnout-aware routing.',
      ],
      verification: [
        'Compromise Scan on each reprovisioned AC: should pass.',
        'Run Regression Test.',
        'Monitor for compromise indicators going forward.',
      ],
      postIncident: [
        'Document the mass-compromise event.',
        'Conduct CISM Retros for affected analysts. Mass workstation compromise is a significant stressor.',
        'Review the org\'s endpoint security posture: did it allow this? What needs to change?',
        'Tabletop the scenario in next quarterly TTX.',
      ],
      componentsInvolved: ['Compromise Scan tab', 'AC clients', 'Client Provisioning', 'Restore feature', 'SOAR fail-open routing', 'Burnout Engine baselines'],
      relatedScenarios: ['false_signal_injection_mass_tripwire', 'binary_tampering', 'config_drift_unauthorized_changes'],
    },
  },

  {
    id: 'gd_compromise',
    category: 'Operational Failures',
    title: 'Global Dashboard Failure or Compromise',
    summary: 'The Global Dashboard cannot reach regional MCs (operational failure), OR the GD itself is compromised (security incident). CISO loses cross-region visibility either way.',
    indicators: [
      'GD shows region-disconnect alerts',
      'GD shows aggregate data inconsistent with regional MC values',
      'GD-specific compromise indicators (binary tampering, integrity check failures on GD server)',
      'Unauthorized access to GD',
    ],
    quickRef: {
      trigger: 'GD-MC connection failures, OR GD shows inconsistent regional data, OR GD-specific compromise indicators.',
      firstActions: [
        'Determine: is this an operational failure or a compromise?',
        'For operational failure: check network paths between GD and regional MCs. Coordinate with network team.',
        'For compromise: stop the GD immediately. Snapshot for forensics. Reprovision per the Binary Tampering or Server Crash workflow.',
        'In either case: regional MCs continue operating normally. The GD is purely aggregation; loss of GD doesn\'t affect SOC operations.',
        'Notify CISO and other GD users that visibility is temporarily reduced.',
      ],
      escalation: 'If the GD compromise is part of a broader attack on the org\'s SOC monitoring infrastructure, treat as broader incident.',
    },
    fullRunbook: {
      identification: [
        'GD-side health checks and connectivity tests.',
        'For compromise: GD server\'s integrity check, runtime monitor alerts, audit log review.',
        'For operational: network connectivity tests between GD and each regional MC.',
      ],
      containment: [
        'For operational failure: no FireAlive containment needed; coordinate network repair.',
        'For compromise: stop GD server. Snapshot. Disconnect from network.',
      ],
      eradication: [
        'For operational: network repair.',
        'For compromise: reprovision the GD server, restore from clean backup, investigate root cause.',
      ],
      recovery: [
        'GD comes back online.',
        'Regional MCs resume pushing data.',
        'CISO regains visibility.',
      ],
      verification: [
        'Compromise Scan on GD server.',
        'Regression Test.',
        'Verify aggregate data on GD matches regional MC values.',
      ],
      postIncident: [
        'Document.',
        'Tabletop the scenario.',
      ],
      componentsInvolved: ['Global Dashboard', 'GD Server', 'MC-to-GD push pipeline', 'Network infrastructure'],
      relatedScenarios: ['mc_gd_pipeline_tampering', 'server_crash_ha_degraded'],
    },
  },

  {
    id: 'geo_fence_violation',
    category: 'Operational Failures',
    title: 'Geo-Fencing Violation',
    summary: 'An analyst client logs in from an unexpected country. Could be legitimate travel without prior notification (operational), or stolen credentials being used remotely (security incident).',
    indicators: [
      'Geo-Fencing tab shows an alert: analyst-X authenticated from country-Y, expected country-Z',
      'auth_log shows source IP geo-resolved to unexpected country',
      'Login event combined with timestamp inconsistent with the analyst\'s known travel',
    ],
    quickRef: {
      trigger: 'Geo-Fencing alert fires for an analyst.',
      firstActions: [
        'Contact the analyst directly via known-good channel (their phone, in-person, etc., NOT via FireAlive). Verify whether they are actually in that country.',
        'If yes (legitimate travel): adjust the analyst\'s expected geo in the Data Sovereignty tab. Allow the login.',
        'If no (credentials stolen or compromised): immediately revoke the analyst\'s session, lock the account, treat as JWT theft scenario.',
        'Investigate: how did the credential leak? Is the analyst\'s workstation compromised? Are they being phished?',
      ],
      escalation: 'If multiple geo-fence violations occur simultaneously, attacker has broader credential access. Treat as bulk compromise.',
    },
    fullRunbook: {
      identification: [
        'Geo-fence alert provides: analyst, expected country, observed country, source IP, timestamp.',
        'Reverse-engineer: was this expected? Has the analyst notified anyone of travel?',
      ],
      containment: [
        'Verify legitimacy via out-of-band contact with analyst.',
        'Lock account if illegitimate.',
        'Revoke active sessions.',
      ],
      eradication: [
        'For illegitimate: full JWT theft scenario response.',
        'For legitimate: update geo configuration and document the change.',
      ],
      recovery: [
        'For legitimate: analyst continues working.',
        'For illegitimate: per JWT theft recovery (certificate re-issue, MFA re-enroll, etc.).',
      ],
      verification: [
        'For legitimate: monitor logins for anomalies during the travel period.',
        'For illegitimate: monitor for further compromise indicators.',
      ],
      postIncident: [
        'Document.',
        'For legitimate: review whether the org needs a better travel-notification process so analysts can pre-register travel locations.',
        'For illegitimate: full incident documentation, CISM Retro, threat model update.',
      ],
      componentsInvolved: ['Geo-Fencing / Data Sovereignty', 'Auth log', 'Geo-IP resolution'],
      relatedScenarios: ['jwt_token_theft'],
    },
  },

];

module.exports = {
  SCENARIOS,
  // getScenarioById, listScenarios, and listCategories accept an optional
  // enabledFeatures Set. Scenarios carrying a feature_required field are
  // filtered out when the named feature is not in the set. Used to gate
  // scenarios that reference tables shipped by later phases (e.g. the
  // helper_pay_fraud scenario references helper_points_ledger and
  // peer_session_ratings, which are added in F5). Default empty set
  // preserves the pre-F5 behavior of hiding any feature-gated scenario.
  getScenarioById: (id, enabledFeatures = new Set()) =>
    SCENARIOS.find(s =>
      s.id === id &&
      !s.deprecated &&
      (!s.feature_required || enabledFeatures.has(s.feature_required))
    ),
  listScenarios: (enabledFeatures = new Set()) =>
    SCENARIOS
      .filter(s =>
        !s.deprecated &&
        (!s.feature_required || enabledFeatures.has(s.feature_required))
      )
      .map(s => ({
        id: s.id,
        category: s.category,
        title: s.title,
        summary: s.summary,
      })),
  listCategories: (enabledFeatures = new Set()) => {
    const cats = new Set();
    for (const s of SCENARIOS) {
      if (s.deprecated) continue;
      if (s.feature_required && !enabledFeatures.has(s.feature_required)) continue;
      cats.add(s.category);
    }
    return Array.from(cats);
  },
};
