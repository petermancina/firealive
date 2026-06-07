# Integrations Privacy Contract — SOAR, Ticketing, Routing Webhook

This document covers the privacy contracts of the FireAlive-to-external integrations: three introduced or finalized in R3j (v1.0.36) — the SOAR routing-variable publication, the ticketing-system read channel, and the SOAR-to-FireAlive routing-decisions webhook — plus the ticketing activity-events feed added in B5d1 (v1.0.56). Each is a distinct data-flow direction with its own contract; conflating them blurs the security boundary.

This is **not a general privacy overview** of the FireAlive platform. For the Tier-1 / Tier-3 / pseudonym architecture see `FEATURE-GUIDE.md` and `Security.md`. For backup data residency see `docs/backup-destinations-eu.md`. This document covers only the integration surfaces R3j ships.

This is **not legal advice**. Compliance posture depends on your sector, member state, and DPA's interpretation. Talk to your DPO before relying on any specific contract here for a regulated-data workflow.

## The data flows in scope

```
                  outbound: routing variables
       FireAlive  ──────────────────────────────────────▶  SOAR
                  GET /api/routing/variables
                  (api-key + routing:read scope)


                  inbound: routing decisions
       FireAlive  ◀──────────────────────────────────────  SOAR
                  POST /api/routing/soar-events
                  (api-key + routing:events scope)


                  outbound: read-only metadata pulls
       FireAlive  ──────────────────────────────────────▶  Ticketing System
                  Live ticketing-API integration deferred
                  to R3k or later; the read-only invariant
                  is established server-side in R3j.


                  inbound: per-action push (activity events)
       FireAlive  ◀──────────────────────────────────────  Ticketing System
                  POST /api/integrations/ticketing/
                       activity-events
                  (api-key + ticketing:events scope)
```

The SOAR and ticketing systems are external; once data crosses the boundary, FireAlive's privacy controls do not apply. These contracts are designed to minimize what crosses the boundary in the first place.

## Contract 1: SOAR routing-variable publication

The SOAR polls `GET /api/routing/variables` on its own cadence (typical: 30–60 seconds). FireAlive returns the current state the SOAR needs to make routing decisions within its own playbook logic.

**Response shape:**

```
{
  fetched_at: <ISO timestamp>,
  panic_mode: <boolean>,
  panic_deactivated_at: <ISO timestamp or null>,
  routing_enabled: <boolean>,
  analysts: [
    {
      pseudonym: <stable pseudonym string>,
      tier: <integer 1-3>,
      shift: <"day" | "swing" | "night">,
      available: <boolean>,
      capacity_score: <integer 0-100>,
      last_heartbeat: <ISO timestamp>,
      complexity_cap: <integer 1-5>,
      complexity_cap_is_override: <boolean>,
      complexity_cap_override_reason: <string or null>
    },
    ...
  ],
  soar_variables: {
    analyst_capacity: ...,
    complexity_cap: ...,
    equity_weights: ...,
    skill_matrix: ...,
    burnout_risk_tier: ...,
    shift_handoff: ...
  }
}
```

### Privacy invariants enforced at the server

1. **Pseudonym, not user.id.** Every analyst-keyed value in the response uses `pseudonym` as the identifier. `user.id` (the database primary key) is never serialized into the response. This is enforced in the SQL query that backs `GET /api/routing/variables` (`server/routes/routing.js`) by selecting only `u.pseudonym` from the `users` table; `u.id` does not appear in the SELECT clause.

2. **No analyst names or emails.** The response includes `pseudonym`, `tier`, `shift`, `available`, `capacity_score`, `last_heartbeat`, and routing-cap context. It does NOT include `name`, `email`, `mfa_enrollment_required`, `totp_recovery_codes_*`, `last_login`, or any other column from the users table beyond what's enumerated above.

3. **Inactive analysts are filtered out.** The query has `WHERE u.role = 'analyst' AND u.active = 1`. Analysts offboarded via the MC offboarding flow (`active = 0`) never appear in the SOAR's view, even if `soar_routing_events` rows still reference their `user.id` historically.

4. **No burnout-tier per analyst.** The response includes `capacity_score` (a 0–100 workload score derived from current ticket assignments) but does NOT include any individual burnout indicator. Burnout-tier data flows through the `burnout_risk_tier` SOAR variable as a *team-level aggregate* — values are `"healthy"`, `"watch"`, `"stressed"`, or `"critical"` for the whole team, never per-analyst.

### What the SOAR is contractually allowed to do with this data

The SOAR uses the response in its own playbook logic to route tickets. The contract is one-way for variables: FireAlive publishes, SOAR consumes. FireAlive does NOT distribute tickets; the SOAR retains exclusive control over its own routing decisions.

Operators configuring the SOAR side should ensure their SOAR's data-retention policy for this polled data is no longer than operationally necessary. A SOAR that archives every poll response for years effectively creates a long-tail breach surface that FireAlive's own data-retention controls cannot reach.

### Pseudonym rotation

Pseudonyms are rotated via the MC's Pseudonyms tab. Rotation invalidates the old pseudonym at the FireAlive side — subsequent SOAR webhook callbacks using the old pseudonym (Contract 2 below) return HTTP 404 with a hint to re-poll. The rotation itself does NOT cascade backwards into historical `soar_routing_events` rows: the `analyst_pseudonym` column there stores the pseudonym as it was at event-receipt time, so historical audit trails remain valid for the period they describe.

## Contract 2: SOAR-to-FireAlive routing-decisions webhook

After the SOAR makes a routing decision, it posts the decision back to FireAlive via `POST /api/routing/soar-events`. FireAlive persists each event into the `soar_routing_events` table and uses it to update `ticket_assignments` (closing the capacity-feedback loop into `signal-collector.js`).

**Request shape (required fields in bold):**

```
{
  "event_type": "ticket_assigned" | "ticket_reassigned" | "ticket_closed",    [REQUIRED]
  "ticket_id": <string>,                                                       [REQUIRED]
  "analyst_pseudonym": <string>,                                               [REQUIRED]
  "assigned_at": <ISO timestamp>,                                              [REQUIRED]
  "soar_source": <string, optional but recommended>,
  "external_event_id": <string, optional but strongly recommended>,
  "priority": <string, optional>,
  "complexity": <integer 1-5, optional>,
  "reason": <string, optional>,
  "soar_metadata": <object, optional, stored verbatim>
}
```

### Privacy invariants enforced at the server

1. **Pseudonym is the analyst key on the request.** The SOAR sends `analyst_pseudonym` (the same string the SOAR received in Contract 1's `analysts[].pseudonym`). The webhook handler resolves the pseudonym to `user.id` server-side via `SELECT id FROM users WHERE pseudonym = ?`; this resolved `user.id` is stored in the local `soar_routing_events.analyst_id` column but is never echoed back to the SOAR in the response.

2. **Audit log uses pseudonym, not user.id.** The webhook handler writes a `SOAR_EVENT_RECEIVED` audit row with the detail string `event_type=<type> ticket_id=<id> analyst_pseudonym=<pseudonym> source=<source>`. The audit trail preserves the SOAR-side anonymity contract: even an admin running an audit-log query for routing activity sees only the pseudonym, not the user's name. To deanonymize an audit row, a separate `SELECT name FROM users WHERE id = (SELECT analyst_id FROM soar_routing_events WHERE id = ?)` is required, which itself is audit-logged.

3. **`soar_metadata` is stored verbatim, not parsed.** FireAlive does not interpret the contents of the `soar_metadata` blob. SOAR vendors use this field for vendor-specific context (playbook IDs, enrichment results, severity scoring paths). FireAlive's contract is to preserve it for the operator's later use; FireAlive itself never reads its contents at runtime. This means a SOAR that accidentally puts a PII-laden blob into `soar_metadata` does so at its own discretion — FireAlive will store it as supplied. Operators are responsible for ensuring the SOAR's webhook configuration excludes sensitive fields the FireAlive deployment does not have a basis to store.

4. **Idempotency without de-duplication of the analyst identifier.** The composite `(soar_source, external_event_id)` UNIQUE constraint on `soar_routing_events` lets a SOAR retry the same webhook safely (FireAlive returns 200 `{idempotent: true}` rather than double-counting). This does NOT de-duplicate by analyst — the same analyst may receive many tickets in rapid succession, each producing a distinct event row.

### Scope creep boundary

The webhook receiver in R3j accepts only `event_type` values `ticket_assigned`, `ticket_reassigned`, `ticket_closed`. A SOAR that wants to report richer events (analyst marked-as-busy, ticket-priority-changed-by-analyst, automation-engaged) must either (a) wait for a future phase that adds those event types to the CHECK constraint, or (b) use the optional `reason` and `soar_metadata` fields to encode the additional context without inventing new event_type values. The CHECK constraint is the schema-level guarantee that scope creep doesn't silently land.

## Contract 3: Ticketing read-only invariant

The ticketing integration (`PUT /api/integrations/ticketing`) is configured by the lead via the MC's SOAR & Ticketing tab. R3j enforces a single invariant: the stored configuration always has `readOnly: true`, regardless of what the client supplies.

### Server-side enforcement

In `server/routes/integrations.js`, the `normalizeConfigForType` helper runs before encryption on every PUT:

```
if (type === 'ticketing') {
  normalized.readOnly = true;
  if (config.readOnly !== true) auditMarkers.push('READ-ONLY invariant enforced');
}
```

The `INTEGRATION_CONFIGURED` audit log entry includes the marker string `(READ-ONLY invariant enforced)` whenever the client supplied anything other than `true` (or omitted the field). An operator examining the audit log can see exactly when the server overrode a client-supplied value.

### Why server-side, not UI-side

The MC's SOAR & Ticketing tab does not expose a `readOnly` toggle. The only way to send `readOnly: false` to the server is via direct API call (a custom client or a misconfigured automation). The server-side enforcement is the load-bearing guarantee: even an attacker who bypasses the UI cannot reconfigure ticketing for write access.

### What read-only means in scope

The ticketing integration in R3j v1.0.36 is limited to read patterns:

- `GET /api/integrations/ticketing/queue` returns aggregate queue metadata (depth, average priority, last sync) — mock-shape in v1.0.36, real per-platform adapters deferred.

The integration does NOT expose a write endpoint at all in R3j. There is no `POST /api/integrations/ticketing/assign-ticket`, no `PUT /api/integrations/ticketing/ticket/:id`, no `DELETE`. The combination of (a) server-side `readOnly: true` enforcement in the stored config and (b) no write endpoints in the route file produces a defense-in-depth posture: even if a future commit accidentally introduced a write endpoint, the stored config's `readOnly: true` flag would be the second-line check that the new endpoint should consult before mutating ticketing state.

Operators using the read-only invariant for compliance evidence (HIPAA minimum-necessary, GDPR purpose limitation) should confirm in their per-deployment audit that the `readOnly: true` flag is present in the decrypted ticketing config. The flag's presence is sufficient evidence that R3j-or-later FireAlive is enforcing the contract.

## Contract 4: Ticketing activity-events push (burnout-signal feed)

The activity-events feed was added in B5d1 (v1.0.56) to give FireAlive's burnout-signal collector real operational inputs. After an analyst acts on a ticket in the external ticketing/SOAR platform, the platform pushes that action to FireAlive via `POST /api/integrations/ticketing/activity-events`. FireAlive persists each action as a `ticket_actions` row; the per-analyst behavioral signals (investigation time, dismiss rate, ticket-note quality, escalation rate) are computed from that table. This is the inbound sibling of Contract 3's read-only ticketing channel — Contract 3 governs what FireAlive may read from the ticketing system, Contract 4 governs what the ticketing system reports back about analyst actions. The two are loosely coupled: they join only on `ticket_id`, and this endpoint never writes `ticket_assignments` (the SOAR routing rail owned by Contract 2).

**Auth.** api-key with the `ticketing:events` scope ONLY. A JWT is rejected, exactly like the Contract 2 webhook (`POST /api/routing/soar-events`). The endpoint is mounted ahead of `/api/integrations`, so it is deliberately NOT behind the configuration-lock gate that guards the integration-config routes: a machine-to-machine feed must keep accepting events during a config-lock window rather than dropping burnout data. The handler enforces api-key + scope itself and does not rely on the mount's role list.

**Request shape (required fields in bold):**

```
{
  "action_type": "triage" | "comment" | "close" | "escalate" | "dismiss" | "reassign",   [REQUIRED]
  "ticket_id": <string>,                                                                  [REQUIRED]
  "analyst_pseudonym": <string>,                                                          [REQUIRED]
  "external_action_id": <string>,                                                         [REQUIRED]
  "occurred_at": <ISO timestamp, optional; stored as the action's created_at>,
  "category": <string, optional>,
  "response_time_min": <number, optional>,
  "notes": <string, optional>
}
```

### Privacy invariants enforced at the server

1. **Pseudonym is the analyst key on the request.** The platform sends `analyst_pseudonym` (the same string it received in Contract 1's `analysts[].pseudonym`). The handler resolves it to `user.id` server-side via `SELECT id FROM users WHERE pseudonym = ? AND active = 1`; an unknown or stale pseudonym (rotated since the platform last polled) returns HTTP 404 with a hint to re-poll `GET /api/routing/variables`. The resolved `user.id` is stored on the local `ticket_actions` row but is never echoed back, and the handler never accepts an analyst id from the request body — the pseudonym is the only analyst key it honors.

2. **Audit log uses pseudonym, and never the note text.** The handler writes an `ACTIVITY_EVENT_RECEIVED` audit row whose detail carries `action_type`, `ticket_id`, `analyst_pseudonym`, and `external_action_id` — never the contents of `notes`. Note text exists only to feed the analyst's own on-device ticket-note-quality scoring; it is not surfaced to management and not written to the audit trail.

3. **`dismiss` is a distinct action type, not a flavor of `close`.** The accepted `action_type` values are `triage`, `comment`, `close`, `escalate`, `dismiss`, and `reassign`. Keeping `dismiss` separate from `close` is what lets the false-positive dismiss rate and the notes-based ticket-note quality remain distinct signals, rather than conflating "closed with a resolution" with "dismissed as a false positive."

4. **Idempotent on `external_action_id`, not de-duplicated by analyst.** `ticket_actions` carries a partial UNIQUE index on `external_action_id` (`WHERE external_action_id IS NOT NULL`), so a re-delivered event is a no-op: the handler uses `INSERT OR IGNORE`, returning 200 `{idempotent: true}` when the row already exists and 201 when it is newly stored. This does NOT de-duplicate by analyst — one analyst performs many actions, each a distinct event row with its own `external_action_id`.

### What the behavioral signals do with this data

The activity feed is the source of the four behavioral signals, but those signals never leave the analyst in identifiable form: they are computed, sealed to the analyst's own key, and stored de-identified for any team-level view, with no server path that decrypts a named analyst's behavioral value. The operational pressure signals derived alongside them — including `shift_overtime`, which combines the roster's scheduled hours with actual after-hours activity seen in `ticket_actions` — are lead-visible by design because they drive routing capacity, but they are workload measures, not the sealed behavioral set. See `FEATURE-GUIDE.md` for the analyst-facing "My Signals" view and the pressure/behavior split.

## Auth surface matrix

The endpoints introduced or modified in R3j sit at distinct auth boundaries. This table summarizes who can call what.

```
Endpoint                                Path                                    Auth
------------------------------------    ----------------------------------      ------------------------------------
SOAR polling (read)                     GET  /api/routing/variables             api-key + routing:read OR lead/admin JWT
SOAR webhook (write)                    POST /api/routing/soar-events           api-key + routing:events ONLY
Routing variables (read)                GET  /api/routing/soar                  lead/admin JWT
Routing variables (write)               PUT  /api/routing/soar                  lead/admin JWT
Routing-enabled toggle (read)           GET  /api/routing/enabled               api-key + routing:read OR lead/admin JWT
Routing-enabled toggle (write)          PUT  /api/routing/enabled               lead/admin JWT ONLY
Routing caps (read)                     GET  /api/routing                       lead/admin JWT
Routing caps (write per analyst)        PUT  /api/routing/:analystId            lead/admin JWT
Panic mode (engage/restore)             POST /api/routing/panic                 lead/admin JWT
Panic mode (read, lead-facing)          GET  /api/routing/panic                 lead/admin JWT
Panic mode (read, AC-accessible)        GET  /api/status/panic                  analyst / lead / admin JWT
Integrations list                       GET  /api/integrations                  admin JWT
SOAR / ticketing config (read)          GET  /api/integrations/:type            admin JWT (sensitive fields redacted)
SOAR / ticketing config (write)         PUT  /api/integrations/:type            admin JWT (ticketing readOnly enforced)
Ticketing queue metadata                GET  /api/integrations/ticketing/queue  admin JWT (mock shape in v1.0.36)
```

### Three design choices the matrix encodes

1. **routing:events is distinct from routing:write.** A SOAR vendor needs to *post events back to FireAlive*, but should NOT be able to mutate FireAlive's published SOAR variables (which would let the SOAR silently change its own routing inputs). Splitting the scopes (C3) enforces this in the api-keys table: an operator provisions a key with `routing:read` (polling) and `routing:events` (webhook) but withholds `routing:write`.

2. **/api/status/panic is a sibling of /api/system, not /api/routing.** The AC needs to read panic state but runs under the analyst role; the rest of `/api/routing/*` is intentionally lead/admin only. Loosening `/api/routing` to include analyst would expose panic POST, SOAR variable mutations, equity analysis, and per-analyst cap PUT to analyst tokens — a much wider blast radius than the AC needs. The dedicated `/api/status` mount in C12 keeps the AC's read access surgically narrow.

3. **routing_enabled mutation requires JWT, not api-key.** The silent-pause toggle is a config-mutation decision (a lead choosing to pause variable publishing for maintenance). A key with `routing:read` scope should not be able to silently pause its own variable feed. `PUT /api/routing/enabled` explicitly rejects api-key auth (`if (req.user.apiKey) return 403`) even when the key carries a scope that would otherwise grant read access.

## What's NOT in this document

This document covers the R3j integration contracts. Related-but-separate topics live elsewhere:

- **Tier-1 / Tier-3 / pseudonym fundamentals.** See `FEATURE-GUIDE.md` (Tier-3 Architecture section) and `Security.md`.
- **Backup data residency, EU sovereignty, Schrems II posture.** See `docs/backup-destinations-eu.md`.
- **Two-person restore approval gate.** See `docs/two-person-restore.md`.
- **AI/ML provider routing and prompt residency.** Covered in the AI/ML Integrations tab in the MC.
- **IAM federation, SAML, OIDC, LDAP.** Covered in the IAM tab and `Security.md`.
- **Peer messaging, peer board, ephemeral encryption.** Covered in the Peer Config tab.

If a privacy concern around an integration is not addressed here or in one of the above documents, file an issue against the FireAlive repo with the surface name and the concrete scenario. R3 phases continue to extend integration scope; future-phase contracts will be documented as they ship.
