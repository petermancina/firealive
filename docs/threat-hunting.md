# Threat-Hunting Feed

Operator runbook for the threat-hunting integration: a read-only, inbound feed
that lets your own external security tools (XDR, ATP, Next-Gen AV, MSP scanners)
pull FireAlive's operational security telemetry for correlation in their own
consoles. It is the counterpart to the outbound SIEM/SOAR push described in
[`integrations-privacy.md`](./integrations-privacy.md): there FireAlive sends
events out; here authorized tools pull a curated, pseudonymous slice in.

This document describes shipped behavior. It is written for SOC administrators
and team leads operating the Regional Server and Management Console (MC). The
feature lives on the Regional Server only; the Global Dashboard is out of scope.

## What the feed is, and is not

FireAlive is the **monitored asset** here. It never dials out to a threat-hunting
platform. Authorized consumers connect *inbound* over mutual TLS, present a
bearer token, and pull from a fixed set of endpoints. Every pull is gated and
logged.

- **It is** a read-only view of FireAlive's *own* security telemetry —
  authentication events, sessions, the audit trail, and integrity findings —
  rendered in the consumer's preferred format.
- **It is not** access to analyst-private data. Records are pseudonymous and
  carry no burnout, wellbeing, or Tier-3 signals (see Privacy guarantees below).
- **It is not** a scanner of your cloud deployment — that is the separate
  cloud-vulnerability authorization feature.
- **It is not** a push integration — SIEM/SOAR delivery is configured elsewhere.

## The four data domains

The feed exposes four domains, each projected from a single source table and
paginated by an opaque cursor:

- **`auth_events`** — authentication successes and failures (from the auth log).
- **`sessions`** — session lifecycle records. The refresh-token hash is never
  exposed; the session identifier is itself pseudonymized.
- **`audit_trail`** — administrative and security audit events. The raw CEF
  message is not carried; the structured fields are.
- **`integrity`** — client compromise-scan results (clean / warning / fail /
  inconclusive / unreachable) with the signature-verification flag.

A separate **summary** endpoint returns actor-free aggregates (active and total
sessions, authentication and audit event counts over 24h / 7d) plus compromise
indicators (recent self-scan status distribution, active tamper lockouts). The
summary is the only place "resource consumption" style metrics are served, and
they are aggregate counts — never per-analyst.

The burnout / pressure store (`analyst_metrics_deidentified`) has **no
collector**. There is no code path by which it can reach the feed, in any
format, under any query. This is enforced structurally and asserted by the
security regression suite.

## Privacy guarantees

Three mechanisms keep identity and wellbeing data out of the feed, each failing
closed:

1. **Re-pseudonymization.** Any actor identifier is replaced with an HMAC-derived
   pseudonym (`analyst-` + a truncated MAC) keyed by a per-deployment secret. The
   pseudonym is stable within the deployment and irreversible without the secret.
   Different field namespaces (for example session references) produce different
   pseudonyms, so identifiers cannot be correlated across domains by value.
2. **Fail-closed projection.** Each domain row is filtered through an explicit
   allow-list. Only allow-listed fields are read; anything else is dropped. An
   identity-source field (user id, username, and the like) is dropped unless it
   is explicitly marked for pseudonymization.
3. **Hard deny-list.** Regardless of the allow-list, any field whose name matches
   the deny vocabulary — burnout, wellbeing, wellness, morale, stress, fatigue,
   sentiment, mood, tier-3, plus secrets (passwords, token hashes, private keys,
   recovery material) and direct PII (real name, email, phone, SSN) — is dropped.

The privacy model is shared with the rest of the integration surface; see
[`integrations-privacy.md`](./integrations-privacy.md) for the system-wide view.

## The three-factor access gate

Every request to the native feed and the TAXII server passes through a single
gate that enforces three independent factors and fails closed on each:

1. **Mutual-TLS client certificate.** The consumer presents a certificate issued
   by FireAlive's internal CA (see
   [`iam-and-authentication.md`](./iam-and-authentication.md)). The gate verifies
   the full chain and validity window, requires the threat-hunting consumer
   organizational unit, confirms the certificate was issued by this deployment
   and not revoked, and matches its fingerprint to a registered authorization.
2. **Bearer token.** A per-consumer token, compared in constant time against a
   salted hash. The token is stored only as a hash and is never retrievable after
   issuance.
3. **Source-IP allow-list.** The request's source IP must fall within the
   authorization's allow-listed addresses or CIDR ranges.

A failure on any factor returns a generic rejection — the response does not
reveal *which* factor failed, so it cannot be used as an oracle. Internally the
precise outcome is recorded in the access log (see below). Disabling or revoking
an authorization stops its token *and* revokes its certificate.

## Authorizing a consumer

All consumer management is in the MC, on the **Threat Hunting** tab, and is
restricted to administrators behind the configuration-lock chokepoint.

1. **Enable the category in policy.** In the per-category section, enable the
   consumer class you intend to authorize (XDR, ATP, Next-Gen AV, or MSP).
2. **Authorize the consumer.** Under *Feed Consumer Authorizations*, choose
   **+ Authorize Consumer** and provide:
   - **Consumer type** — one of `xdr`, `atp`, `ngav`, `msp` (a closed set; there
     is no free-form custom type).
   - **Display name** — a human label, e.g. `Cortex XDR (prod)`.
   - **Source IP allow-list** — one or more IPs / CIDRs.
   - **Default output format** — `json`, `cef`, `ocsf`, or `stix`.
3. **Capture the credentials — shown once.** On creation the MC displays four
   secrets that are never retrievable again:
   - the **bearer token**,
   - the **client certificate** (PEM),
   - the **client private key** (PEM),
   - the **FireAlive CA certificate** (PEM), needed to trust the server.

   Copy all four into the consumer's configuration before dismissing the panel.
   The token and key are stored only as hashes / not at all.

To rotate credentials, revoke the authorization and create a new one; there is
deliberately no in-place token or certificate rotation. Disable temporarily
suspends access without revoking the certificate; revoke is permanent.

## Output dialects

A single internal event model is rendered into four interchangeable formats. The
consumer's default format applies unless a request overrides it.

- **`json`** — a native FireAlive envelope (`firealive.threat-hunting.events`).
- **`cef`** — one CEF record per event, suitable for ArcSight and syslog
  collectors.
- **`ocsf`** — OCSF 1.1.0 (Authentication, API Activity, and Detection Finding
  classes).
- **`stix`** — a STIX 2.1 bundle of observed-data objects with deterministic
  observable identifiers; this is what the TAXII server serves.

## Pulling the feed

### Native feed

Mounted at `/api/threat-hunting-feed`, behind the gate:

- `GET /domains` — lists the available domains, the supported formats, and the
  consumer's default format.
- `GET /summary` — the actor-free aggregate summary.
- `GET /:domain` — a page of events for one domain.

Query parameters on `/:domain`: `format` (override the default), `limit`
(positive integer, clamped to a server maximum), `since` / `until` (timestamp
bounds), and `cursor` (opaque pagination token). Invalid parameters are rejected
before any database read. The response carries `has_more` and `next_cursor` for
forward pagination.

```
curl --cert consumer.crt --key consumer.key --cacert firealive-ca.crt \
  -H "Authorization: Bearer <token>" \
  "https://<regional-server>/api/threat-hunting-feed/auth_events?format=ocsf&limit=100"
```

### TAXII 2.1

Mounted at `/taxii2`, behind the gate, for STIX 2.1 clients. The discovery
document is the entry point; the single API root is `feed`.

- `GET /taxii2/` — discovery (advertises the API root).
- `GET /taxii2/feed` — API-root information.
- `GET /taxii2/feed/collections` — one collection per domain.
- `GET /taxii2/feed/collections/{id}/objects` — the STIX bundle for that domain.
- `GET /taxii2/feed/collections/{id}/manifest` — the object manifest.

Responses use the TAXII (`application/taxii+json;version=2.1`) and STIX
(`application/stix+json;version=2.1`) media types. The same mutual-TLS
certificate, bearer token, and source-IP allow-list apply.

## The feed access log

Every request that reaches the gate is recorded in an append-only,
tamper-evident log, built on the same per-row hash chain as the audit log
(see [`audit-log-integrity.md`](./audit-log-integrity.md)). Database triggers
reject `UPDATE` and `DELETE`, and each row binds to its predecessor by hash, so
any edit, deletion, or reorder breaks the chain at the first affected row.

Each entry records the outcome — `authorized`, or one of `rejected_cert`,
`rejected_token`, `rejected_ip`, `rejected_disabled`, `rejected_category`,
`rejected_query` — together with the consumer type, source IP, certificate
fingerprint, endpoint, format, a query summary, and the result count.

**Verifying the chain.** In the MC, *Verify chain* on the Threat Hunting tab
reports `CHAIN OK (n)` or the position of the first broken link. Programmatically,
`GET /api/threat-hunting/access-log/verify` returns `{ intact, count }` or, on a
break, the `brokenAt` index.

**Canonical specification (for independent verification).** Each row's
`this_hash` is the lowercase hex SHA-256 of the following fields joined by a NUL
(`U+0000`) byte, in this exact order, with an empty string substituted for any
null or absent value (and the integer result count rendered as its decimal
string):

```
prev_hash, authorization_id, consumer_type, source_ip, cert_fingerprint,
endpoint, format, query_summary, outcome, result_count, accessed_at
```

The first row's `prev_hash` is the empty string. An auditor can recompute the
chain from a database dump using only this specification and a SHA-256 routine.

## Rate limiting

The feed and TAXII routes carry a dedicated per-IP rate limit (600 requests per
5 minutes) that is independent of the interactive API limit. It bounds a
misbehaving or compromised consumer without throttling normal polling, and it
applies even though authorized consumer traffic is otherwise exempt from the
general API limiter.

## Threat model and honest scope

- **Application-layer authorization.** FireAlive authorizes and logs the pulls
  that reach it. Network-layer blocking of unauthorized hosts remains your
  firewall / security-group responsibility; the source-IP allow-list is a second
  check, not a substitute for it.
- **Defense in depth.** Mutual TLS, the bearer token, and the IP allow-list are
  three independent factors. Compromise of one (a leaked token, say) does not by
  itself grant access; the certificate and source IP must also match.
- **Tamper-evident, not tamper-proof.** As with the audit log, an attacker with
  raw database access can still destroy the log; what they cannot do is edit it
  *undetectably*, because any rewrite breaks the hash chain.
- **Pseudonymity, not anonymity.** Pseudonyms are stable within a deployment so
  that a consumer can correlate an actor's events over time. They are
  irreversible without the per-deployment secret, but an operator holding that
  secret could in principle re-identify; treat the secret accordingly.

## Troubleshooting

- **Consumer cannot connect.** Confirm, in order: the category is enabled in
  policy; the authorization is enabled (not disabled or revoked); the client
  certificate, key, and CA chain are the ones issued at authorization time; the
  bearer token is present and current; and the consumer's source IP is within the
  allow-list. The access log records the precise rejection outcome for each
  attempt.
- **A pull returns a query error.** Check the `limit`, `since`, `until`, and
  `cursor` parameters; malformed values are rejected as `rejected_query` before
  any data is read.
- **Rotating a leaked credential.** Revoke the affected authorization (this
  disables the token and revokes the certificate) and issue a new one. Update the
  consumer with the new credentials.
- **Confirming integrity after an incident.** Run *Verify chain* (or the verify
  endpoint) and, for independent assurance, recompute the chain offline from a
  database dump using the canonical specification above.
