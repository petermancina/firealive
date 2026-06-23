# Login Geo-Fencing

Login geo-fencing checks the country an analyst authenticates *from* against the
country assigned *to* their account, and — when you turn enforcement on — blocks
logins whose origin country does not match. It runs entirely on a self-hosted
MaxMind GeoLite2-Country database read by FireAlive's own auditable code. No
analyst identity or location ever leaves the server, and the geo subsystem
carries none of the burnout, wellbeing, or Tier-3 signals that live elsewhere in
the platform.

This is a defence-in-depth control, not a perimeter. Read **What it cannot do**
and **Before you enforce** before enabling it.

---

## What it cannot do

Geo-fencing can only judge a login when FireAlive observes the analyst's **real,
public** client IP address. Three consequences follow, and all three bite in
practice:

1. **Behind a reverse proxy or load balancer**, `req.ip` is the proxy's address
   unless you tell FireAlive to trust the proxy. Set the `TRUST_PROXY`
   environment variable to your proxy hop count (or CIDR) so the server reads the
   forwarded client address. If you skip this, every login appears to come from
   the proxy's internal IP and country resolution is meaningless. See **Seeing
   the real client IP**.

2. **On a pure-LAN deployment** every login arrives from a private (RFC 1918)
   address that has no country. Country *matching* never triggers there. What
   protects a LAN deployment is the **trusted-network allow-list**, not country
   comparison — declare the subnets you accept and everything else is refused
   under enforcement.

3. **VPNs, residential proxies, and cloud egress** let a determined adversary
   present an IP in any country. Country is a coarse signal. Geo-fencing raises
   the cost of a stolen-credential login from an unexpected region; it does not
   defeat an attacker who tunnels through the right country.

Geo-fencing is one layer on top of passwordless hardware-bound authentication,
not a replacement for it.

---

## How a login is judged

The check runs at the end of passwordless login (`finishPasswordlessLogin`),
after the certificate or passkey has already verified. It evaluates in this
fixed order and stops at the first rule that applies:

```
1. feature disabled               -> allow  (no checking at all)
2. user has no assigned country   -> allow  (that analyst is not fenced)
3. GeoIP database not loaded       -> allow  + HIGH alert  (fail-open, see below)
4. source IP is loopback           -> allow  (bypass)
5. source IP in a trusted network  -> allow  (bypass)
6. resolves to the assigned country-> allow  (match)
7. an active exception permits it  -> allow  (exception)
8. otherwise                       -> mismatch / unresolvable
                                      audit + CRITICAL alert always;
                                      block (403, no token) only if enforcing
```

Two flags drive it:

- **`enabled`** turns the feature on. A mismatch — or an origin that cannot be
  resolved and is not on a trusted network — always writes an audit event and
  raises a CRITICAL alert, **even in audit-only mode**.
- **`enforceGeoLogin`** additionally *blocks* the login: the server returns 403
  and issues no JWT. With this off, you get the alerts without the lockout risk,
  which is the right way to pilot the feature.

**Fail-open on misconfiguration is deliberate.** If the feature is enabled but no
GeoIP database is loaded, the check allows the login and raises a HIGH
`GEO_CONFIG_MISCONFIGURED` alert. A missing database is operator error, not an
attack, and it must not brick every login — including the admin's. This is
distinct from the per-login case where a database *is* loaded but this particular
IP is unresolvable and untrusted: that fails **closed** under enforcement.

**Break-glass recovery is exempt by design.** Emergency recovery issues a scoped
enrollment token through a separate handler that does not pass through the login
chokepoint, so a locked-out administrator can always recover.

---

## Provisioning the GeoIP database

FireAlive does not ship a GeoIP database. MaxMind's GeoLite2 licence forbids
redistribution, and a committed snapshot would age. You provide the database; the
server malware-scans, format-validates, and hash-verifies it on upload before it
ever resolves an address.

1. Create a free account at
   `https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/` and generate a
   licence key.
2. In the account portal, open **Download Databases** and download the
   **GeoLite2-Country** edition (edition ID `GeoLite2-Country`). Use Country, not
   City — City is far larger and unnecessary for login geo-fencing. Each build
   has a published **SHA256** link next to it.
3. In the Management Console, open **Data Sovereignty -> GeoIP Database** and
   select the extracted `.mmdb` file. The console computes the file's SHA-256
   locally and sends it as an `X-Expected-Sha256` integrity header; paste
   MaxMind's published SHA256 there as well if you want the server to reject a
   download that was corrupted in transit.
4. On upload the server scans the file, validates that it is a well-formed
   country database, records its SHA-256 in the `geoip_database` table, and
   activates it atomically. A rejected upload (`GEO_DB_REJECTED`) never replaces
   the active database.

**Provenance — pull from MaxMind directly only.** The artifact may come only from
MaxMind's official portal (account + licence key). The GitHub mirrors and jsDelivr
CDN copies of `GeoLite2` that turn up in search are community redistributions with
unverifiable provenance and are not acceptable.

**Re-upload cadence is relaxed.** MaxMind publishes a new build twice weekly
(Tuesdays and Fridays), but geo data has no "vulnerability" the way code does — a
stale database only means slightly less accurate country resolution. Refreshing
monthly, or when you notice accuracy gaps, is sufficient. Each refresh is a normal
upload; record the new SHA-256 with your release notes.

---

## Assigning analyst countries

An analyst is geo-fenced only once they have a country. An account with no
`geo_country` is never blocked, regardless of where they log in from. Assign
countries three ways:

- **Per analyst in the console.** **Data Sovereignty -> Analyst Country
  Assignments** lists every account with a country selector. Setting it persists
  immediately.
- **At provision time.** The Provision Analyst Client dialog has an optional home
  country, so new accounts can be fenced from first login.
- **From your directory.** Accounts synced from LDAP inherit their country from
  the standard `c` (countryName) attribute when it is present. **A directory
  value is authoritative when supplied** — it overrides a manual assignment on the
  next sync. When the directory has *no* `c` value for a user, a manual assignment
  is preserved and never wiped. If you run LDAP sync, set country in the directory
  and treat the console as a fallback.

Country codes are ISO 3166-1 alpha-2 (two letters, e.g. `US`, `GB`, `DE`).

---

## Trusted networks

Trusted networks are CIDR ranges whose member IPs bypass the country check
entirely — the standard "network membership proves physical presence" model.
Declare your office subnets and VPN egress ranges here so on-site and VPN logins
are never blocked. Loopback is always exempt without configuration.

This is an allow-list, not trust-all-RFC-1918. An IP on an arbitrary private
network an attacker controls is **not** auto-trusted: only the ranges you list
bypass the check; every other origin — public or private — must resolve and match.

Trusted networks are saved as part of the policy. Add or remove ranges in the
console and click **Save Policy**; malformed CIDRs are rejected on save.

---

## Temporary exceptions

An exception grants one analyst the right to log in from a specific country for a
bounded time — the mechanism for legitimate travel. Add it under **Data
Sovereignty -> Temporary Login Exceptions** with the analyst, the permitted
country, an optional reason, and an expiry date (which must be in the future).
Exceptions expire automatically; an expired exception is retained for the audit
trail but no longer permits access, so a traveller falls back to a normal
mismatch once their exception lapses.

---

## Before you enforce (lockout checklist)

Audit-only mode (`enabled` on, `enforceGeoLogin` off) is safe — it alerts without
blocking. Before turning on enforcement, confirm all of the following, or you can
lock analysts out:

- [ ] A GeoIP database is loaded (the GeoIP Database card shows **LOADED**).
- [ ] Every analyst who logs in over the public internet has a country assigned.
- [ ] Your corporate LAN and VPN egress ranges are in Trusted Networks.
- [ ] You have run in audit-only mode long enough to see what the alerts catch.

Remember the failure modes: a *misconfigured* (unloaded) database fails open, but
an *unassigned or wrong* country still blocks that specific analyst under
enforcement, and an unresolvable, untrusted origin is also blocked. Break-glass
recovery remains available throughout.

---

## Seeing the real client IP (reverse proxies)

The decision uses `req.ip`. By default Express reports the direct socket peer,
which behind a reverse proxy or load balancer is the *proxy's* address, not the
analyst's. Set the `TRUST_PROXY` environment variable so the server reads the
real client address from the forwarded headers:

- A small integer is the number of trusted proxy hops in front of FireAlive
  (e.g. `TRUST_PROXY=1` for a single proxy).
- A CIDR or comma-separated list names the trusted proxy addresses.

Set this to match your actual topology. Setting it too permissively lets a client
spoof its address via a forwarded header; leaving it unset behind a proxy makes
every login look like it came from the proxy. After changing it, verify with the
**Resolve an IP** diagnostic that a known external address resolves to the
expected country.

---

## Audit events

Every geo decision and administrative change writes to the append-only audit log
under a closed set of event types, surfaced in **Data Sovereignty -> Recent Geo
Events**:

- `GEO_FENCE_VIOLATION` — a mismatch or unresolvable-untrusted origin (audit-only
  or pre-block).
- `GEO_FENCE_BLOCKED` — a login the server refused under enforcement.
- `GEO_CONFIG_MISCONFIGURED` — enabled but no database loaded (fail-open alert).
- `GEO_DB_UPDATED` / `GEO_DB_REJECTED` — a database upload that activated / was
  refused.
- `GEO_EXCEPTION_ADDED` / `GEO_EXCEPTION_REMOVED` — exception lifecycle.
- `GEO_USER_COUNTRY_SET` — an analyst's country assignment changed.
- `GEO_FENCE_CONFIG_UPDATED` — the policy (flags or trusted networks) changed.

Events identify accounts by their stable internal id and pseudonym; no real name,
and none of the wellbeing data, is recorded.

---

## Threat model and honest scope

**What it raises the cost of:** a stolen-credential or stolen-device login
replayed from an unexpected country, on a deployment where analysts log in over
the public internet from known regions. It turns "right credential, wrong
continent" into a blocked, alerted event.

**What it does not stop:** an adversary who tunnels through a VPN, residential
proxy, or cloud instance in the analyst's own country; a compromise that occurs
*inside* a trusted network; or anything that does not flow through the login
chokepoint. Country is coarse, and GeoLite2 is best-effort — IP-to-country
mappings are occasionally wrong, particularly for mobile carriers, satellite
links, and recently reallocated ranges.

**Where it is blind:** pure-LAN deployments (no public client IP to resolve) and
misconfigured proxy setups (no real client IP visible). In both, lean on trusted
networks and the rest of the authentication stack.

Treat geo-fencing as a tripwire and a cost-raiser layered on hardware-bound
passwordless auth — never as the thing standing between an attacker and the SOC.

---

## Troubleshooting

**Everyone is suddenly blocked after enabling enforcement.** Almost always a
missing client IP: you are behind a proxy without `TRUST_PROXY`, so every login
resolves to a private proxy address that is neither trusted nor resolvable. Set
`TRUST_PROXY`, or add the proxy/LAN range to Trusted Networks, and re-test with
the Resolve diagnostic. (A *missing database* would fail open, not block, so that
is not the cause.)

**A specific analyst is blocked.** Their assigned country does not match where
they are logging in from. Confirm the assignment is correct, add a temporary
exception if they are travelling, or check whether their origin is a VPN exit in
another country.

**The GeoIP Database card shows NOT LOADED.** No database has been uploaded, or
the last upload was rejected (check for a `GEO_DB_REJECTED` event and re-download
from MaxMind). Until one loads, the feature fails open and alerts.

**Resolve returns "(unresolved)" for a real public IP.** The loaded database may
be stale or the IP is in a range MaxMind does not map. Re-upload the latest
GeoLite2-Country build.

**Audit shows violations but no logins are blocked.** You are in audit-only mode
(`enabled` on, `enforceGeoLogin` off) — the intended pilot configuration. Turn on
enforcement only after working through the lockout checklist.
