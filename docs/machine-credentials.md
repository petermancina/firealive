# Machine Credentials

**Every non-human caller into FireAlive is sender-constrained.** A bearer secret —
an API key, a scanner token — authenticates *nothing* on its own. The request must
arrive over a mutual-TLS connection whose client certificate this deployment's CA
issued, which carries the role organizational unit for that surface, and which is
bound to the exact credential being presented.

A leaked key, copied out of a config file or a log, is not usable. Without the
private key of the certificate it was issued alongside — which never leaves the
machine it was installed on — the TLS handshake does not complete, and the key is
never compared.

---

## Why the secret alone is not enough

A bearer credential is a *shared secret*: whoever holds it is, as far as the
server is concerned, the legitimate caller. That is the whole of its security. It
survives being copied, pasted, logged, screenshotted, committed to a repository,
or read out of a backup, and nothing about the request distinguishes the thief
from the owner.

Binding the credential to a certificate changes what is being proved. The client
must demonstrate *possession of a private key* during the TLS handshake — not
present a string it happens to know. That proof cannot be replayed, cannot be
copied out of a log, and is enforced by the transport before any application code
runs.

This is the same property RFC 8705 gives OAuth tokens, applied to every machine
credential FireAlive issues.

---

## The four surfaces

| Surface | Secret | Role OU | Server |
|---|---|---|---|
| API keys (headless integrations) | `X-API-Key` | `api-key-consumer` | Regional |
| On-prem vulnerability scanners | bearer / `X-Scan-Token` | `scanner-consumer` | Regional |
| Cloud vulnerability scanners | bearer / `X-Scan-Token` | `scanner-consumer` | Regional |
| Cloud vulnerability scanners | bearer / `X-Scan-Token` | `scanner-consumer` | Global Dashboard |
| Threat-hunting consumers | bearer | `threat-hunting-consumer` | Regional |

A **fifth** machine path — Management Console → Global Dashboard pushes — is
authenticated by per-request Ed25519 signatures rather than a bound certificate.
See below.

### A fifth surface, with a different and stronger mechanism

**Management Console → Global Dashboard pushes are not certificate-bound, and
deliberately so.** They are authenticated by **per-request Ed25519 signatures**,
built by R3g PR3:

- `management_consoles.api_key` **identifies** the calling MC — it resolves which
  row is speaking. It does not authenticate.
- `X-FA-Signature` carries an Ed25519 signature over `timestamp + "\n" + rawBody`,
  verified against a per-MC public key in the `signing_keys` registry, scoped by
  `mc_id` + fingerprint + `approval_status = 'approved'` + (active, or inside the
  configured rotation grace window).
- `X-FA-Timestamp` is bounded to a five-minute skew in either direction.
- The MC's private key is sealed at **Tier-1** and never stored in plaintext.
- A new key arrives `pending_approval, is_active = 0`. A CISO (or
  `signing_key_approver`) verifies its fingerprint **out of band** with the MC
  operator before approving; approval atomically demotes the prior key with a
  grace window for in-flight pushes. The handshake, approve and reject routes are
  all configuration-lock gated.

**Why signing rather than mTLS here.** Mutual TLS proves possession of a key at
*connection setup*. Request signing proves it **per request, over the body**, and
survives TLS termination at a proxy or load balancer — which matters because this
is the one machine path that crosses a network boundary between two deployments
with **separate certificate authorities**. Adding mTLS on top would be
belt-and-braces on a path that already has a per-request cryptographic proof and
an out-of-band-approved trust root.

The principle is the same as everywhere else in this document: **the shared
secret is not the authenticator.** Only the mechanism differs.

---

**The role OU is enforced, not decorative.** A certificate issued for the
threat-hunting feed is *refused* by the API-key path, and an API-key certificate
is refused by the feed. Each surface accepts only its own class. A single shared
OU would make every machine certificate universal — one compromised scanner
credential would reach every machine-authenticated endpoint on the deployment.

The Regional Server and the Global Dashboard run **separate certificate
authorities**. A certificate issued by one does not verify on the other. They are
distinct trust domains, and a credential for one grants nothing on the other.

---

## The decision sequence

Every machine-authenticated request runs the same checks, in this order, failing
closed on each:

1. **A client certificate is present** on the TLS connection.
2. **It verifies against this deployment's CA** — signed by it, inside its
   validity window, and not in the local revocation list.
3. **Its subject carries the role OU** for the surface being called.
4. **A credential row is bound to that exact certificate fingerprint.**
5. **The bearer secret matches that row**, compared in constant time (scanners and
   threat-hunting) or against a bcrypt hash (API keys).
6. **The source IP falls inside the allow-list**, where the surface has one.

**Order matters.** A caller with no certificate never reaches step 5, so the
endpoint cannot be used to probe which secrets exist. Every failure returns the
same generic rejection — the response never reveals *which* factor failed, so it
is not an oracle. The precise reason is recorded server-side in the audit or
access log.

---

## Issuing a credential

Creating an API key or authorizing a scanner mints **both halves at once**, inside
a single database transaction. FireAlive generates the certificate's private key
itself, so the subject — including the role OU the gate checks — is
server-controlled and therefore trustworthy.

The console returns four items, **shown exactly once**:

- the **bearer secret** (API key, or scanner token),
- the **client certificate** (PEM),
- the **client private key** (PEM),
- the **FireAlive CA certificate** (PEM), needed so the client can trust the server.

None is retrievable afterwards. The secret is stored only as a hash; the private
key is not stored at all. If any part is lost, revoke the credential and issue a
new one — there is deliberately no in-place rotation, because rotation in place
means a window where two credentials are valid and only one is accounted for.

Creating or revoking a machine credential is a **mint path**: it requires a fresh
user-verified hardware-key assertion at the moment of the action, on top of the
configuration lock. See [`configuration-lock.md`](./configuration-lock.md).

---

## Revoking a credential

Revoking a credential revokes **its certificate as well**, in one transaction.
Flagging the row alone would leave a certificate this deployment's CA still
vouches for — a credential the operator believes is destroyed and which is not.

Disabling an authorization suspends access without revoking the certificate, and
is reversible. Revocation is permanent.

---

## Installing a credential on the client

The client must be configured to:

1. present the **client certificate and private key** on every request,
2. **trust the FireAlive CA certificate** when validating the server, and
3. send the **bearer secret** in its header (`X-API-Key`, `Authorization: Bearer`,
   or `X-Scan-Token` depending on the surface).

All three are required. A client that presents the certificate but omits the
secret is rejected, and so is one that sends the secret without the certificate.

---

## Upgrading an existing deployment

Credentials created before this model existed have **no bound certificate**, and
they do not authenticate. This is deliberate and it is not silent: the migration
logs, for each affected table, that existing rows are unbound and cannot
authenticate until re-issued.

There is no permissive mode, no grandfathering period, and no per-credential
opt-in. An unbound credential is a bearer credential, and the point of this model
is that FireAlive does not accept those. Re-issue each machine credential from its
console and install the new material on the client.

On a **fresh install** the database enforces this structurally — the
certificate-fingerprint column is `NOT NULL`, so an unbound row cannot be written
at all.

---

## What this does not protect against

- **A compromised client machine.** If an attacker has the private key *and* the
  secret from a host they control, they are that client. Sender-constraining
  raises the bar from "read a string" to "compromise the host"; it does not remove
  the host from the trust boundary.
- **An operator who installs one credential on many machines.** FireAlive cannot
  tell one host from another beyond the certificate presented. Issue one
  credential per client.
- **Anything after authentication.** Scope, source-IP allow-lists, the
  configuration lock and the audit trail govern what an authenticated caller may
  do. This model governs only whether it is authenticated at all.

---

## Related

- [`iam-and-authentication.md`](./iam-and-authentication.md) — the human
  authentication model and the internal CA
- [`threat-hunting.md`](./threat-hunting.md) — the consumer feed, which has worked
  this way since B5m
- [`vulnerability-scanning.md`](./vulnerability-scanning.md) — the scanner access
  gate
- [`configuration-lock.md`](./configuration-lock.md) — the lock that governs
  configuration writes
