# IAM & Authentication

This document is for **CISOs**, **SOC managers**, **identity/PKI administrators**, and **analysts** who need to understand or operate how people sign in to FireAlive and how access is governed. FireAlive is **passwordless and phishing-resistant by design**: there is no password anywhere in the system, and no shared secret a network attacker or a malicious server can replay. Sign-in rests on **possession of a hardware-backed credential**, not on knowing something.

This applies uniformly to all three surfaces — the **Analyst Client** (AC), the **Management Console** (MC), and the **Global Dashboard** (GD). The GD runs in its own application and security realm with its own Certificate Authority; the rules below hold in both realms.

## Why passwordless

A SOC is a high-value target, and the analysts who staff it are exactly the people an adversary most wants to impersonate. Passwords — even with a one-time code bolted on — are **phishable**: an attacker-in-the-middle page can capture a password and a TOTP code and replay them in real time. The gold standard for this threat model (NIST SP 800-63B AAL3, CISA, OMB M-22-09) is **phishing-resistant authentication only**, where the credential is cryptographically bound to the real server and never leaves the user’s authenticator.

FireAlive therefore offers two **co-primary** phishing-resistant authenticators and nothing weaker:

- **Mutual-TLS client certificates** (the PIV/CAC pattern) — for shops that run smart cards or a PKI.
- **FIDO2 / WebAuthn passkeys** (a hardware security key, or a platform/TPM authenticator) — for everyone else.

Both are hardware-backed, both reach AAL3, and **neither involves a browser redirect**. A thick-client SOC tool routing its login through a system browser would be handing its weakest link to the attacker; FireAlive’s desktop clients perform the credential ceremony in-process instead.

### What was removed, and why

Earlier builds had passwords, LDAP-password login, and TOTP. All three are gone:

- **No password / LDAP-password login.** There is no `/login` or `/login-ldap` endpoint. The regression suite asserts their absence.
- **No TOTP.** A user-verified passkey or a certificate-plus-PIN is *already* two factors (AAL3). Adding a phishable TOTP step to an unphishable passkey would **lower** the bar, not raise it, so there is no second prompt — assurance comes from the strength of the single primary, not from prompt-count.

The one deliberate exception is **break-glass recovery** (below), which is single-purpose, one-time, hashed at rest, rate-limited, and audited.

## The built-in Certificate Authority

FireAlive ships a turnkey Certificate Authority so an organization can issue per-analyst client certificates without standing up its own PKI.

- The CA is **RSA-3072** (`rsa-3072`, ~128-bit security, CNSA-aligned), self-initialized on first run. Its private key is generated with the openssl CLI in a scratch directory and stored **encrypted at rest** in the database (`ca_authority`); the scratch directory is discarded. The CA certificate is valid for ten years.
- **Client certificates** are issued from a CSR (the private key is generated on the holder’s device and never transmitted), valid for one year, and bound to the holder’s stable **`external_id`** via a Subject Alternative Name URI. The TLS **server certificate** is issued by the same CA (≈27-month lifetime, the CA/Browser-Forum maximum) so HTTPS/WSS validates with zero operator effort in dev and prod alike.
- **Relying-party mode.** An organization that already runs its own CA can point FireAlive at it instead of issuing from the built-in CA; the built-in CA is the primary tested path.

Certificate issuance, the issued-certificate inventory, and revocation are surfaced in the MC’s **IAM** panel (and the GD operates an equivalent for its own realm).

## Revocation: local list + signed CRL, no OCSP

Revocation is **local and air-gap-friendly**. There is no live OCSP responder to depend on (and so no fail-open/fail-closed fragility on a flaky network):

- The CA maintains a database-backed revocation list. Every mutual-TLS handshake checks the presented certificate against it, and a revoked certificate is rejected (`reason: revoked`).
- A **CA-signed CRL** (RSA-SHA256 over the revoked set) is published for external verifiers; in relying-party mode a periodically-cached copy of the organization CA’s CRL is used.

Revoking a certificate is immediate on the next handshake. Offboarding a user revokes their active certificates as part of the same action.

## Break-glass recovery

Because there is no password to fall back to, the **only** lockout-recovery path is a single break-glass credential:

- It is **high-entropy** (192-bit), **hashed at rest** (the plaintext is shown exactly once, at CA initialization), **rate-limited**, and **fully audited**.
- It is **single-purpose**: it authorizes re-provisioning an administrator’s authenticator (enrolling a fresh passkey or issuing a new certificate), nothing more.
- Verification is timing-safe.

This is the one non-passwordless path in default operation, and it is deliberately narrow.

## Step-up for sensitive actions

A handful of consequential actions require a **fresh** proof of presence — a newly minted, user-verified WebAuthn assertion at the moment of the action, not a cached session:

- Toggling the **configuration lock**.
- Approving a **two-person restore**.

Step-up uses a distinct challenge purpose bound to the acting user’s credential; a stale or replayed assertion will not satisfy it.

## LDAP / Active Directory — directory, not authentication

LDAP/AD is used **only as a directory source**, never as a login method. Over LDAPS, FireAlive reads group membership and presence to drive the **offboarding detector**: when a user disappears from the directory (or their certificate is revoked or expired, or their account goes stale), they surface as an offboarding *candidate* for a human to confirm — the detector never deactivates anyone automatically. LDAP filter inputs are escaped (RFC 4515) to prevent filter injection.

## Transport

Every component connects over **HTTPS/WSS with no plaintext fallback** — the connection is fail-closed. The desktop clients (AC, MC, GD) **pin and trust the FireAlive CA** in their main process (so the self-signed-from-our-CA server certificate validates), and present a hardware client certificate from the OS store when one is configured. On first run an operator imports the server’s CA certificate (PEM) once to establish trust; until then the client will not connect, by design.

## The three surfaces

- **Analyst Client (AC).** Connects to the pre-configured FireAlive server. Analysts sign in with a passkey or a client certificate, and manage their own credentials (enroll/remove passkeys, view/revoke their certificates) in a self-service security section.
- **Management Console (MC).** The administrative surface. Operators sign in passwordlessly, manage the CA / directory / offboarding from the **IAM** panel, provision new analysts (which mints a one-time enrollment token), and manage their own credentials in the same self-service section.
- **Global Dashboard (GD).** A **separate application and security realm** with its own CA (`CN=FireAlive Global Dashboard CA`) and its own credential store. CISO/VP operators sign in passwordlessly, can self-serve a backup passkey or revoke a lost credential without falling back to break-glass, and bootstrap their first credential via a break-glass-gated enrollment. The GD structurally cannot see individual analyst data — it holds only Tier-1 aggregates.

## Enrollment & provisioning

A new analyst is **provisioned** from the MC, which mints a **one-time enrollment token** (shown once). The analyst redeems that token in the AC to enroll their first passkey — fetch creation options, create the credential in the authenticator, verify it server-side — after which they sign in normally. Certificates can be issued during provisioning or by an administrator. Thereafter, all credential management is self-service and scoped server-side to the acting user (no request ever carries another user’s id).

## What an attacker cannot do

The guarantees rest on cryptography, not on trusting the channel, the server, or any administrator:

- A **network attacker / AitM** cannot phish a credential: there is no password or TOTP to capture, and the passkey/certificate ceremonies are bound to the real server.
- A **stolen session token** cannot perform a sensitive action: config-lock and restore approvals require a fresh user-verified assertion.
- A **revoked or expired certificate** cannot authenticate: it is rejected at the TLS handshake against the local revocation list.
- A **lost authenticator** does not lock an organization out, and recovery does not weaken the system: break-glass is one-time, hashed, rate-limited, audited, and single-purpose.
- A **plaintext downgrade** cannot happen: there is no non-TLS path.