# IAM & Authentication

This document is for **CISOs**, **SOC managers**, **identity/PKI administrators**, and **analysts** who need to understand or operate how people sign in to FireAlive and how access is governed. FireAlive is **passwordless and phishing-resistant by design**: there is no password anywhere in the system, and no shared secret a network attacker or a malicious server can replay. Sign-in rests on **possession of a hardware-bound credential** — a FIDO2 security key that never leaves the operator's hand — not on knowing something.

This applies uniformly to all three surfaces — the **Analyst Client** (AC), the **Management Console** (MC), and the **Global Dashboard** (GD). The GD runs in its own application and security realm with its own Certificate Authority and its own trust store; the rules below hold in both realms.

## Why passwordless, and why a hardware key

A SOC is a high-value target, and the analysts who staff it are exactly the people an adversary most wants to impersonate. Passwords — even with a one-time code bolted on — are **phishable**: an attacker-in-the-middle page can capture a password and a TOTP code and replay them in real time. The gold standard for this threat model (NIST SP 800-63B, CISA, OMB M-22-09) is **phishing-resistant authentication only**, where the credential is cryptographically bound to the real server and never leaves the user's authenticator.

FireAlive's sign-in credential is a **FIDO2 / WebAuthn passkey held on a hardware security key** (a key or fob that requires a PIN), and nothing weaker. The ceremony runs **in-process** in the desktop client — never through a system browser, which would hand a thick-client SOC tool's weakest link to the attacker.

A passkey alone is not enough, though: an attacker could enroll a *software* or *cloud-synced* passkey (one that lives in iCloud Keychain, Google Password Manager, or Windows Hello and can be copied between devices) and defeat the "possession of hardware" guarantee. So at **enrollment** FireAlive proves the credential is genuinely hardware-bound before it will ever accept it for sign-in. See **Hardware-key enrollment** below.

### Where the client certificate fits now

FireAlive still issues per-operator **mutual-TLS client certificates**, but a certificate is **transport identity, not a sign-in credential**. It secures the connection (mutual TLS), identifies the device at the handshake, and is opportunistically bound into the session (below) — but it is never, by itself, a way to log in.

The reason is precise: a certificate proves only that a valid, unrevoked key signed the handshake. It proves **nothing** about *where* that private key lives — whether it is hardware-backed, non-exportable, or PIN-gated. A hardware passkey, validated by attestation, proves all three. Tying sign-in to the passkey and demoting the certificate to transport gives a single, honest assurance story rather than two credentials of unequal real-world strength.

### What was removed, and why

Earlier builds had passwords, LDAP-password login, TOTP, and certificate sign-in. All are gone as **login** methods:

- **No password / LDAP-password login.** There is no `/login` or `/login-ldap` endpoint. The regression suite asserts their absence.
- **No certificate sign-in.** There is no `/login-cert` endpoint on the regional server or the GD-Server; the regression suite asserts its absence. Certificates remain for transport and revocation, as above.
- **No TOTP.** A user-verified hardware passkey is *already* a possession factor plus a PIN factor. Adding a phishable TOTP step to an unphishable hardware key would **lower** the bar, not raise it.

The one deliberate exception is **break-glass recovery** (below), which is single-purpose, one-time, hashed at rest, rate-limited, and audited.

## Hardware-key enrollment: provenance, non-syncability, user verification

Before a passkey can ever be used to sign in, it must clear three gates **at the moment it is enrolled**. A passkey that fails any of them is refused with a clear message, and nothing about it is persisted as a login credential:

1. **Provenance — attestation chains to a trusted vendor root.** The authenticator presents a manufacturer attestation statement; FireAlive verifies that its attestation certificate chains to one of a set of **trusted vendor roots**. This is *provenance pinning*: the platform ships with a pinned, pre-seeded set of vendor roots, and an administrator may **add** more (audited) — but there is **no toggle to accept un-attested keys**. Direct attestation is requested at enrollment so this check can run.
2. **Non-syncable — the credential is device-bound.** FireAlive requires `credentialBackedUp === false`: the key is not eligible for multi-device sync. Cloud-synced and software passkeys (iCloud Keychain, Google Password Manager, Windows Hello) are rejected, because a credential that can be copied to another device is no longer "possession of a single piece of hardware."
3. **User verification — PIN or biometric gated.** The credential must be user-verified, so possession of the key is not enough on its own; the operator must also satisfy the authenticator's PIN/biometric.

A successful enrollment therefore certifies "hardware security key verified," and the clients say so. A failure is surfaced as a refusal telling the operator to use a hardware security key with a PIN.

### Trust anchors: bundled roots, admin-added roots, and the model allow-list

The set of accepted authenticators is governed entirely by data an administrator can see and manage:

- **Trusted attestation roots.** A pinned, pre-seeded set of vendor CA roots ships with FireAlive. An administrator can add a vendor's root (from the vendor's official PKI or the FIDO Alliance Metadata Service) to accept that vendor's keys. Every add and remove is **audited**, and the system **refuses to remove the last remaining root** (which would make hardware-key enrollment impossible). There is deliberately **no control that relaxes enrollment below provenance pinning**.
- **Model allow-list (AAGUID), optional and off by default.** By default, any model from a trusted vendor is accepted. An organization that wants to standardize on specific authenticator models can add their **AAGUIDs** to an allow-list to narrow enrollment to exactly those models; an empty list means no model restriction.

Both realms keep their **own** trust store. The MC's **IAM -> Hardware Keys** panel manages the regional server's roots and allow-list; the GD's **IAM & Access** tab manages the GD-Server's. Each is gated to the appropriate administrator (lead/admin on the regional server behind the configuration lock; CISO on the GD-Server) and audited.

## The built-in Certificate Authority

FireAlive ships a turnkey Certificate Authority so an organization can issue per-operator client certificates (for transport) and the TLS server certificate without standing up its own PKI.

- The CA is **RSA-3072** (`rsa-3072`, ~128-bit security, CNSA-aligned), self-initialized on first run. Its private key is generated with the openssl CLI in a scratch directory and stored **encrypted at rest** in the database (`ca_authority`); the scratch directory is discarded. The CA certificate is valid for ten years.
- **Client certificates** are issued from a CSR (the private key is generated on the holder's device and never transmitted), valid for one year, and bound to the holder's stable **`external_id`** via a Subject Alternative Name URI. They establish the mutual-TLS transport and bind the session to the device; they are not a sign-in credential. The TLS **server certificate** is issued by the same CA (~27-month lifetime, the CA/Browser-Forum maximum) so HTTPS/WSS validates with zero operator effort in dev and prod alike.
- **Relying-party mode.** An organization that already runs its own CA can point FireAlive at it instead of issuing from the built-in CA; the built-in CA is the primary tested path.

Certificate issuance, the issued-certificate inventory, and revocation are surfaced in the MC's **IAM** panel (and the GD operates an equivalent for its own realm).

## Revocation: local list + signed CRL, no OCSP

Revocation is **local and air-gap-friendly**. There is no live OCSP responder to depend on (and so no fail-open/fail-closed fragility on a flaky network):

- The CA maintains a database-backed revocation list. Every mutual-TLS handshake checks the presented certificate against it, and a revoked certificate is rejected (`reason: revoked`), so it can no longer establish the transport.
- A **CA-signed CRL** (RSA-SHA256 over the revoked set) is published for external verifiers; in relying-party mode a periodically-cached copy of the organization CA's CRL is used.

Revoking a certificate is immediate on the next handshake. Offboarding a user revokes their active certificates as part of the same action.

## Break-glass recovery

Because there is no password to fall back to, the **only** lockout-recovery path is a single break-glass credential:

- It is **high-entropy** (192-bit), **hashed at rest** (the plaintext is shown exactly once, at CA initialization), **rate-limited**, and **fully audited**.
- It is **single-purpose**: it authorizes re-provisioning an administrator's authenticator (enrolling a fresh hardware passkey, which still clears the enrollment gates above), nothing more.
- Verification is timing-safe.

This is the one non-passwordless path in default operation, and it is deliberately narrow.

## Step-up for sensitive actions

A handful of consequential actions require a **fresh** proof of presence — a newly minted, user-verified WebAuthn assertion at the moment of the action, not a cached session:

- Toggling the **configuration lock**.
- Approving a **two-person restore**.

Step-up uses a distinct challenge purpose bound to the acting user's credential; a stale or replayed assertion will not satisfy it.

## Sender-constrained sessions

A successful sign-in mints a short-lived **session token** (a bearer JWT). A bare bearer token has a classic weakness: anyone who copies it — off the wire, from a log, from process memory — can replay it from another machine until it expires. FireAlive removes that weakness by **binding the session token to the operator's hardware device key** and requiring a fresh proof of that key on **every** request, following the shape of DPoP (RFC 9449):

- **The token is bound at issue.** Each operator's app holds a non-exportable hardware device key. At sign-in the token carries an RFC 7800 confirmation claim (`cnf.jkt`) set to that key's RFC 7638 JWK thumbprint, so the token names the one key entitled to wield it.
- **Every request proves possession.** Alongside the token, each authenticated request carries a one-time proof header (`x-fa-device-pop`): a compact object in which the device key signs the request method, the request path, a timestamp, a unique id, and the bound key's thumbprint. The server looks up the operator's active key, confirms its thumbprint still matches the token, and verifies the signature.
- **Tight freshness and single use.** A proof is accepted only within a 60-second window (with a small clock-skew tolerance) and only once — its unique id is remembered until the window closes, so a captured proof cannot be replayed even within that minute.
- **Per-realm domain separation.** The regional server and the Global Dashboard sign their proofs under distinct, versioned prefixes, so a proof minted for one server can never be replayed against the other.
- **Opportunistic channel binding.** When the operator presents a mutual-TLS client certificate, that certificate's thumbprint is bound into the token as well (`cnf` `x5t#S256`) and checked on each request, tying the session to the transport too.
- **A narrow bootstrap.** Registering a device key necessarily happens before a key exists, so the registration endpoints are the only ones exempt from the proof. Once an operator has a key, every request is gated.

The effect: the token alone is not a credential. Without the hardware key — which never leaves the machine — a copied token cannot produce the per-request proof, so it is refused. This holds uniformly for the Analyst Client and Management Console on the regional server, and for the Global Dashboard in its own realm. (API keys for headless integrations are a separate, machine-credential path: they have no hardware key, so they stay on their scoped, hashed, IP-allow-listed model rather than carrying a device-key proof.)

## LDAP / Active Directory — directory, not authentication

LDAP/AD is used **only as a directory source**, never as a login method. Over LDAPS, FireAlive reads group membership and presence to drive the **offboarding detector**: when a user disappears from the directory (or their certificate is revoked or expired, or their account goes stale), they surface as an offboarding *candidate* for a human to confirm — the detector never deactivates anyone automatically. LDAP filter inputs are escaped (RFC 4515) to prevent filter injection.

## Transport

Every component connects over **HTTPS/WSS with no plaintext fallback** — the connection is fail-closed. The desktop clients (AC, MC, GD) **pin and trust the FireAlive CA** in their main process (so the self-signed-from-our-CA server certificate validates), and present a hardware client certificate from the OS store when one is configured — that certificate is the mutual-TLS transport identity, not a login credential. On first run an operator imports the server's CA certificate (PEM) once to establish trust; until then the client will not connect, by design.

## The three surfaces

- **Analyst Client (AC).** Connects to the pre-configured FireAlive server. Analysts sign in with a hardware passkey, and manage their own credentials (enroll/remove passkeys, view/revoke their transport certificates) in a self-service security section.
- **Management Console (MC).** The administrative surface. Operators sign in with a hardware passkey, manage the CA / **hardware-key trust anchors** / directory / offboarding from the **IAM** panel, provision new analysts (which mints a one-time enrollment token), and manage their own credentials in the same self-service section.
- **Global Dashboard (GD).** A **separate application and security realm** with its own CA (`CN=FireAlive Global Dashboard CA`), its own credential store, and its own trust anchors. CISO/VP operators sign in with a hardware passkey, can self-serve a backup passkey or revoke a lost credential without falling back to break-glass, manage the GD-Server's trust anchors from the **IAM & Access** tab, and bootstrap their first credential via a break-glass-gated enrollment. The GD structurally cannot see individual analyst data — it holds only Tier-1 aggregates.

## Enrollment & provisioning

A new analyst is **provisioned** from the MC, which mints a **one-time enrollment token** (shown once). The analyst redeems that token in the AC to enroll their first **hardware** passkey — fetch creation options, create the credential on the security key, and verify it server-side, where it must clear the provenance, non-syncability, and user-verification gates above — after which they sign in normally. Transport certificates can be issued during provisioning or by an administrator. Thereafter, all credential management is self-service and scoped server-side to the acting user (no request ever carries another user's id).

## What an attacker cannot do

The guarantees rest on cryptography, not on trusting the channel, the server, or any administrator:

- A **network attacker / AitM** cannot phish a credential: there is no password or TOTP to capture, and the hardware-passkey ceremony is bound to the real server.
- A **software or cloud-synced passkey cannot be enrolled** as a login credential: enrollment requires a manufacturer attestation that chains to a trusted vendor root, a non-syncable (device-bound) credential, and user verification. A copyable credential never becomes a sign-in factor.
- A **stolen session token** is useless off the operator's machine: every authenticated request must carry a fresh, single-use proof signed by the bound hardware device key, so a token lifted from the wire or from memory cannot be replayed elsewhere. Sensitive actions add a second gate on top — a fresh user-verified assertion for config-lock and restore approvals.
- A **revoked or expired certificate** cannot establish the transport: it is rejected at the TLS handshake against the local revocation list.
- A **lost authenticator** does not lock an organization out, and recovery does not weaken the system: break-glass is one-time, hashed, rate-limited, audited, and single-purpose.
- A **plaintext downgrade** cannot happen: there is no non-TLS path.
