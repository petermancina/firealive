# Report Verification Guide

This document is for **independent abuse reviewers, auditors, HR, and court
experts** who have received a FireAlive-generated report (a compliance report,
a Report Engine export, a helper-pay statement, or an abuse-flag submission
report) and need to confirm two things:

1. The report was genuinely produced by a specific FireAlive instance — not
   forged or altered after the fact.
2. Its contents are exactly what that instance signed.

Two verification depths are available:

- **System verification (primary).** An authorized operator queries
  `GET /api/verify/report/{hash}` and FireAlive re-checks the signature and
  reports `valid: true`. Fast, but it trusts the running system.
- **Independent verification (this guide).** You check the Ed25519 signature
  yourself with OpenSSL against the instance's published public key. No
  FireAlive tooling and no trust in the running system is required — only the
  public key, the signature, and the report. This is the standard for legal
  admissibility, mirroring FireAlive's forensic export guides.

There is **no public verification endpoint** by design. Verification is always
authenticated. In particular, abuse-flag reports verify **only for an
independent abuse reviewer** — so that no one can grind hashes to enumerate or
confirm the existence of accusations. The appeal path for a dismissed
accusation is therefore out-of-band: the accuser presents their exported
report to HR (or a court), and HR asks an independent abuse reviewer to confirm
it against the system. This guide is what the reviewer (or a forwarded expert)
runs.

## Two classes of report, two things signed

Every report carries a footer with: the instance label, the UTC sign time, the
report id, the short signing-key fingerprint, and a verification hash. What the
signature covers depends on the report class:

| Class | Report types | Signed material (`signed_payload_sha256` is its SHA-256) |
|-------|--------------|----------------------------------------------------------|
| Server-side | `compliance`, `report_engine`, `helper_pay` | the produced PDF/DOCX **file bytes** |
| Client-side | `abuse_flag` | a **canonical data payload** (defined below) — never the rendered PDF, and never plaintext |

In both cases the Ed25519 signature is computed over the **32 raw bytes of the
SHA-256 digest** of the signed material.

The abuse-flag canonical payload is a JSON object with keys sorted ascending,
no insignificant whitespace, UTF-8:

```
{"content_sha256":"<64-hex>","flag_uuid":"<uuid>","instance_label":"<label>","submitted_at":"<iso-8601>","target_type":"<peer_session|board_post|lead_chat>"}
```

`content_sha256` is the SHA-256 of the exact submitted report text (UTF-8). The
server never receives or stores that text — only its hash — which is what keeps
abuse reports zero-access. A reviewer who can decrypt the sealed vault entry
recomputes `content_sha256` from the decrypted text and confirms it matches,
binding the exported report to the real submission.

## Tools required

| Tool | Purpose | Notes |
|------|---------|-------|
| `openssl` | Verify the Ed25519 signature | OpenSSL 3.x (Ed25519 needs ≥1.1.1) |
| `sha256sum` | Hash report bytes / canonical payload | macOS: `shasum -a 256` |
| `base64` | Decode the signature | `base64 -d` (macOS: `base64 -D`) |
| `xxd` | Convert the hex digest to raw bytes | part of most base installs |

## Step 1 — Obtain the public key

An operator with `admin`, `ciso`, or `lead` access fetches it:

```
GET /api/report-signing/key
->
{
  "instance_label": "Acme SOC — Production",
  "active_signing_key": {
    "algorithm": "Ed25519",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "fingerprint": "<64-hex>",
    "created_at": "..."
  }
}
```

Save `public_key_pem` to `pubkey.pem`. Confirm it is the key that signed your
report: the report footer shows the short fingerprint; the full fingerprint
must match:

```
openssl pkey -in pubkey.pem -pubin -outform DER | sha256sum
# compare the first 16 hex chars to the footer's "Ed25519 key:" value,
# and the full value to active_signing_key.fingerprint
```

If a report was signed by a rotated-out key, ask the operator for that key's
PEM — `GET /api/report-signing/key` returns only the active key, but every
historical key is retained for verification.

## Step 2 — Obtain the signature and the signed-payload hash

An authorized operator queries the verify endpoint with the hash from the
report footer:

```
GET /api/verify/report/{hash}
->
{
  "valid": true,
  "report_type": "abuse_flag",
  "subject_ref": "<flag-uuid>",
  "signed_payload_sha256": "<64-hex>",     # the message digest that was signed
  "signature": "<base64>",                 # the 64-byte Ed25519 signature
  "key_fingerprint": "<64-hex>",
  "instance_label": "Acme SOC — Production",
  "signed_at": "...",
  "metadata": { ... }                      # content-blind
}
```

(For `abuse_flag`, this resolves only for a `lead`; for everyone else
it returns 404, identical to a genuine miss.)

Write the two values to files:

```
echo -n "<signature-base64>"      | base64 -d        > sig.bin     # 64 bytes
echo -n "<signed_payload_sha256>" | xxd -r -p         > digest.bin  # 32 bytes
```

## Step 3 — Verify the Ed25519 signature

Ed25519 is PureEdDSA: it signs the message directly, so the 32-byte digest is
the message. Use `-rawin`:

```
openssl pkeyutl -verify -pubin -inkey pubkey.pem -rawin -in digest.bin -sigfile sig.bin
# Expected:
# Signature Verified Successfully
```

A success here proves the instance holding the private key for `pubkey.pem`
signed exactly this digest. If it fails: confirm you have the right public key
(Step 1), that OpenSSL is ≥1.1.1, and that the base64/hex were copied whole.

## Step 4 — Confirm the digest matches the report

The signature proves the digest is authentic; this step proves the digest
belongs to *your* report.

**Server-side reports** (`compliance`, `report_engine`, `helper_pay`) — hash the
file bytes and compare to `signed_payload_sha256`:

```
sha256sum report.pdf      # or report.docx
# the hex must equal signed_payload_sha256 from Step 2
```

**Abuse-flag reports** — rebuild the canonical payload from the report footer
fields and hash it:

```
# Fill in the exact values shown on the report (note the sorted key order
# and the absence of spaces):
printf '%s' '{"content_sha256":"<hex>","flag_uuid":"<uuid>","instance_label":"<label>","submitted_at":"<iso>","target_type":"<type>"}' | sha256sum
# the hex must equal signed_payload_sha256 from Step 2
```

Then confirm the report **text** is the text that was submitted, by hashing it
and comparing to the `content_sha256` field inside the payload:

```
printf '%s' "<the exact submitted text, UTF-8>" | sha256sum
# must equal content_sha256
```

If both digests match and Step 3 succeeded, the report is genuine, was produced
by the named instance at the stated time, and its text is exactly what was
submitted.

## What this proves — and what it does not

Proven when all steps pass:

- **Authenticity:** the report was signed by the private key whose public half
  is `pubkey.pem` — i.e., by that FireAlive instance.
- **Integrity:** not one byte of a server-side report, and not one character of
  an abuse-flag report's text, has changed since signing.
- **Time:** the instance recorded `signed_at` in its permanent, append-only
  verification ledger at signing.

Not proven by cryptography alone (and never claimed):

- That the public key belongs to the organization you think it does — establish
  that out-of-band (the operator hands you the PEM through a trusted channel).
- For abuse-flag reports, the *truth* of the accusation. Verification confirms
  the report is a genuine, unaltered record of what was submitted and when — it
  is evidence of the submission, not an adjudication of it.

## Design notes

- Verification records are permanent and append-only; a dismissed accusation
  stays verifiable indefinitely, which is what makes the HR/court appeal path
  work after an independent reviewer has closed a case.
- The architecture (key families, zero-access sealing, the canonical payload)
  is described in the U4 build plan; this document is the procedure.
