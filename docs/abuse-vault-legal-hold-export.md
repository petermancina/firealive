# Abuse-Vault Legal-Hold Export

This document is for **abuse reviewers**, **CISOs**, and **recipients of a produced case file** (legal/HR counsel) who need to understand, operate, or independently verify FireAlive's two-person legal-hold export for vaulted abuse cases. It describes a control whose guarantee rests on **cryptography**, not on trusting the network, the server, or any administrator.

A legal-hold export takes a sealed abuse case out of the eternal-retention vault as a self-contained case file, under a rule that **two independent people must act**: an abuse reviewer requests it, and a CISO approves it. The approval is an Ed25519-signed decision token, and the reviewer's own device verifies that signature against an independently pinned CISO public key **before** any case file is assembled. A compromised server, a management-console administrator, a network attacker, or a rogue reviewer acting alone cannot forge an approval or unlock an export.

This is distinct from the forensic/backup legal-hold export documented in `docs/legal-hold-export.md` (the `legal_hold_exports` / `legal_hold_chain` feature). That export covers backup and forensic data for litigation holds; **this** export covers a single sealed peer-abuse case and is gated by the two-person, signed-token control described here.

## Why this exists

A vaulted abuse case contains the authentic, end-to-end-encrypted content that was flagged, the reporter's note, surrounding context, and the reviewer's locked determination. The vault is **eternal and append-only** — nothing deletes a vault row, ever. When that material is genuinely needed for a legal or HR matter, the legal-hold action exports a *copy*; the original persists forever. Because the material is sensitive and the action is consequential, it is placed behind a control that no single person can satisfy.

## The two-person guarantee

The guarantee does **not** depend on the channel, the regional server, or any administrator being honest:

- The requester is a regional **abuse reviewer** (in the Abuse Review Console, "ARC"). The approver is a **CISO** in a separate application and security realm (the Global Dashboard, "GD"), holding a distinct signing key.
- A CISO approval is an **Ed25519-signed decision token** over the specific request. The CISO's private key lives only on the GD side (Tier-1-encrypted; HSM-backed where available) and never leaves it.
- The reviewer's device verifies that token against a CISO public key the reviewer **pinned out of band**, independent of the server. A forged token, or a token signed by some other key the server tried to substitute, will not verify.
- The server-side request `status` is only an **advisory cache**. The authoritative gate is the signature check performed on the reviewer's device at produce time.

## The parties, and the reviewer ≠ CISO requirement

Separation of duties is enforced structurally in the codebase:

- A user holds exactly one role; no user is both a team lead and an admin.
- A team lead or admin may **never** be designated an abuse reviewer (the designation route refuses, and an admin cannot self-assign).
- The reviewer authority check (`canReview`) admits only the `abuse_reviewer` role, excludes any party to the case, and is scoped per assignment.
- The export request and produce routes are reachable only by an `abuse_reviewer`; management roles cannot reach them at all.

The one separation the software cannot enforce is **identity across the two realms**: nothing in code prevents the same human from operating both the ARC reviewer account and the GD CISO account. There is no shared identity map between the regional server and the Global Dashboard. Treat this as a governance requirement: **the reviewer and the CISO must be different individuals.** A deployment that collapses them has no real two-person control regardless of the cryptography.

## Lifecycle

1. **Request.** A reviewer opens a sealed case in the ARC and submits a legal-hold export request with a written rationale (minimum length enforced). One open request per case; the request is valid for a fixed approval window. A `LEGAL_HOLD_REQUESTED` entry is written to the custody chain.
2. **Relay out.** A background relay on the regional server pushes the request to dedicated Global Dashboard endpoints. The relay is "dumb": it carries opaque blobs and reuses the existing GD transport for connectivity only. It performs an allowed-host check before connecting.
3. **CISO decision.** In the GD, a CISO sees the request on the "Pending Legal-Hold Export Approvals" card and approves or denies it. Approving **mints** an Ed25519-signed decision token over a fixed, canonical payload (see below). Denying mints a signed denial.
4. **Relay back.** The regional relay polls for the decision. Before storing anything, it verifies the token's signature against the pinned CISO key **and** that the token binds this exact request — refusing on a bad signature or a mismatched binding. On success it records the token and writes `LEGAL_HOLD_APPROVED` or `LEGAL_HOLD_DENIED` to the chain.
5. **Produce.** When the reviewer chooses to produce, the ARC re-verifies the token on the device (signature + binding) and refuses if it does not check out. Only then does it assemble the watermarked, self-verifying case file from the already-decrypted material, download it, and record production. A `LEGAL_HOLD_PRODUCED` entry is written to the chain, and the request is marked consumed. **The vault row is never modified.**

## The signed decision token

The CISO signature is computed over a canonical payload with a fixed key order:

```json
{
  "request_id": "<export request id>",
  "flag_id": "<the abuse case id>",
  "mc_id": "<originating management-console / regional id>",
  "requested_by": "<reviewer user id>",
  "decision": "approved",        // or "denied"
  "decided_at": "<ISO-8601 timestamp>",
  "nonce": "<random nonce>"
}
```

The signature is Ed25519 over the UTF-8 bytes of that canonical JSON string. Verification requires three things to all hold: the token's key fingerprint equals the pinned CISO key's fingerprint; the signature verifies against that public key; and the payload binds the expected `request_id`, `flag_id`, and `decision`. Any tampering with a relayed field breaks the signature.

## Pinning the CISO approval key in the reviewer's console

Before a reviewer can produce an export, the ARC must hold the CISO's **public** approval key, pinned once, out of band. The pin lives only on the reviewer's device; it is never fetched implicitly from the server.

The fingerprint is the SHA-256 of the key's SPKI DER encoding, in lowercase hex:

```bash
# The CISO exports the approval PUBLIC key (PEM) and computes its fingerprint:
openssl pkey -pubin -in ciso_export_pub.pem -outform DER | openssl dgst -sha256
# -> the hex fingerprint the reviewer must confirm
```

The CISO communicates the public key and that fingerprint to the reviewer through a trusted, out-of-band channel (in person, signed message, or a separately verified document — not through the platform). In the ARC, on an approved request, the reviewer pastes the public key and the expected fingerprint. The ARC **recomputes** the fingerprint from the key bytes and refuses to pin if it does not match the value the reviewer entered — so a substituted key cannot be silently accepted. Re-pinning replaces the prior key (used for routine key rotation).

## Producing a case file

When the key is pinned and a request is approved, "Produce case file" performs, in order: verify the CISO token on the device (refuse on any failure), assemble the case file, download it, and record production. The case file is a self-verifying JSON document marked `RESTRICTED — Legal/HR`:

```json
{
  "document": "FireAlive Legal-Hold Case File",
  "classification": "RESTRICTED — Legal/HR",
  "generatedAt": "<ISO-8601>",
  "caseId": "<flag id>",
  "targetType": "...",
  "determination": "...",
  "resolutionNote": "...",
  "evidence": { "content": "...", "reporterNote": "...", "context": [ ... ] },
  "cisoApproval": {
    "payloadCanonical": "<the exact signed JSON string>",
    "signature": "<hex Ed25519 signature>",
    "keyFingerprint": "<sha256 hex>",
    "verifiedAgainstPinnedKey": true,
    "decidedAt": "...",
    "nonce": "..."
  },
  "chainReference": { "requestId": "...", "flagId": "..." }
}
```

The decrypted evidence is assembled only on the reviewer's device; the server never sees it. The embedded `cisoApproval` block makes the file **independently verifiable** by a recipient, as below.

## Verifying a produced case file offline

A recipient (counsel, an auditor) can confirm a case file was authorized by the named CISO, without any FireAlive tooling, using OpenSSL. You need the case file and the CISO's published public key (`ciso_export_pub.pem`), obtained through your own trusted channel.

```bash
# 1. Confirm the public key matches the file's claimed fingerprint.
openssl pkey -pubin -in ciso_export_pub.pem -outform DER | openssl dgst -sha256
#    Compare the hex output to cisoApproval.keyFingerprint in the case file.

# 2. Extract the signed payload and signature from the case file.
#    (jq shown for convenience; any JSON tool works.)
jq -rj '.cisoApproval.payloadCanonical' case.json > payload.json
jq -rj '.cisoApproval.signature'        case.json | xxd -r -p > sig.bin

# 3. Verify the Ed25519 signature (one-shot, raw input).
openssl pkeyutl -verify -pubin -inkey ciso_export_pub.pem \
  -rawin -in payload.json -sigfile sig.bin
# Expected: Signature Verified Successfully

# 4. Confirm the payload binds this case.
jq '.cisoApproval.payloadCanonical | fromjson
    | {request_id, flag_id, decision}' case.json
#    flag_id must equal caseId; request_id must equal chainReference.requestId;
#    decision must be "approved".
```

If all four hold, the file carries a valid approval from the holder of that CISO key, bound to this specific case and request. If the fingerprint does not match your trusted copy of the CISO key, or the signature fails, do not rely on the file.

## The custody chain

Every lifecycle event is recorded in `abuse_vault_chain`, an append-only, hash-chained, Ed25519-signed ledger (with database triggers that reject any UPDATE or DELETE). Each entry's `this_hash` is `SHA-256(prev_hash || canonical(payload))`, and the payload is reconstructable from the row's columns, so the chain can be re-derived and re-verified independently. The chain records `VAULT_SEALED` and the full `LEGAL_HOLD_REQUESTED` / `APPROVED` / `DENIED` / `PRODUCED` lifecycle. The chain is scoped to the reviewer/CISO context and is **never readable from the management console**.

## What these controls do — and do not — do

State this plainly to anyone who relies on an export:

- **What is enforced:** two independent authorizations (a reviewer's request and a CISO's signed approval), a recorded rationale, an append-only custody chain, and a restricted-purpose watermark on the produced file.
- **What is not enforced:** once two authorized people hold an exported file, software cannot control where the file then goes. The watermark and the recorded rationale are accountability measures, not destination enforcement.

The verifiable nature of an export is a chain-of-custody and authenticity property. It is **not** an escalation or appeal mechanism, and it must never be described as a way for any party to go over a reviewer's head or to relitigate a locked determination. Determinations are one-shot and final; the export does not reopen them.

## Privacy properties

- **No management-console involvement, anywhere in the path.** A team lead never learns that an export was requested, approved, or produced. The only actors are the abuse reviewer (ARC) and the CISO (GD).
- **Audit-silence on the flag/export path.** There is no flagger-identifying, management-readable audit entry on this path; the custody chain is the record.
- **Zero-access.** The server never receives the decrypted case material; assembly and decryption happen only on the reviewer's device.
- **Eternal retention.** The export copies the case; the vault original is never deleted.
- **Key separation.** The report-signing key, the abuse-vault chain key, the CISO approval key, and the existing forensic/backup/chain key families are all distinct.

## Code layout summary

- `server/services/abuse-vault-chain.js` — the append-only signed custody chain (`appendEntry`, `verifyChain`).
- `server/services/abuse-export-ciso-trust.js` — the regional pinned-CISO-key trust store and `verifyWithPinnedKey`.
- `server/services/abuse-export-sync.js` — the dumb relay (push requests, poll decisions, verify before persisting).
- `server/routes/abuse-vault-export.js` — the reviewer-only request, read, and produce-record routes.
- `packages/global-dashboard-server/services/abuse-export-approval-keys.js` — the CISO approval key family and decision-token minting.
- `packages/global-dashboard-server/index.js` — the GD ingest / status / pending / approve / deny endpoints.
- `packages/global-dashboard/global-dashboard.jsx` — the CISO "Pending Legal-Hold Export Approvals" card.
- `packages/abuse-review-console/main.js` — CISO-key pinning and on-device token verification (`abuse:pinCisoKey`, `abuse:verifyExportToken`).
- `packages/abuse-review-console/abuse-review-console.jsx` — the reviewer's request and produce flow.
