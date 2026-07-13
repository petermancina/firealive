# Key Continuity & In-Place Upgrades

How FireAlive preserves its encryption keys across an ordinary version upgrade,
and what the recovery code is — and is not — for. This document describes
shipped behavior. It is written for SOC administrators and team leads operating
the Regional Server / Management Console (MC) and the Global Dashboard (GD).

The short version: **a normal in-place upgrade preserves every key and every
sealed record. You drop in the new release on the same host and start it — no
re-keying, no re-encryption, no data loss, no recovery code needed.** The
recovery code is reserved for a different situation: recovering or moving the
deployment to a *new* key, which is the only case that touches the sealed data
at rest.

## What holds the keys together

FireAlive's most sensitive material — signing keys, CA private keys, peer
message keys, integration secrets — lives in Tier-1 columns, sealed at rest
under a Tier-1 key-encryption key (KEK). Depending on how you deployed, that
KEK is derived from a hardware root of trust on the host, from an environment
variable, or wrapped by a cloud KMS (AWS, Azure, GCP, or HashiCorp Vault). The
sealed ciphertext in the database is bound to that KEK.

Because the ciphertext is bound to the KEK, key continuity is really two
questions: *does an upgrade change the KEK?* (no) and *does an upgrade rewrite
the sealed bytes?* (also no). The sections below explain why, and what to do in
the one case where the KEK does change.

## Why an in-place upgrade preserves keys

An upgrade replaces the application code. It does not touch the KEK — the same
hardware root, environment variable, or KMS key is resolved by the new version
exactly as it was by the old one — and it does not re-seal the data at rest.
Sealed records are read and written on demand, under the KEK that is already
present. A new release therefore reads the existing sealed data with no
migration step and no window in which keys are exposed.

The seal format itself is versioned so that this stays safe over time. Every
sealed value carries a seal-format version, and each node records the highest
seal version it has ever seen. A newer release may introduce a newer seal
format and will read older ones transparently; it will **not** silently rewrite
your data at rest to the new format behind your back. And a node will refuse to
start under a release that only understands an *older* seal format than the data
it is holding — a downgrade is halted and the affected material quarantined,
rather than risking a mismatched read. This anti-rollback behavior is deliberate:
downgrading a security tool onto data it can no longer safely interpret is
exactly the kind of silent corruption a CISO cannot accept.

The practical consequence is that the upgrade runbook is boring, which is the
point:

1. Obtain the new release and validate it however your change process requires.
2. Stop the old version.
3. Start the new version on the same host, against the same database and the
   same KEK source.

That is the whole procedure. Nothing about keys changes.

## The one case that touches keys: moving to a new KEK

There is exactly one situation where the sealed data must be handled: when the
deployment moves to a **different** KEK. That happens when you rebuild a host
and its hardware root of trust changes, when you rotate to a new KMS key, or
when you migrate a deployment onto different infrastructure. In every one of
these cases the existing ciphertext is bound to the *old* KEK, and the new
environment resolves a *new* one.

FireAlive handles this explicitly rather than by weakening the binding. The
import re-key tool takes an exported deployment, recovers the *source* KEK from
the source deployment's recovery code, and re-seals every Tier-1 column from the
source KEK to the target's own KEK in a single atomic, fail-closed step. Nothing
is left half-converted, and the source key material is scrubbed from memory as
soon as the operation ends. The online import path handles same-KEK imports and
refuses a cross-KEK bundle up front, pointing you to the offline tool — so a
foreign-KEK import can never be applied by accident.

A related, narrower operation exists for high availability: when a standby is
promoted, it rebinds its replicated Tier-1 columns from the shared pairing key
to its own key, so the promoted node stands alone on its own root of trust.

## The recovery code is the sole disaster-recovery factor

The recovery code recovers the Tier-1 KEK. It is the **only** thing that can.
There is no escrow copy of the Tier-1 KEK held by a cloud KMS or by Anthropic,
and there is no back door, master key, or support-side reset that can stand in
for it. This is a design decision, not an oversight: an escrowed or
substitutable KEK would undermine the anti-clone guarantee that a FireAlive
deployment cannot be silently copied and run elsewhere. The strength of that
guarantee is exactly the absence of a substitute.

What this means operationally:

- **Keep the recovery code.** Generate it, store it under your existing
  break-glass procedure (an offline safe, a sealed secrets vault — wherever your
  organization keeps root credentials), and treat losing it as equivalent to
  losing the deployment's sealed data. For a normal in-place upgrade you will
  never touch it; for disaster recovery or a cross-KEK move you cannot proceed
  without it.
- **Retain old recovery codes across a re-key.** Re-keying is forward-only: it
  re-seals the *live* database to the new key, but exported backups and forensic
  archives stay under the key they were written with. To read an old backup you
  need the recovery code that was current when it was made.

If you take one thing from this document: an update costs nothing, and the
recovery code is the price of admission for everything an update deliberately
does not touch.
