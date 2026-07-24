# Pre-Upgrade Restore Points & Rollback

FireAlive's anti-rollback fuse refuses to start a build older than the highest one
a deployment has ever run. That is deliberate: it stops an attacker downgrading to
a version whose vulnerability was patched. It also means an upgrade is, by
default, a one-way door.

This document describes the way back: a **pre-upgrade restore point** taken from
the build you are about to replace, and an **offline rollback tool** that can put
that build back in front of its data — once, on the host, with the server stopped,
under an authorization the running server granted beforehand.

Nothing here touches the network. No restore point is transmitted anywhere and the
rollback is a local operation, so an air-gapped deployment keeps every part of
this capability.

## Why a restore point is the only way back

The anti-rollback mark lives in the database, in `node_state.fuse_high_water`, and
the boot gate halts a build whose fuse is below it. Two consequences follow, and
they are the whole reason this mechanism exists:

- **An uninstall does not reset anything.** Since P1 the data root lives at
  `~/.firealive/` and the installer only ever replaces program files. Reinstalling
  the older version leaves it facing a database that still records the newer
  build's mark, and it halts at boot.
- **An ordinary restore will not help either.** Restoring a pre-upgrade backup
  from the running (newer) console re-engages the anti-rollback ratchet, which
  takes the *higher* of the current and restored marks. The mark goes straight
  back up and the older build still refuses to start. That behaviour is correct —
  it is what stops a restore being used as a downgrade attack — and it is
  precisely why a rollback needs its own, separately-authorized path.

So the only artifact that makes a rollback possible is a backup taken **before**
the upgrade, at the old fuse and old schema, by the old build. It cannot be
produced afterwards. If you take one thing from this document: take the restore
point before you upgrade.

## Taking a restore point

From either console, when the update banner appears, choose **Take restore
point** — or take one at any time from Backup & Restore. It is an ordinary
full-suite backup: the same encrypted archive, the same Ed25519-signed manifest,
the same hardware-sealed key wrapping, verifiable by the same tooling.

Two things distinguish it:

- **Where it is stored.** `~/.firealive/restore-points/` on the Regional Server,
  `~/.firealive/gd-restore-points/` on the Global Dashboard — deliberately
  *outside* the data root. A rollback replaces the contents of the data root, so a
  restore point kept inside it would be destroyed by the operation it exists to
  serve. The directory is owner-only (0700) and, like the hardware keystore beside
  it, survives an uninstall.
- **What it records.** The fuse and version it was taken at, who took it, and an
  optional rollback authorization (below). The signed manifest carries the fuse
  independently, which is what the rollback tool actually trusts — it must not
  depend on a database it is about to replace.

If a restore point cannot be produced, the attempt fails **loudly** and says so.
An operator who believes they have a way back and does not is worse off than one
who knows they do not.

Copying a restore point to removable media is a plain file copy and entirely up to
you. FireAlive will not do it for you and has no mechanism to send it anywhere.

## Authorizing a rollback

A rollback consumes a **key-operation authorization** (`op='rollback'`). Like
every other key operation, it can only be *minted* by a running server, behind an
approved two-person request, and it is signed by the hardware anchor — a copied
disk cannot mint one. The offline tool verifies and consumes; it can never create.

There are two moments to mint it, and which you choose depends on a failure you
cannot predict:

- **After the upgrade**, if the new build still starts. Request it under Key
  Operations as normal. Valid one hour, which is ample to carry it to the tool.
- **Before the upgrade**, as a contingency. If the new build will not boot, there
  is no running server to mint anything — and that is exactly the case a rollback
  is for. A contingency authorization is minted alongside the restore point, while
  the deployment is healthy and can still authenticate properly, and is valid for
  30 days.

The longer window is bounded by the authorization's shape rather than by time. It
authorizes **one** restore point, on **one** host, **once** — and it is
**self-invalidating**: the tool requires the restore point to be exactly one
version below the current mark, so upgrading again voids any outstanding
authorization without anyone having to revoke it.

## Rolling back

The full operator procedure, including the exact command and per-platform paths,
is in **SETUP.md → Rolling back**. In outline:

1. Quit FireAlive completely.
2. Run the offline tool **from the currently installed (newer) version**, with
   `--dry-run` first. It ships inside that installation and reads the
   authorization and signing keys from the database it is about to replace, so
   running it before uninstalling is not optional.
3. Uninstall the newer version, install the previous one, and start it.

The restored node comes up with its configuration **locked**, requiring a hardware
unlock before any change — the same posture any restore leaves behind. The
database that was replaced is kept as a pre-restore snapshot and its path is
printed.

## What the tool refuses

Every one of these aborts the operation with nothing changed:

| Refusal | Why |
|---|---|
| the server is running | the swap renames a database over the live file; a running server would keep writing to an unlinked copy and silently lose every write |
| no authorization, or expired, already used, or tampered | the tool consumes authorizations, it cannot create them |
| authorization for a different operation or a different restore point | one authorization authorizes exactly one restore point |
| the restore point was already applied | single use |
| the bundle is incomplete | the store sits outside the data root precisely so it survives; if it is gone, it cannot be applied |
| the manifest signature does not verify against a key this deployment knows | refuses an unattributable bundle |
| the bundle was wrapped under a different KEK | refuses another deployment's backup, before the swap |
| the malware scan is failed, inconclusive, or no scanner is configured | fail-closed, inherited from the shared restore path |
| the restore point is not exactly one version back | bounds a rollback to a single step; go back one release at a time, each with its own restore point |

## Why this is a control and not a back door

This is the only operation in FireAlive that lets a build run below the recorded
anti-rollback mark, so it is worth being explicit about what constrains it.

Every capability it exercises was granted in advance by an authenticated
administrator on a working system, through an approved two-person gate, and signed
by the hardware anchor. The tool itself grants nothing. On top of that it requires
physical access to the host, a stopped server, and a signed bundle that this
deployment produced at that exact fuse, and it will only move one version. An
adversary able to satisfy all of that already controls the machine.

It has **no HTTP surface**: no route, no flag, no configuration option can reach
it, and a CI gate fails the build if any route file, or either server's `index.js`,
ever imports it. The same gate asserts it never re-engages the anti-rollback
ratchet — because a rollback that ratcheted would restore the old database and
then push the mark straight back up, leaving the operator exactly where they
started.

## Related

- `SETUP.md` — the step-by-step procedure, commands, and per-platform paths
- `docs/automatic-updates.md` — how you are notified an update exists
- `docs/full-suite-backup.md` — what a full-suite bundle contains
- `docs/configuration-lock.md` — the locked posture a restored node comes up in
- `docs/key-continuity-and-upgrades.md` — how keys and identity survive an upgrade
- `docs/tier1-kek-hardware-sealing.md` — the hardware root, and the recovery code
