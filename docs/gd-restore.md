# Global Dashboard Restore

Operator runbook for restoring the Global Dashboard (GD) Server's database:
from this instance's own backups, from another deployment's backups, and the
approval workflow that gates every destructive restore. It also covers the
trust material the GD uses to decide a backup is authentic before touching it.

This document describes shipped behavior. It is written for the CISO-level
administrators who operate the GD Server. Everything here lives behind
`authMiddleware(['ciso'])` and, for the destructive steps, a hardware-key
step-up.

## What a GD restore replaces

The GD Server keeps its state in a single SQLite database: the tamper-evident
audit chain, the forensic export chain, deployment configuration, the IAM
records, storage routing, and the compliance evidence the dashboard renders. A
restore replaces that live database wholesale with the contents of a verified
backup. It is not a merge and not a selective import — the database that was
running is swapped out for the one in the backup.

Because the swap is total and irreversible, the GD writes a **pre-restore
snapshot** of the current database next to the live file before it performs the
swap. If a restore turns out to be wrong, the pre-restore snapshot is the
recovery path; it is not automatic rollback, but it means the prior state is
never simply discarded.

## Two restore sources

The GD restores from two places, each with its own route namespace and its own
trust check.

**Internal restore** (`/api/restore`) restores from a backup this instance
produced. The instance already trusts its own backups, so the check is
integrity, not provenance: the backup's files must be present on disk and match
the recorded hash (v1) or manifest digest (v2).

**External restore** (`/api/external-restore`) restores from a backup a
*different* deployment produced — the disaster-recovery case where the original
host is gone and a fresh GD Server adopts the old deployment's data. Here
provenance matters: the external backup is signed, and the GD refuses it unless
the signing key is one the operator has explicitly registered as trusted (see
Trusted keys, below).

## Internal restore

List the instance's backups with `GET /api/restore/points`. Each entry reports
its type (full, incremental, or differential), format version, size, hash, and
creation time.

Selecting a backup calls `GET /api/restore/preview/:id`, which verifies the
backup on disk without changing anything. A v1 (single-file) backup reports
whether the file is present and matches its hash. A v2 (manifest) backup
reports whether every file the manifest lists is present on disk and whether
the manifest digest matches. The preview also reports whether an approval is
required for this deployment, and in which mode — this is what the UI uses to
decide between a direct execute and the approval flow.

Executing is split by backup type:

- `POST /api/restore/execute/:id` restores a single full backup.
- `POST /api/restore/execute-chain/:id` restores an incremental or differential
  chain: the base backup plus every increment up to the selected point, walked
  and replayed in order.

Both are gated by a hardware-key step-up and, outside disabled mode, by an
approval (see The approval workflow). A v2 restore rewrites multiple files and
recommends restarting the GD Server afterward so it re-reads the swapped
database cleanly; the execute response says so.

## External restore

External sources are registered first. Each source names an adapter and the
connection detail for a backup location the operator controls. Five adapters
ship: network share, NAS, S3, Azure Blob, and SFTP. A registered source can be
tested (`/sources/:id/test`) and browsed (`/sources/:id/browse`) to list the
backups it holds.

`/sources/:id/preview/:backupId` fetches enough of a candidate backup to verify
it: it checks the manifest signature and reports whether the signing key is one
this deployment trusts. If the structure is intact and the signature verifies
against a trusted key, the backup is eligible for restore. If the key is not
trusted, the restore is refused — register the source deployment's signing key
first.

External restore is always a two-step, approval-gated operation:

1. `POST /sources/:id/restore-request/:backupId` creates an approval row and
   returns its id and status.
2. `POST /restore-execute/:approvalId`, once the approval is approved, performs
   the destructive swap under a hardware-key step-up. A pre-restore snapshot is
   written, and the operation is recorded in the audit chain.

## The approval workflow

Every destructive restore — internal or external — consumes an **approval row**.
The approval mode is a deployment policy with three settings:

- **strict** — two-person. One CISO requests; a *different* CISO approves. The
  approver can never be the requester.
- **delayed-self-approval** — the GD default, and the single-CISO operational
  model. The same administrator who requested may approve, but only *after* the
  approval window has elapsed (24 hours by default). A second CISO may still
  approve immediately if one is available. The waiting window is the security
  property: it turns a stolen session into a delayed, auditable action rather
  than an instant one.
- **disabled** — no separate approval. The request is auto-approved at creation,
  so the execute step proceeds directly. This is the only mode in which a
  restore needs no queue interaction.

Requests, approvals, and denials are managed at `/api/restore-approvals` and
surfaced in the Restore Approvals tab:

- `POST /api/restore-approvals` creates a request for a backup.
- `GET /api/restore-approvals/pending` is the queue; `GET /api/restore-approvals`
  lists across all statuses.
- `POST /api/restore-approvals/:id/approve` approves, under a hardware-key
  step-up. The step-up is the second factor — a fresh, user-verified WebAuthn
  assertion — that the approval service requires before it will record an
  approval.
- `POST /api/restore-approvals/:id/deny` closes a request with an optional
  reason.

Two deadlines bound the lifetime of every row. A pending request expires if it
is not acted on within the window (in delayed-self-approval mode a hard expiry
follows at twice the window). An approved request must be *consumed* — used to
execute a restore — within one window of its approval; past that, the approval
is swept to expired and the restore route refuses it. This bounds the
stolen-approval surface: an approved-but-unused approval cannot sit idle for
days and then be replayed.

Internal restore in the default mode therefore reads: preview the backup,
request an approval, wait out the window (or have a second CISO approve),
approve it in the queue, then execute — all destructive steps under a
hardware-key step-up. In disabled mode it collapses to preview then execute.

## Backup signing keys

Backups are signed so that a restoring instance can prove who produced them.
The GD holds its own signing key and can present the public keys of other
deployments it is willing to restore from.

- `GET /api/backup/signing-keys` lists the current signing keys.
- `POST /api/backup/signing-keys/rotate` rotates this instance's signing key.
- `POST /api/backup/signing-keys/register-external` registers another
  deployment's public signing key, which is what makes that deployment's backups
  eligible for external restore.

An external backup whose signature does not verify against a registered key is
never restored. Registration is the deliberate, operator-controlled act of
extending trust to another deployment's backups.

## Configuration snapshots and trusted keys

Separate from database backups, the GD can snapshot its **configuration
baseline** — the golden record of how the deployment is set up — and compare or
restore it independently.

- `GET`/`POST /api/config-baseline` list and capture baselines.
- `GET /api/config-baseline/:id/diff` shows what changed against a baseline;
  `GET /api/config-baseline/:id/export` exports one.
- `POST /api/config-baseline/:id/revert` restores a baseline and
  `POST /api/config-baseline/import` imports one — both under a hardware-key
  step-up.

To verify a baseline exported by another deployment, the GD checks its
signature against a **trusted baseline key**. Those keys are managed at
`/api/config-baseline/keys`: paste a key, validate it, register it, or revoke
it. As with backup signing keys, an imported baseline signed by an unregistered
key is refused until the operator registers the key.

## Audit and residual risk

Every state change in this surface — a restore request, an approval, a denial,
a completed restore, a key rotation, a baseline revert — is written to the GD's
tamper-evident audit chain. Read-only listing and preview are covered by the
global audit middleware. The chain is append-only and hash-linked, so the
record of who restored what, and who approved it, cannot be silently rewritten.

This control set does **not** mitigate:

- An operator with shell access to the GD Server host, who can act on the
  database file directly and bypass every application control.
- Simultaneous compromise of two distinct CISO accounts in strict mode, or of a
  single CISO account across a full window in delayed-self-approval mode.
- Loss of the pre-restore snapshot before a bad restore is noticed — the
  snapshot is the recovery path, and it is only as good as the storage it sits
  on.

See also: [two-person-restore.md](./two-person-restore.md) for the Regional
Server's strict two-person model, [golden-baseline.md](./golden-baseline.md)
for configuration baselines, [backup-destinations-eu.md](./backup-destinations-eu.md)
and [storage-routing.md](./storage-routing.md) for where backups are written,
and [gd-backup-scheduling.md](./gd-backup-scheduling.md) for how they are
produced on a schedule.
