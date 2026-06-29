# Storage Routing, Guaranteed Dual-Write, and Replication Status

Operator runbook for how a FireAlive deployment decides where each kind of
retained data is written, how it guarantees a second copy lands, how that copy
is kept gap- and tamper-evident, and how to read whether replication is keeping
up.

This document describes shipped behavior. It is written for SOC administrators
and team leads operating the Regional Server and Management Console (MC). It
assumes familiarity with the backup, audit-log, and forensic-export features
documented separately; this runbook is about *routing and replicating* their
output, not about producing it.

## Destinations and routes are different things

A **destination** is a place a copy can land. A **route** maps a kind of data to
the destinations it is written to. They are configured separately and on purpose:
you register a destination once, then point any number of data types at it.

A destination has an adapter (one of `local`, `sftp`, `s3`, `azure-blob`, `gcs`),
its connection config, optional credentials, an immutability mode, and an
optional retention. Credentials are encrypted at rest, decrypted just-in-time on
the server for a push or a connectivity test, and never returned to the client —
the destination list and the console never hold a secret.

A route names, per data type, a **primary** destination and an optional
**secondary**. It is set in the routing section of the MC or through the API.

## The five routed data types

| Data type         | What it is                                            |
|-------------------|-------------------------------------------------------|
| `backup`          | Daily full and on-demand backups                      |
| `snapshot`        | Point-in-time captures (before config changes, manual)|
| `audit_log`       | The append-only, tamper-evident audit chain           |
| `forensic_export` | Chain-of-custody-signed forensic exports              |
| `cef_archive`     | The archived SIEM CEF event feed                       |

`snapshot` is special: if it has no usable destination of its own, it **inherits
the `backup` route**. Configure a snapshot route only when you want snapshots to
go somewhere different from backups.

## The dual-write model — a concurrent second copy, not failover

Each routed type is written to its primary and, if set, its secondary
destination **on every run**. This is concurrent dual-write, not active-passive
failover: the secondary is not a standby that is only used when the primary is
down — it receives its own copy every time.

"Primary" and "secondary" are an ordering, not a priority of reliability. The
primary's push is the one whose status a backup surfaces, and for the archive
chains the primary push is what advances the integrity chain; the secondary is an
independent second copy.

On-host storage plus a primary remote plus a secondary remote satisfies the
**3-2-1 rule** (three copies, two media, one off-site) for that data type. A
second destination is what lets the data survive the loss of one location, which
is why frameworks expect one for anything you are obliged to retain.

The secondary must be a different destination from the primary; the server
rejects a route that names the same destination twice.

## Guaranteed replication — retries, not hope

"A copy already exists in each destination" only holds if both writes reliably
happen. Every push — primary and secondary, for all five data types — is tracked
in a push-tracking table and retried on failure:

- Up to **5 attempts** per destination.
- Backoff between attempts of roughly **5 minutes, 30 minutes, 2 hours, then 12
  hours**.
- A push that exhausts its attempts is marked a **permanent failure** (its next
  retry time is cleared) and stays as a failed row for the operator to see. It is
  never silently dropped.

A scheduled **replication retry sweep** (by default a few minutes past the hour)
picks up failed-but-not-exhausted pushes and retries them. A separate scheduled
**archival sealing** job (also hourly by default) drains new audit-log rows and
the CEF spool into their chains before they are pushed. Both jobs run only on the
node that currently holds write authority, so an HA pair does not double-write.

## What is archived, and how it stays trustworthy

Two of the routed types are produced by archival writers that exist so the data
is retained at all:

- **Audit log.** New audit-log rows are sealed into an append-only `audit_log`
  segment chain. The chain is self-describing: the next batch starts from the
  highest record already archived, and because the audit table forbids deletion
  the cursor cannot move backward.

- **CEF archive.** The SIEM CEF feed is otherwise fire-and-forget. A crash-safe,
  order-preserving spool captures every forwarded CEF line and seals accumulated
  lines into a `cef_archive` chain — so the events you forwarded to your SIEM are
  also retained under your own routing and residency policy, even when the SIEM
  is unreachable.

Both chains are gap-evident and tamper-evident and are verified independently of
where their copies land. Backups and forensic exports carry their own integrity
(signing keys, chain-of-custody signatures) documented in their own runbooks.

## Immutability

Each destination declares an immutability mode, constrained to what its adapter
supports:

- `none` — no object-level immutability (amber in the console; acceptable for
  some types, weak for audit logs).
- `append-only` — the destination prevents overwrite of existing objects.
- `object-lock` — write-once-read-many retention (S3 Object Lock, Azure
  Immutable Blob, GCS retention) — the strongest mode, available on the cloud
  adapters.
- `unknown` — not yet verified.

Set the mode to reflect what the destination is actually configured to enforce;
it is a declaration the console surfaces, not a switch that configures the remote
bucket for you. Configure the bucket's lock policy in your cloud provider, then
declare it here.

## Encrypt before it leaves

Only FireAlive-encrypted ciphertext (the `FA-ENC1` envelope) is ever transmitted
to a destination. Encryption happens before the push; a destination — including a
third-party cloud bucket — never receives plaintext. This is independent of
whatever encryption the destination itself applies at rest.

## Data residency

A destination is declared and evaluated **per data type it serves**. The same
bucket can be compliant for backups and non-compliant for forensic exports,
because residency policy is set per category. The routing system enforces the
primary destination's residency at write time (fail-closed), and the data-
residency reconciliation records any cross-border transfer the route implies.

Declare a destination's jurisdiction in the data-residency panel, choosing the
data type from the selector. See `data-residency.md` for the policy model,
permitted regions, the transfer register, and the legal-mechanism documentation
workflow.

## Reading replication status

The routing section shows, per data type, a **health badge** and a per-role
breakdown drawn from the actual push history. Health is one of:

- **idle** — nothing has been pushed yet (a fresh route, or a type with no
  activity). Neutral.
- **healthy** — recent pushes succeeded and nothing is outstanding.
- **pending** — copies are in flight (queued or running). Normal operation.
- **degraded** — there are transient failures being retried. Recoverable; watch
  it.
- **failing** — there are permanent failures. **A copy is not protected. Act.**

The breakdown reports, for the primary and the secondary, the destination, the
counts (succeeded / pending / retrying / failed), and a relative last-success or
oldest-pending time, with the most recent permanent-failure message when there is
one. The data type's overall badge is the most severe of its roles.

The status is computed correctly per type: backups and snapshots share a push
table but are distinguished by the backup's type, audit logs and CEF archives
share a push table but are distinguished by the segment category, and a push
counts toward a role only if it targeted that role's *current* destination — so
changing a route does not leave stale history polluting the new destination's
health.

A **failing** badge means retries have been exhausted for a copy. Investigate the
destination (use **Test** on it in the registry to check connectivity), fix the
underlying problem (credentials, capacity, network, bucket policy), and the retry
sweep will resume — or trigger a re-check.

## Doing it in the console

All of this lives in the MC under **Backup, Recovery & Storage Routing**.

1. **Register destinations.** In *Storage Destinations*, add a destination,
   choosing the adapter and filling its location and (if needed) credentials, the
   immutability mode, and an optional retention. Use **Test** to confirm
   connectivity without writing anything. Edit, enable/disable, or remove from the
   same list. A destination with push history cannot be removed (to keep audit
   continuity) — disable it instead.

2. **Route data types.** In *Storage Routing*, set each type's primary and
   optional secondary destination, an optional path prefix, and whether the route
   is enabled. **Save** per type; **Test** probes the routed destinations. Invalid
   choices (a disabled destination, a residency-blocked region, the same
   destination for both roles) are refused with the reason shown inline.

3. **Declare residency.** In the data-residency panel, pick the data type and
   declare each destination's jurisdiction. See `data-residency.md`.

## API reference

All endpoints are admin-only and behind the config-write chokepoint.

**Destinations** — `/api/storage-destinations`

- `GET /` — list destinations (no credentials).
- `GET /adapters` — available adapters and their supported immutability modes.
- `POST /` — create a destination.
- `PATCH /:id` — update fields, enable/disable; omit credentials to keep the
  stored ones.
- `DELETE /:id` — remove (refused with `has_push_history` if it has pushes).
- `POST /:id/probe` — connectivity test (credentials decrypted just-in-time,
  nothing written).

**Routing** — `/api/storage-routing`

- `GET /` — every data type's route, with resolved destination names.
- `GET /replication` — per-type replication health (the status above).
- `GET /:type` — one route.
- `PUT /:type` — set a type's primary, secondary, path prefix, and enabled flag;
  validated against the immutability and residency gates (a typed failure names
  the offending side).
- `POST /:type/test` — probe the type's routed destinations.

**Residency** — `/api/data-residency` (see `data-residency.md`)

- `GET/PUT /config`, `GET /destinations?category=<type>`,
  `PUT /destinations/:ref`, `GET/PUT /transfers`, `POST /evaluate`,
  `GET /posture`.

## On upgrade

After upgrading into this feature, no routes exist yet; retained data stays
on-host until an admin configures a route. Register your destinations, set a
primary and (strongly recommended) a secondary for each data type you must
retain, declare their residency, and confirm each type reads **healthy** once
pushes have run.
