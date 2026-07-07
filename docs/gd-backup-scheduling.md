# Global Dashboard Backup Scheduling

Operator runbook for scheduling automated backups of the Global Dashboard (GD)
Server's database: how often they run, what kind of backup each produces, how
long copies are kept, and how the regulatory presets translate a compliance
obligation into concrete schedule settings.

This document describes shipped behavior. It is written for the CISO-level
administrators who operate the GD Server. Scheduling lives behind
`authMiddleware(['ciso'])` at `/api/backup-schedules` and is driven from the
Backup Schedules tab.

## What a schedule does

A schedule is a standing instruction to back up the GD Server's database on a
recurring basis, without an operator initiating each run. The scheduler records
when each schedule last ran, whether that run succeeded, and when it is next
due, so the tab doubles as a health view of the backup program.

Where the resulting backups are *written* is not part of the schedule — that is
decided by storage routing (see [storage-routing.md](./storage-routing.md)). A
schedule decides *when* and *what*; routing decides *where*.

## Creating a schedule

A schedule carries a name and four choices that together define its behavior.

**Frequency** — how often the backup runs. Five options ship:

- **hourly** — once an hour.
- **interval** — every N minutes, for a custom cadence between the hourly and
  sub-daily extremes. The interval is floored to a sane minimum so a schedule
  cannot be set to hammer the server every few seconds.
- **daily** — once a day at a chosen time.
- **weekly** — on a chosen day of the week at a chosen time.
- **monthly** — on a chosen day of the month at a chosen time.

The frequency is also the schedule's **recovery point objective (RPO)**: the
most data you can lose if the database is destroyed between runs. An hourly
schedule bounds loss to about an hour; a daily schedule, to about a day. The tab
states the resulting RPO as you choose the frequency so the trade-off between
run cost and data-loss exposure is explicit.

**Backup type** — what each run produces:

- **full** — a complete copy of the database. Self-contained and the simplest to
  restore, but the largest.
- **incremental** — only what changed since the previous backup of any kind.
  Smallest to write, but a restore must replay the whole chain back to a full.
- **differential** — everything changed since the last *full* backup. Larger
  than an incremental, but a restore needs only the full plus one differential.

Incremental and differential backups exist to keep frequent schedules cheap;
the restore side walks and replays the chain (see
[incremental-differential-chains.md](./incremental-differential-chains.md) and
[gd-restore.md](./gd-restore.md)).

**Retention** — how long copies are kept before the scheduler prunes them.
Retention is the other half of a compliance obligation: a framework that
requires you to be able to restore to a point 90 days ago is only satisfied if
retention actually holds 90 days of backups.

**Encryption** — on by default. Backups are encrypted at rest; a schedule can in
principle be created without it, but a regulatory preset that requires
encryption locks it on (below).

## Regulatory presets

A preset packages a compliance framework's backup expectations into schedule
defaults so an operator does not have to translate a control into settings by
hand. Each preset carries a minimum retention, a required encryption setting, a
recommended frequency, and a citation to the framework clause it comes from.

Applying a preset to a new schedule:

- pre-fills the recommended frequency,
- raises retention to at least the preset's minimum, and
- if the preset requires AES-256, turns encryption on and **locks** it, so the
  schedule cannot be saved in a state that violates the framework.

The citation is shown alongside, so the schedule carries its own justification:
an auditor can see not just that a 90-day encrypted daily backup exists, but
which obligation it was created to satisfy. A preset is a starting point, not a
ceiling — an operator may keep backups longer or run them more often than the
preset recommends, but not less.

## Overlap detection

Two schedules whose runs land close together waste effort and can contend for
the same resources. When a schedule is created, the scheduler checks its
projected fire times against existing schedules within a fixed overlap window.
If any collide, the create is refused with a `SCHEDULE_OVERLAP` response naming
how many fire times conflict.

This is a guardrail, not a hard prohibition. If the overlap is intentional —
two backup types that are meant to run on the same cadence, for example — the
create is retried with `force_queue=true`, which accepts the overlap and lets
the runs queue rather than collide. The default refusal simply makes an
accidental double-schedule something the operator has to confirm on purpose.

## Managing schedules

Existing schedules are listed with their last run, last status, and next due
time. Each can be:

- **paused or resumed** by toggling its active flag — a paused schedule stays
  configured but does not fire.
- **deleted** when it is no longer needed.

Pausing is the safe way to suspend a backup program temporarily (during a
migration, say) without losing the schedule definition; deleting is permanent.

## Residual risk

Scheduling automates *producing* backups; it does not by itself guarantee they
are recoverable. A schedule that runs successfully but writes to a destination
that later fails, or whose retention is shorter than the recovery window an
incident actually needs, will still leave a gap. The controls that close those
gaps live elsewhere: storage routing and destination health for *where* backups
land, and the restore runbook for verifying and consuming them.

This control does **not** mitigate:

- A storage destination that is silently failing — a schedule reports its own
  run status, not the durability of the copy at rest. Pair scheduling with the
  destination probes in [storage-routing.md](./storage-routing.md).
- A retention window set shorter than the obligation it was meant to satisfy —
  the preset raises retention to its minimum, but an operator who overrides it
  downward afterward is on their own.
- An operator with database-file access, who can act outside the scheduler
  entirely.

See also: [gd-restore.md](./gd-restore.md) for restoring what these schedules
produce, [storage-routing.md](./storage-routing.md) for where backups are
written, [full-suite-backup.md](./full-suite-backup.md) and
[incremental-differential-chains.md](./incremental-differential-chains.md) for
backup composition, and [backup-destinations-eu.md](./backup-destinations-eu.md)
for residency-constrained destinations.
