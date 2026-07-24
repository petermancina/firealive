# Automatic Update Detection

Operator runbook for how FireAlive tells you that a newer release is available.
The feature is **detect-and-notify only**: FireAlive checks this project's
GitHub Releases, tells you when a newer stable release exists, and stops there.
It never downloads, stages, lab-tests, or installs an update. You download the
new release from GitHub, validate it however your change process requires, and
apply it on your own schedule.

This document describes shipped behavior. It is written for SOC administrators
and team leads operating the Regional Server / Management Console (MC) and the
Global Dashboard (GD).

## Why detect-and-notify, and nothing more

Auto-applying an update to a production security tool is bad practice, and the
mature SIEM/SOAR pattern reflects that: the platform performs a pull-based
version check and surfaces the result, while the actual upgrade stays a
deliberate, change-managed action an administrator takes. FireAlive follows
that pattern exactly.

The deployment reality reinforces it. FireAlive is self-hosted inside your
security-operations stack and distributed only through GitHub Releases. There
is no FireAlive-operated update server to poll, and the Electron installers are
not code-signed, so there is no signed auto-update feed to trust. The honest,
CISO-defensible choice is to surface the signal reliably and leave the apply
decision — including any lab validation and the timing — entirely with you.

## What it does

- Issues `GET https://api.github.com/repos/petermancina/firealive/releases/latest`.
- `/releases/latest` returns only the newest **stable** release; GitHub
  pre-releases are skipped. During the pre-release era (before the first stable
  release is cut), GitHub returns `404`, which FireAlive treats as a valid
  "no stable release yet" result — not an error and not an update.
- Compares the release tag to the running version and reports an update as
  available **only** when the tag is strictly newer.
- Records every check in an append-only log and surfaces the latest result in
  the app.

It lights up the moment the first real release is published, and thereafter on
each subsequent release.

## Where it runs (central-check)

- The **Regional Server** performs the check on behalf of the MC and the
  analyst-client (AC) suite. Analyst clients never call GitHub and never
  self-update.
- The **GD-server** performs the check for the Global Dashboard.

Each side is independent and self-hosted. Neither contacts a FireAlive-operated
service, because there is none — the only outbound destination is GitHub.

## The properties that make it safe

### Opt-in, off by default

The feature ships disabled on both sides. An air-gapped deployment that never
enables it makes no outbound call at all. Enable it per side from the MC Updates
tab and/or the GD App Updates tab.

### Zero telemetry

The check is a plain `GET` carrying only a `User-Agent` and an `Accept` header.
There is no request body and no query string. Nothing about your deployment —
version, identity, environment, or anything else — is sent to GitHub beyond what
any anonymous `GET` to a public release endpoint necessarily reveals.

### Fail-safe

Any network error, timeout, unexpected status, or oversized response resolves to
`source_unreachable`. The check never reports "up to date" when it could not
actually reach the source, and a `source_unreachable` result never clears a
standing "update available" — so a flaky network cannot make a real update
silently disappear.

### Anti-rollback

An update is reported as available only when the release tag is strictly newer
than the running version. A downgrade, an equal version, or a malformed tag is
never surfaced as an update. This complements the deployment anti-rollback fuse,
which independently refuses to install an older build over a newer one.

## How you are notified

- **Persistent in-app banner (primary).** When a newer version is detected, a
  banner appears at the top of every screen with the new version and a link to
  the GitHub release. It is dismissible per version: once you dismiss it for a
  given version it stays dismissed for that version, and it reappears when a
  still-newer version is later detected. The banner clears automatically once
  the running version catches up.
- **Optional once-per-version channel notice (MC only).** If you enable "notify
  the team lead," the lead and admins receive one notification per new version
  through their configured channels (the same channels FireAlive already uses).
  It fires once per version, never repeatedly. The GD is read-only and has no
  notification channels, so it is banner-only.

## Configuring it

On the MC, open the **Updates** tab; on the GD, open the **App Updates** tab.
Both expose the same controls:

- **Enable automatic update checks** — off by default.
- **Frequency** — daily, weekly, or monthly.
- **Day of week** (weekly) or **day of month** (monthly, 1-28).
- **Time (UTC)** — when the scheduled check runs.

All scheduling is in **UTC**. The scheduled check is cadence-based: on each
internal tick the server runs a check if a daily/weekly/monthly boundary has
passed since the last scheduled check, so a window missed while the server was
down is picked up on the next run rather than skipped.

**Check now** runs an immediate check regardless of schedule. It is rate-limited
to roughly once per minute to keep manual clicks from hammering the endpoint;
the manual check updates the last-check display but never fires the channel
notice.

## What to allow-list

The only outbound destination is `api.github.com` over HTTPS (443). If your
egress is restricted:

- Allow `api.github.com` for the Regional Server if the MC/AC suite should check.
- Allow `api.github.com` for the GD-server if the Global Dashboard should check.
- Allow nothing for analyst clients — they never make the call.

If you do not want any outbound call from FireAlive, leave the feature disabled
on both sides and watch the GitHub Releases page manually.

## What it deliberately does NOT do

- **No download, staging, lab-routing, or installation.** FireAlive detects and
  notifies; it does not move bits.
- **No configurable update URL.** The source is hardcoded to this repository's
  GitHub Releases. There is no operator-set endpoint, which removes an SSRF
  surface and any dead configuration.
- **No bundled-model update checking.** Local model bumps ship as part of a new
  pinned FireAlive release; they are handled by the project's supply-chain
  process, not by this runtime check.
- **No code-signing or signed-update feed.** The Electron installers are
  unsigned; validate downloads against the published GitHub release.

## Evidence and audit

Every check is recorded in the append-only `auto_update_check_log` table (present
on both the Regional Server and the GD): the timestamp, the running version, the
result (`none` / `available` / `source_unreachable`), the newer tag and release
URL when one is found, whether a notification has fired for that version, and the
trigger (`scheduled` or `manual`).

Check runs are written to the audit log as `UPDATE_AVAILABLE`,
`UPDATE_SOURCE_UNREACHABLE`, or `UPDATE_CHECK_RAN`, and configuration changes are
recorded as `AUTO_UPDATE_CONFIG_SET`. The full-suite regression runner includes
an `auto_update` category on both sides, covering the evidence table, the check
service and its exports, the version-comparison logic (run without network), and
config readability.

## Applying an update (your responsibility)

When you are notified that a new version exists:

1. Read the release notes on the linked GitHub release.
2. **Take a pre-upgrade restore point** from the banner or Backup & Restore, and
   -- if a failure to boot would leave you unable to authenticate -- mint a
   contingency rollback authorization at the same time. This is the step that
   makes a rollback possible at all, and it can only be taken from the build you
   are about to replace. See `docs/pre-upgrade-restore-point.md`.
3. Download the installer for your platform from that release.
4. Validate it according to your change-management process (for example, install
   and exercise it in a lab or staging deployment first).
5. Install it on the production host. The anti-rollback fuse advances when the new
   build first starts, and an older build will then refuse to run against that
   data -- so the restore point from step 2 is your only way back.

FireAlive performs none of these steps for you, by design. Detection keeps you
informed; the upgrade remains a deliberate action you own.
