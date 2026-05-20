# Training Library — Schema, Seed, Recommender, Review Workflow

This document covers the training-library subsystem shipped in R3l (v1.0.37): the schema that stores training platforms and modules, the seed catalog of vetted modules, the gap-driven recommender that surfaces modules to analysts, the AC submission form analysts use to report completions, and the MC review queue that lets leads verify or reject those submissions.

This is **not a general overview** of the FireAlive platform. For the privacy architecture see `FEATURE-GUIDE.md` and `Security.md`. For the IAM and assessment subsystems that feed the recommender's gap detection see the corresponding sections of `FEATURE-GUIDE.md`. This document covers only what R3l adds on top of the existing assessment infrastructure.

## The four data flows in scope

```
                  ingest: seed catalog
       SQLite DB  ◀──────────────────────────────────────  training-modules-seed.json
                  server/db/seed-training-library.js
                  (loader, runs at boot via init.js)


                  read: gap-driven recommendation
                  GET /api/training-recommendations/me
       Analyst   ◀──────────────────────────────────────  Regional Server
       (AC)       (analyst role, Tier-3 self-read)


                  write: completion submission
                  POST /api/training/submit-completion
       Analyst   ──────────────────────────────────────▶  Regional Server
       (AC)       (analyst role, Tier-3 self-write)


                  review: lead/admin verify or reject
                  GET, PATCH /api/training/completions-review
       Lead      ◀────────────────────────────────────▶  Regional Server
       (MC)       (lead or admin role, Tier-1 surface)
```

The four flows form a closed loop: an authoritative seed populates the catalog, the recommender selects from the catalog based on each analyst's measured skill gaps, analysts complete modules and self-report, and leads validate those reports. No flow crosses the Tier-3 boundary into the lead's view except in the explicit form of a training-completion record, which carries no wellbeing signals.

## Schema

Two tables are created in `server/db/init.js`:

**`training_platforms`** — one row per training provider. Columns: `id` (auto-increment), `slug` (e.g., `tryhackme`, `hackthebox`), `name` (display name), `base_url` (canonical site root), `category` (e.g., `blue-team`, `general`), `is_active` (boolean), `created_at`.

**`training_modules`** — one row per module the recommender can surface. Columns: `id` (auto-increment), `platform_id` (FK to `training_platforms.id`), `external_id` (the platform's own identifier when known), `title`, `url`, `skill_tag` (the assessment skill this module addresses, e.g., `phishing-analysis`), `difficulty` (`beginner` | `intermediate` | `advanced` | `expert`), `estimated_hours`, `free_or_paid`, `is_active` (boolean), `created_at`.

### The `url_legitimacy` CHECK constraint

`training_modules.url` carries a SQL CHECK constraint that allowlists hostnames. Only URLs matching one of these prefixes can be inserted:

- `https://tryhackme.com/path/outline/%`
- `https://academy.hackthebox.com/course/preview/%`
- `https://cyberdefenders.org/blueteam-ctf-challenges/%`
- `https://www.sans.org/cyber-security-courses/%`
- `https://app.letsdefend.io/%` (currently no modules; constraint retained for future re-add)
- `https://www.immersivelabs.com/career-paths/%` (currently no modules; constraint retained for future re-add)
- `https://app.immersivelabs.com/%` (currently no modules; constraint retained for future re-add)

The constraint is structural defense against stale, spoofed, or attacker-supplied URLs. Even a compromised maintainer cannot insert a `bit.ly` link or a phishing domain — the row insert fails. SQLite does not support `ALTER TABLE DROP CONSTRAINT`, so prefixes for platforms that lost their seed entries (LetsDefend, Immersive Labs) remain in the allowlist; tightening the schema would require a table-recreation migration, deferred until a future commit if a reviewer asks for strict-allowlist enforcement at the DB layer.

## The seed catalog

`server/db/training-modules-seed.json` contains the canonical list of training modules the platform ships with. Structure:

```
{
  "version": "0.0.24-r3l-c2-cleanup",
  "generated_at": "2026-05-19",
  "source": "URLs sourced exclusively from each platform's own official catalog page",
  "verification_note": "<explanation of the cleanup rationale>",
  "platforms": [ { "slug": ..., "name": ..., "base_url": ..., "category": ... }, ... ],
  "modules": [ { "platform_slug": ..., "external_id": ..., "title": ..., "url": ..., "skill_tag": ..., "difficulty": ..., "estimated_hours": ..., "free_or_paid": ... }, ... ]
}
```

The loader at `server/db/seed-training-library.js` reads this file at server boot, upserts the platforms, then upserts the modules with `platform_id` resolved by `platform_slug` lookup. Upserts use `INSERT OR REPLACE` keyed on `(platform_slug, external_id)` for platforms with stable external IDs and `(platform_slug, url)` otherwise.

### Current coverage

229 modules across 4 platforms:

| Platform | Modules | Source page |
|---|---|---|
| TryHackMe | 7 learning paths | `tryhackme.com/paths` |
| HackTheBox Academy | 158 courses | `academy.hackthebox.com/catalogue` |
| CyberDefenders | 43 challenges | `cyberdefenders.org/blueteam-ctf-challenges/` |
| SANS | 21 courses | `sans.org/cyber-security-courses` |

46 of the 73 tracked assessment skills currently have at least one module in the catalog. The remaining 27 skills surface "No training modules available for this skill yet — flag to your lead so the maintainers can add some." in the AC's Training tab, rather than fabricating a recommendation.

### URL provenance rule

**Only links obtained from the platform's own official catalog page are eligible for inclusion in the seed.** This rule was established during the R3l C2fix cleanup, after the original C2 seed was found to contain 376 URLs sourced from community-maintained GitHub indexes (Hunterdii/TryHackMe-Roadmap and adnan-kutay-yuksel/letsdefend-all-courses-database) plus 5 URLs that were pattern-extrapolated rather than verified. Those 381 entries were removed in the C2fix purge.

Pattern-extrapolated URLs are forbidden even when the pattern looks obvious — the C2fix audit found that `https://www.immersivelabs.com/career-paths/<slug>` URLs do not exist on the platform's actual public marketing site (Immersive Labs's career paths live behind authentication on `support.immersivelabs.com` and `app.immersivelabs.com`).

### Platforms not currently in the seed

**LetsDefend** (acquired by HackTheBox in September 2025): 185 community-sourced URLs were removed in C2fix. Re-adding requires an authoritative catalog from the platform itself; outreach has been opened via the consolidated HackTheBox channel.

**Immersive Labs**: 5 pattern-extrapolated URLs were removed in C2fix. Re-adding requires guidance from the platform on the right URL pattern for an external app to deep-link to a specific lab or career path, since most content lives behind enterprise authentication. Outreach has been opened.

Future maintainer commits that re-add either platform must source URLs directly from the platform (via correspondence with their team or by browsing an authoritative catalog the platform publishes) and document the source in the C-commit description.

## Recommender flow

The AC's Training tab fetches `GET /api/training-recommendations/me` whenever the tab is opened. The endpoint is analyst-self only — it reads `req.user.id` from the JWT and returns recommendations scoped to that analyst's own assessment results. No other analyst's recommendations are accessible, and the endpoint is not exposed to lead or admin roles (those roles have their own visibility surfaces).

The recommendation algorithm (`server/routes/training-recommendations.js`):

1. Read the most recent assessment score per skill for the requesting analyst.
2. For each skill where the latest score is below the configurable gap threshold (default: 70 out of 100), look up active modules in `training_modules` matching that skill tag.
3. Rank modules within each skill: lower difficulty first for very-low scores, intermediate for borderline gaps, advanced for analysts close to threshold.
4. Return up to N recommendations per skill (default: 3), each with platform name, module title, URL, difficulty, free/paid, estimated hours.

The AC renders each recommendation as a card that deep-links to the platform's site. FireAlive does not host, proxy, embed, or excerpt any module content — the link opens in the analyst's browser as the analyst, with no FireAlive intermediation.

## Submission flow

The AC's Submit Completion form (wired in R3l C13) accepts free-form platform name, URL, module name, optional completion date, and optional score. On submit, the AC POSTs to `/api/training/submit-completion` (analyst-self only). The server inserts a row into `training_completions` with `status = 'pending'` and `submitted_at = NOW`. No matching is done against `training_modules` — analysts can submit completions for any training, including modules not currently in the seed catalog. This is intentional: the platform should not gatekeep professional development based on whether the maintainer has indexed a module.

The submission form's URL field accepts up to 2048 characters (raised from 500 in C13 to accommodate platforms that use long query-parameter URLs).

## Review flow

The MC's Training Reviews tab (wired in R3l C16d) is the lead/admin surface for processing the pending queue.

`GET /api/training/completions-review?status=<filter>&limit=<n>` (lead or admin role only) returns a filtered list of completion records plus a counts subtree (pending / verified / rejected / total). Allowed status filters: `pending`, `verified`, `rejected`, `all`. The tab renders four summary tiles, a filter pill row, and a table with columns for Analyst, Platform / Module, Submitted, Status, and Actions.

`PATCH /api/training/completions-review/:id` with body `{ status: 'verified' | 'rejected' }` transitions a single row. The server enforces a strict state machine: only `pending → verified` and `pending → rejected` are allowed; anything else returns 409 with the row's current status in the error message. Verified and rejected rows are terminal — no un-verify or un-reject path. If a lead needs to reverse a decision, the analyst must resubmit the completion (which creates a new pending row, preserving the original audit trail).

### Privacy posture

The review surface is Tier-1 only. The response includes `user_id` and `user_name` so the lead can identify which analyst submitted which completion (this is the lead's normal visibility of their team's training activity). No Tier-3 wellbeing signals, burnout indicators, capacity scores, or routing weights are surfaced anywhere in the review view. The queue's purpose is bounded: validate that an analyst genuinely completed the training they claim to have completed.

A lead reviewing the queue cannot infer anything about an analyst's wellbeing state from the review surface alone. This is deliberate — the training-review workflow should not become an indirect channel for surveillance.

### Audit events

Every operation on the review surface emits an audit event via `middleware/audit.js`:

- `TRAINING_COMPLETIONS_REVIEW_VIEWED` on each list call, with the active status filter and the row count returned
- `TRAINING_COMPLETION_VERIFIED` on each verify transition, with the completion ID and the acting user's ID
- `TRAINING_COMPLETION_REJECTED` on each reject transition, with the completion ID and the acting user's ID

Audit events are fire-and-forget — failures in the audit subsystem do not block the underlying operation, but the immutable SHA-256 hash chain in the audit log will surface any tampering with the audit history.

## Pre-release status and platform outreach

FireAlive is in pre-release. The training library works without authoritative catalogs from the platforms — the seed file is a viable starting point, and the recommender degrades gracefully (the "No training modules available yet" affordance) for skills without coverage. The project's maintainer has opened outreach with each platform to request structured catalogs (CSV, JSON, or sitemap) sourced directly from the platform rather than third parties. Responses will be merged into the seed file in subsequent commits with each catalog source documented in the commit description.

Until those responses arrive, the C2fix-cleanup baseline is the canonical seed state: 229 modules, 4 platforms, all URLs sourced from official platform catalog pages.

## Files

| Path | Purpose |
|---|---|
| `server/db/init.js` | Schema for `training_platforms`, `training_modules`, and the `url_legitimacy` CHECK constraint |
| `server/db/training-modules-seed.json` | Canonical seed catalog (229 modules, 4 platforms) |
| `server/db/seed-training-library.js` | Boot-time loader that upserts platforms and modules from the seed JSON |
| `server/routes/training-recommendations.js` | GET `/api/training-recommendations/me` — gap-driven recommendation endpoint |
| `server/routes/training.js` | POST `/api/training/submit-completion` — analyst submission endpoint |
| `server/routes/training-completions-review.js` | GET, PATCH `/api/training/completions-review` — lead/admin review queue |
| `packages/analyst-client/analyst-client.jsx` | AC Training tab render and Submit Completion form |
| `frontend/firealive-mc.jsx` | MC Training Reviews tab render, summary tiles, queue table, action handlers |
