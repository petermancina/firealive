# Contributing to FireAlive

FireAlive is maintained by Peter Mancina. The project is open source under AGPL-3.0-or-later and the source is public, but the maintainer model is single-author rather than community-merged: framework additions, control modifications, and compliance-engine changes are kept in-house so the audit trail of who authored each control stays clear.

This document is **maintainer-facing internal notes**, not a contributor onboarding guide. The conventions documented here are for the maintainer and any explicitly-invited collaborators to follow; they are not invitations for unsolicited framework PRs.

If you have a question about FireAlive, found a bug, or want to suggest a feature, open a GitHub issue. PRs from outside the maintainer's circle are not the workflow for framework additions or compliance changes.

---

## Forking for Additional Frameworks

FireAlive ships with 16 compliance frameworks: NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD, PDPA Singapore, APPI Japan, POPIA South Africa, NIS2, CPS 234 Australia, Cyber Essentials UK, and FISMA.

If you operate a SOC under a jurisdiction whose regulatory regime isn't on this list — South Korean PIPA, Brazil's banking-sector resolutions, an industry-specific framework like NERC CIP, or anything else — the supported path is to **fork the project and add your framework in your fork**. The AGPL-3.0 license permits this; the framework file structure is documented below so a fork has everything it needs to add a new framework without inventing conventions.

The upstream project will not merge framework PRs from forks. Reasons:
- Each framework requires authoritative knowledge of the regulation and the platform's controls together; the maintainer cannot vouch for a framework's accuracy without doing that research themselves
- An auditor reading a FireAlive report needs to know who authored each control; upstream-merging external framework contributions blurs that provenance
- A framework added to upstream becomes the maintainer's perpetual obligation to update as the regulation evolves; that's a non-trivial commitment per framework

A fork's framework files live in the fork. The fork's users get the fork's coverage. This is the intended distribution model.

---

## Maintainer Internal Notes — Dual-Codebase Compliance Framework Pattern

When the maintainer modifies the existing 16 frameworks, the parallel-codebase structure described below applies. This section exists so the maintainer (and future co-maintainers if any are invited) has a written reference rather than a re-derived-each-time convention.

### The Two Locations

| Side | Path | Consumed by |
|------|------|-------------|
| MC | `server/services/compliance/frameworks/` | MC's `GET /api/compliance/report/:framework` (`server/routes/compliance-monitoring.js`) |
| GD | `packages/global-dashboard-server/services/compliance/frameworks/` | GD's `GET /api/compliance/report/:framework` (`packages/global-dashboard-server/index.js`) |

Each directory holds the same 16 framework files. The file ID (e.g., `hipaa`) is the canonical framework identifier used across the codebase — UI selector option values, audit log entries, and the URL path parameter on the compliance report endpoints all reference this ID exactly.

### Why Two Copies

The MC and GD are independent backends with independent state. The MC's compliance report describes the MC's running system; the GD's report describes the GD-Server's running system. They share the framework taxonomy (what each control means, which sections of which regulation it maps to) but verify different runtime state (the MC checks MC-side configuration; the GD checks GD-side configuration like the signing-key trust registry, mailbox-pattern fulfillment, cross-region aggregation integrity).

A single shared package would require either a monorepo workspace dependency that complicates the build for two separately-distributed Electron apps, or a published npm package whose release cadence couples the MC and GD versions. Neither trade-off was worth the duplication-avoidance benefit. The two copies have **identical taxonomy** (same control IDs, same regulatory citations, same `customerResponsibility` enumerations, same `mapping` strings) but **independent `check:` functions** since each side checks its own running state.

### The Parallel Structure

Inside each framework directory, the per-framework file follows the same shape on both sides:

```javascript
module.exports = {
  name: 'HIPAA Security Rule',
  authority: 'U.S. Department of Health & Human Services Office for Civil Rights',
  citation: '45 CFR §164.302-318 (Security Rule), §164.400-414 (Breach Notification)',
  note: 'optional framework-level guidance',
  verifiedControls: [
    {
      id: '164.312(a)(1)',
      name: 'Access Control',
      mapping: 'HIPAA 164.312(a)(1) | NIST 800-53 AC-3 | ISO 27001 A.9.4.1',
      check: checkAccessControl,
    },
  ],
  customerResponsibility: [
    {
      id: '164.308(a)(1)(i)',
      name: 'Security Management Process',
      category: 'organizational',
      detail: 'Implement policies and procedures...',
    },
  ],
};
```

Three companion locations need parallel updates when frameworks change:

- `./checks/` directory — the `check:` functions referenced in `verifiedControls`. MC side under `server/services/compliance/checks/`; GD side under `packages/global-dashboard-server/services/compliance/checks/`. The check function bodies can DIVERGE between MC and GD — the same control name checks different runtime state on each side. That's intentional. The function NAMES need to remain stable for the remediations lookup.
- `./remediations.js` — operator-actionable remediation guidance keyed by check-function name. When a control fails or warns, the report includes the matching remediation. Update on both sides when a new check is added.
- `./index.js` — the framework registry. New frameworks need to be registered here on both sides.

### Maintainer Reference: When Modifying an Existing Framework

When the maintainer touches an existing framework (adds a control, updates a citation, refines `customerResponsibility` detail):

- Apply the same change to **both** the MC-side file and the GD-side file
- If a `verifiedControls` entry is changed, also update the matching `check:` function on both sides if needed
- If a new control's check would warn or fail in some states, add a remediation entry on both sides
- Re-run any tests that exercise the framework's report shape

When modifying the `report` response shape itself:

- Update `generateComplianceReport` on both sides (`server/services/compliance/index.js` and `packages/global-dashboard-server/services/compliance/index.js`)
- Update the consumers: MC frontend's Compliance tab render, GD frontend's Compliance Posture render, GD frontend's Cross-Region Compliance per-cell drilldown render. These are in the relevant `.jsx` files.

### Fork Maintainer Reference: When Adding a New Framework in a Fork

A fork adding a new framework (e.g., a Korean PIPA file, an NERC CIP file) should follow the same structure to keep the fork's behavior consistent. The fork maintainer should:

- Create `server/services/compliance/frameworks/<id>.js` (MC side)
- Create `packages/global-dashboard-server/services/compliance/frameworks/<id>.js` (GD side)
- If new `check:` functions are needed, add them to the appropriate `./checks/` files on both sides
- Add remediation entries to both sides' `./remediations.js`
- Register the framework in both sides' `./index.js`
- Add the framework's canonical ID + display label to the UI selectors:
  - MC: `frontend/firealive-mc.jsx` — Compliance tab `<Sel>` options
  - GD: `packages/global-dashboard/global-dashboard.jsx` — `COMPLIANCE_FRAMEWORKS` module-level constant
- Verify both endpoints return the new framework against the fork's running servers

The fork is responsible for keeping its added framework current as the underlying regulation evolves. Upstream does not track fork-specific frameworks.

---

## Issues, Bug Reports, Security Disclosures

Open a GitHub issue for bug reports, feature suggestions, and general discussion.

For security vulnerabilities, do **not** open a public issue. Contact the maintainer directly via the email address listed in the maintainer's GitHub profile or via the security reporting channel documented in `SECURITY.md` (when present).
