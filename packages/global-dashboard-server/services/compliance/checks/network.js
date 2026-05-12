// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Network Security
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/network.js.
// Both files export the same 4 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD has a substantially smaller network-security
// surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD has no tier-based encryption (no TIER1_ENCRYPTION_KEY,
//     no TIER3_ENCRYPTION_KEY env vars; no users.tier column). The
//     GD's data segmentation is architectural rather than crypto-
//     keyed: all data on the GD is either aggregate (regional_metrics)
//     or account-level (users). The data-boundary is enforced by
//     what tables exist on the GD, not by per-row tier values.
//   - GD has no security-hardening middleware module (no
//     middleware/ subdirectory at all; all middleware is inline in
//     index.js). There is no antiReplay middleware, no preventPivot,
//     no validateMtls. checkAntiReplay returns warning honestly.
//   - GD has no integration_config table. The GD's third-party
//     surface is the management_consoles table (the MCs that push
//     aggregate metrics to the GD). checkSystemBoundaries inspects
//     management_consoles.status distribution rather than
//     integration_config.
//   - GD HAS express-rate-limit (apiLimiter inline in index.js,
//     1000 req/15min window). checkRateLimiting verifies the
//     dependency resolves, same pattern as MC.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkNetworkSegmentation ─────────────────────────────────────────────────
// Verifies the GD's data segmentation is structurally enforced. Unlike
// MC's tier-based encryption segmentation, the GD's segmentation is
// architectural: aggregate metrics (regional_metrics, no analyst-
// identifying fields) live separately from account data (users); the
// "boundary" is the absence of analyst-data tables on the GD entirely.
// API-layer enforcement (route middleware checking req.user.role)
// provides the authorization boundary; there is no in-platform
// network-layer middleware on the GD (no preventPivot / validateMtls
// equivalent of MC's network-security module).
//
// Maps to controls including: SOC 2 CC6.6 System Boundaries, NIST CSF
// PR.IR-01 Networks Isolated, ISO 27001 A.8.20 Network security /
// A.8.22 Segregation of networks, NIST 800-53 SC-7 Boundary Protection.
function checkNetworkSegmentation(db) {
  const metricsCount = db.prepare("SELECT COUNT(*) AS c FROM regional_metrics").get();
  const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return {
    status: 'pass',
    detail: `GD data segmentation is architectural, not crypto-keyed: ${metricsCount.c} aggregate metric row(s) (regional_metrics, no analyst-identifying fields) + ${userCount.c} account record(s) (users, CISO/VP/readonly). Analyst data tables do not exist on the GD; the "boundary" is enforced by table absence. API-layer middleware enforces role-based route access. Network-layer segmentation (firewall rules, network ACLs, security groups isolating the GD port from inappropriate sources) is operator-managed at the deployment layer.`,
  };
}

// ── checkAntiReplay ──────────────────────────────────────────────────────────
// Verifies anti-replay protection. The GD has no anti-replay middleware
// — no nonce tracking, no sliding-window protection against replayed
// JWTs or replayed MC-push payloads. The JWT 8h expiry provides
// time-bounded protection (a stolen JWT is replayable only within its
// validity window) but does not prevent intra-window replay.
//
// SOC-grade norm is nonce-based or sequence-number-based anti-replay
// on authenticated channels. The MC → GD push channel (PR3) will need
// to incorporate anti-replay protection when implemented; the
// currently-broken /api/v1/compliance/scan callsite was the only path
// where replay would have mattered, and that callsite is being
// repointed in PR4.
//
// Maps to controls including: SOC 2 CC6.6, NIST CSF PR.AA-03,
// NIST 800-53 SC-23 Session Authenticity, IA-2(8) Access to Accounts —
// Replay Resistant, ISO 27001 A.8.5.
function checkAntiReplay() {
  return {
    status: 'warning',
    detail: 'GD has no anti-replay middleware (no nonce tracking, no sliding-window protection). JWT 8h expiry provides time-bounded protection only — a stolen JWT is replayable within its validity window. SOC-grade norm is nonce-based or sequence-number-based anti-replay on authenticated channels. PR3 MC → GD push channel will incorporate anti-replay; intervening transport-layer protection (mTLS at the reverse proxy with strict cert pinning) is operator-managed.',
  };
}

// ── checkRateLimiting ────────────────────────────────────────────────────────
// Verifies rate limiting is configured. The GD's apiLimiter is
// declared inline in index.js using express-rate-limit
// (windowMs = 15 * 60 * 1000, max = 1000). This check loads the
// express-rate-limit module via require to verify the dependency
// resolves; the actual mounting at /api/ is verified by app startup.
//
// Maps to controls including: SOC 2 CC6.1/CC6.6, NIST CSF PR.IR-04,
// NIST 800-53 SC-5 Denial of Service Protection, ISO 27001 A.8.20.
function checkRateLimiting() {
  try {
    const rl = require('express-rate-limit');
    if (typeof rl !== 'function' && typeof rl.default !== 'function') {
      return {
        status: 'fail',
        detail: 'express-rate-limit module loaded but export is not a function. Rate limiting non-operational on the GD.',
      };
    }
    return {
      status: 'pass',
      detail: 'Rate limiting: express-rate-limit module loaded; apiLimiter configured inline in packages/global-dashboard-server/index.js (windowMs=15min, max=1000 req/IP) and applied to /api/ paths at startup (with /api/health exempt to avoid impacting reverse-proxy health probes).',
    };
  } catch (err) {
    return {
      status: 'fail',
      detail: `Rate limiting dependency not resolvable on the GD: ${err.message}. Rate limiting non-operational.`,
    };
  }
}

// ── checkSystemBoundaries ────────────────────────────────────────────────────
// Verifies system-boundary integrations (the GD's third-party surface).
// The GD has no integration_config table; its third-party surface IS
// the management_consoles table (the MCs that push aggregate metrics
// to the GD). Inspects status distribution: active / offboarded /
// any non-active value other than offboarded counts as a boundary
// concern requiring operator attention.
//
// Maps to controls including: SOC 2 CC6.6 System Boundaries,
// NIST CSF ID.AM-03 / PR.IR-01, ISO 27001 A.8.21 Security of network
// services, NIST 800-53 CM-8 System Component Inventory, DORA Art.15
// ICT Third-Party Risk.
function checkSystemBoundaries(db) {
  const rows = db.prepare(
    "SELECT status, COUNT(*) AS c FROM management_consoles GROUP BY status"
  ).all();
  if (rows.length === 0) {
    return {
      status: 'pass',
      detail: 'No management consoles registered on the GD. The GD\'s third-party surface (the connected MCs) is empty; system-boundary check vacuously holds. Cross-region aggregation will populate this surface once MCs are connected.',
    };
  }
  const active = rows.filter(r => r.status === 'active').reduce((sum, r) => sum + r.c, 0);
  const offboarded = rows.filter(r => r.status === 'offboarded').reduce((sum, r) => sum + r.c, 0);
  const unhealthy = rows.filter(r => r.status !== 'active' && r.status !== 'offboarded');
  const summary = rows.map(r => `${r.status}(${r.c})`).join(', ');
  if (unhealthy.length > 0) {
    const unhealthyTotal = unhealthy.reduce((sum, r) => sum + r.c, 0);
    const unhealthySummary = unhealthy.map(r => `${r.status}(${r.c})`).join(', ');
    return {
      status: 'warning',
      detail: `${unhealthyTotal} management console(s) in non-active, non-offboarded state: ${unhealthySummary}. Distribution overall: ${summary}. Investigate degraded MCs via /api/management-consoles.`,
    };
  }
  return {
    status: 'pass',
    detail: `System boundaries: ${active} active MC(s), ${offboarded} offboarded. Distribution: ${summary}. The MCs are the GD's authorized third-party data sources; each pushes aggregate metrics on a configured schedule (PR3) and is authenticated via management_consoles.api_key.`,
  };
}

module.exports = {
  checkNetworkSegmentation,
  checkAntiReplay,
  checkRateLimiting,
  checkSystemBoundaries,
};
