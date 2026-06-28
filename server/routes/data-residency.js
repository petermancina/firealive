// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Data-Residency Admin Routes
//
// Admin-only CRUD for the data-residency policy, per-destination jurisdiction
// declarations, and the cross-border transfer register, plus an on-demand
// posture / drift re-check. Mounted in index.js behind authMiddleware(['admin'])
// and the config-lock chokepoint, so this router carries no auth of its own.
//
// Routes:
//   GET    /config              the policy
//   PUT    /config              set the policy (validated) + reconcile + audit
//   GET    /destinations        destinations + declaration + compliance for a
//                               routed category (?category=, default backup)
//   PUT    /destinations/:ref    set a destination's jurisdiction for a routed
//                               category (body.category, default backup) + audit
//   GET    /transfers           the cross-border transfer register + summary
//   PUT    /transfers/:id        set a transfer's mechanism / notes / review + audit
//   POST   /evaluate            reconcile + posture; raise region-mismatch alert
//   GET    /posture             declared vs detected residency + per-destination state
//
// Audit events are pseudonymous (operator actor + jurisdiction), never analyst
// identity, and are drawn from the closed RESIDENCY_* set.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const express = require('express');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const dataResidency = require('../services/data-residency');
const regions = require('../services/residency-regions');
const cloudMetadata = require('../services/cloud-metadata');
const { routeAlert } = require('../services/alert-router');
const { logger } = require('../services/logger');

const router = express.Router();

const VALID_MODES = ['enforce', 'warn'];
const VALID_MECHANISMS = ['adequacy', 'scc', 'bcr', 'derogation', 'none', 'unset'];

// Residency declarations and posture are scoped to a routed destination kind: a
// physical destination is declared/evaluated per category it serves (its route's
// primary/secondary). Only reconciled categories (those with real remote
// destinations) are accepted; 'backup' is the default for back-compat.
function normalizeCategory(raw) {
  if (raw === undefined || raw === null || raw === '') return 'backup';
  const c = String(raw);
  return dataResidency.RECONCILED_CATEGORIES.indexOf(c) !== -1 ? c : null;
}

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

// Two-letter shorthands that are blocs / non-country codes, not ISO 3166-1
// alpha-2 countries (the UK's country code is GB, not UK).
const NON_COUNTRY_TOKENS = ['EU', 'UK', 'EEA'];
function isIsoCountry(v) {
  const t = regions.normalizeToken(v);
  if (!t || !/^[A-Z]{2}$/.test(t)) return false;
  return NON_COUNTRY_TOKENS.indexOf(t) === -1;
}

// A permitted-region token is a valid ISO 3166-1 alpha-2 code or a known bloc.
function isValidRegionToken(v) {
  const t = regions.normalizeToken(v);
  if (!t) return false;
  if (Object.prototype.hasOwnProperty.call(regions.BLOCS, t)) return true;
  return /^[A-Z]{2}$/.test(t);
}

function destinationView(db, d, category) {
  const cat = category || 'backup';
  const jur = dataResidency.resolveDestinationJurisdiction(db, cat, d.id);
  const verdict = dataResidency.evaluateDestination(db, cat, d.id);
  return {
    ref: d.id,
    category: cat,
    name: d.name,
    adapter: d.adapter,
    enabled: d.enabled === 1 || d.enabled === true,
    jurisdiction: jur.country,
    providerDomicile: jur.providerDomicile,
    region: jur.region,
    source: jur.source,
    action: verdict.action,
    compliant: verdict.compliant,
    blocked: verdict.blocked,
    mode: verdict.mode,
    reason: verdict.reason,
  };
}

// Build the residency posture. When req is provided (the /evaluate re-check), a
// detected-vs-declared region mismatch raises a HIGH alert + audit; GET /posture
// passes null and only reports. Cloud metadata is cached after the first fetch.
async function buildPosture(db, req) {
  const cfg = dataResidency.loadResidencyConfig(db);
  const declaredCountry = cfg.primaryResidency.country;

  let provider = null;
  let detectedRegion = null;
  let detectedCountry = null;
  let mismatch = false;
  try {
    const md = await cloudMetadata.readCloudMetadata();
    provider = md.provider;
    detectedRegion = cloudMetadata.getRegion(md);
    if (detectedRegion) {
      const hit = regions.regionToCountry(detectedRegion);
      detectedCountry = hit ? hit.country : null;
    }
    if (detectedCountry && declaredCountry && detectedCountry !== declaredCountry) {
      mismatch = true;
    }
  } catch (e) {
    // detection is best-effort
  }

  if (req && mismatch) {
    try {
      await routeAlert(db, {
        type: 'RESIDENCY_REGION_MISMATCH',
        severity: 'high',
        source: 'data-residency',
        message: 'declared primary residency ' + declaredCountry
          + ' does not match detected deployment region ' + detectedRegion
          + ' (' + (detectedCountry || 'unknown') + ')',
        timestamp: new Date().toISOString(),
      });
      auditLog(actorOf(req), 'RESIDENCY_REGION_MISMATCH',
        'declared=' + declaredCountry + ' detected=' + detectedRegion
        + ' country=' + (detectedCountry || 'unknown'), req.ip);
    } catch (e) {
      logger.error('routes/data-residency: region-mismatch alert failed', { error: e.message });
    }
  }

  const dests = db.prepare('SELECT id, name, adapter, enabled FROM storage_destinations ORDER BY name').all();
  const destinations = dests.map(function (d) { return destinationView(db, d); });

  return {
    enabled: cfg.enabled,
    primaryResidency: {
      declared: {
        country: declaredCountry,
        region: cfg.primaryResidency.region,
        providerDomicile: cfg.primaryResidency.providerDomicile,
        source: cfg.primaryResidency.source,
      },
      detected: { provider: provider, region: detectedRegion, country: detectedCountry },
      mismatch: mismatch,
    },
    categories: cfg.categories,
    destinations: destinations,
    register: dataResidency.summarize(db),
  };
}

// ── Config ──────────────────────────────────────────────────────────────────

router.get('/config', (req, res) => {
  const db = getDb();
  try {
    return res.json(dataResidency.loadResidencyConfig(db));
  } catch (e) {
    return res.status(500).json({ error: 'failed to load data-residency config' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.put('/config', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const b = req.body;
    const enabled = b.enabled === true;

    const primaryResidency = { country: null, region: null, providerDomicile: null, source: 'declared' };
    if (b.primaryResidency !== undefined && b.primaryResidency !== null) {
      if (typeof b.primaryResidency !== 'object') {
        return res.status(400).json({ error: 'primaryResidency must be an object' });
      }
      const pr = b.primaryResidency;
      if (pr.country !== undefined && pr.country !== null && pr.country !== '') {
        if (!isIsoCountry(pr.country)) {
          return res.status(400).json({ error: 'primaryResidency.country must be an ISO 3166-1 alpha-2 code' });
        }
        primaryResidency.country = regions.normalizeToken(pr.country);
      }
      if (typeof pr.region === 'string' && pr.region.trim()) primaryResidency.region = pr.region.trim();
      if (pr.providerDomicile !== undefined && pr.providerDomicile !== null && pr.providerDomicile !== '') {
        if (!isIsoCountry(pr.providerDomicile)) {
          return res.status(400).json({ error: 'primaryResidency.providerDomicile must be an ISO 3166-1 alpha-2 code' });
        }
        primaryResidency.providerDomicile = regions.normalizeToken(pr.providerDomicile);
      }
      if (pr.source === 'cloud-metadata') primaryResidency.source = 'cloud-metadata';
    }

    const categories = dataResidency.defaultConfig().categories;
    if (b.categories !== undefined && b.categories !== null) {
      if (typeof b.categories !== 'object') {
        return res.status(400).json({ error: 'categories must be an object' });
      }
      for (let i = 0; i < dataResidency.CATEGORIES.length; i += 1) {
        const cat = dataResidency.CATEGORIES[i];
        const sc = b.categories[cat];
        if (sc === undefined || sc === null) continue;
        if (typeof sc !== 'object') {
          return res.status(400).json({ error: 'categories.' + cat + ' must be an object' });
        }
        if (cat === 'live_deployment') { categories[cat] = { mode: 'declare-only' }; continue; }
        const permitted = [];
        if (sc.permittedRegions !== undefined) {
          if (!Array.isArray(sc.permittedRegions)) {
            return res.status(400).json({ error: 'categories.' + cat + '.permittedRegions must be an array' });
          }
          for (let j = 0; j < sc.permittedRegions.length; j += 1) {
            const tok = sc.permittedRegions[j];
            if (!isValidRegionToken(tok)) {
              return res.status(400).json({ error: 'invalid region token in categories.' + cat + ': ' + String(tok) });
            }
            const norm = regions.normalizeToken(tok);
            if (permitted.indexOf(norm) === -1) permitted.push(norm);
          }
        }
        let mode = 'warn';
        if (sc.mode !== undefined) {
          if (VALID_MODES.indexOf(sc.mode) === -1) {
            return res.status(400).json({ error: 'categories.' + cat + '.mode must be one of: ' + VALID_MODES.join(', ') });
          }
          mode = sc.mode;
        }
        categories[cat] = { permittedRegions: permitted, mode: mode };
      }
    }

    const cfg = { enabled: enabled, primaryResidency: primaryResidency, categories: categories };
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('data_residency_config', ?)").run(JSON.stringify(cfg));
    try {
      dataResidency.reconcileTransfers(db);
    } catch (e) {
      logger.error('routes/data-residency: reconcile after config save failed', { error: e.message });
    }
    const enforcedList = Object.keys(categories)
      .filter(function (k) { return categories[k].mode === 'enforce'; }).join(',') || 'none';
    auditLog(actorOf(req), 'RESIDENCY_CONFIG_UPDATED',
      'enabled=' + enabled + ' primary=' + (primaryResidency.country || 'none') + ' enforced=' + enforcedList,
      req.ip);
    return res.json({ success: true, config: cfg });
  } catch (e) {
    return res.status(500).json({ error: 'failed to save data-residency config' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Destination declarations ────────────────────────────────────────────────

router.get('/destinations', (req, res) => {
  const db = getDb();
  try {
    const category = normalizeCategory(req.query.category);
    if (!category) {
      return res.status(400).json({ error: 'category must be one of: ' + dataResidency.RECONCILED_CATEGORIES.join(', ') });
    }
    const dests = db.prepare('SELECT id, name, adapter, enabled FROM storage_destinations ORDER BY name').all();
    const out = dests.map(function (d) {
      const decl = db.prepare(
        'SELECT declared_country, declared_region, provider_domicile, key_custody, auto_detected '
        + 'FROM data_residency_destinations WHERE destination_kind = ? AND destination_ref = ?'
      ).get(category, d.id) || null;
      const view = destinationView(db, d, category);
      view.declaration = decl;
      return view;
    });
    return res.json({ category: category, destinations: out });
  } catch (e) {
    return res.status(500).json({ error: 'failed to list residency destinations' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.put('/destinations/:ref', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const ref = req.params.ref;
    const exists = db.prepare('SELECT id FROM storage_destinations WHERE id = ?').get(ref);
    if (!exists) return res.status(404).json({ error: 'destination not found' });

    const b = req.body;
    const category = normalizeCategory(b.category);
    if (!category) {
      return res.status(400).json({ error: 'category must be one of: ' + dataResidency.RECONCILED_CATEGORIES.join(', ') });
    }
    let country = null;
    if (b.declared_country !== undefined && b.declared_country !== null && b.declared_country !== '') {
      if (!isIsoCountry(b.declared_country)) {
        return res.status(400).json({ error: 'declared_country must be an ISO 3166-1 alpha-2 code or null' });
      }
      country = regions.normalizeToken(b.declared_country);
    }
    let domicile = null;
    if (b.provider_domicile !== undefined && b.provider_domicile !== null && b.provider_domicile !== '') {
      if (!isIsoCountry(b.provider_domicile)) {
        return res.status(400).json({ error: 'provider_domicile must be an ISO 3166-1 alpha-2 code or null' });
      }
      domicile = regions.normalizeToken(b.provider_domicile);
    }
    const region = (typeof b.declared_region === 'string' && b.declared_region.trim()) ? b.declared_region.trim() : null;
    const keyCustody = (typeof b.key_custody === 'string' && b.key_custody.trim()) ? b.key_custody.trim() : null;
    const autoDetected = (b.auto_detected === true || b.auto_detected === 1) ? 1 : 0;

    db.prepare(
      'INSERT INTO data_residency_destinations '
      + '(destination_kind, destination_ref, declared_country, declared_region, provider_domicile, key_custody, auto_detected, updated_at) '
      + "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now')) "
      + 'ON CONFLICT(destination_kind, destination_ref) DO UPDATE SET '
      + 'declared_country = excluded.declared_country, declared_region = excluded.declared_region, '
      + 'provider_domicile = excluded.provider_domicile, key_custody = excluded.key_custody, '
      + "auto_detected = excluded.auto_detected, updated_at = datetime('now')"
    ).run(category, ref, country, region, domicile, keyCustody, autoDetected);

    try {
      dataResidency.reconcileTransfers(db);
    } catch (e) {
      logger.error('routes/data-residency: reconcile after destination set failed', { error: e.message });
    }
    auditLog(actorOf(req), 'RESIDENCY_DESTINATION_SET',
      'category=' + category + ' ref=' + ref + ' country=' + (country || 'cleared') + ' domicile=' + (domicile || 'none'), req.ip);

    const d = db.prepare('SELECT id, name, adapter, enabled FROM storage_destinations WHERE id = ?').get(ref);
    return res.json({ success: true, destination: destinationView(db, d, category) });
  } catch (e) {
    return res.status(500).json({ error: 'failed to set residency destination' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Transfer register ───────────────────────────────────────────────────────

router.get('/transfers', (req, res) => {
  const db = getDb();
  try {
    const rows = db.prepare(
      'SELECT id, transfer_key, data_category, source_jurisdiction, dest_jurisdiction, destination_ref, '
      + 'provider_domicile, foreign_law_exposure, key_custody, mechanism, mechanism_notes, status, '
      + 'detected_at, reviewed_at, reviewed_by, next_review_at '
      + 'FROM data_residency_transfers ORDER BY detected_at DESC'
    ).all();
    return res.json({ transfers: rows, summary: dataResidency.summarize(db) });
  } catch (e) {
    return res.status(500).json({ error: 'failed to list transfers' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.put('/transfers/:id', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const id = req.params.id;
    const row = db.prepare('SELECT id, status FROM data_residency_transfers WHERE id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'transfer not found' });

    const b = req.body;
    if (b.mechanism === undefined || VALID_MECHANISMS.indexOf(b.mechanism) === -1) {
      return res.status(400).json({ error: 'mechanism must be one of: ' + VALID_MECHANISMS.join(', ') });
    }
    const mechanism = b.mechanism;
    const notes = (typeof b.mechanism_notes === 'string') ? b.mechanism_notes.slice(0, 2000) : null;
    const nextReview = (typeof b.next_review_at === 'string' && b.next_review_at.trim()) ? b.next_review_at.trim() : null;
    // Preserve a blocked status (set by the write path / reconcile); else derive.
    const status = row.status === 'blocked' ? 'blocked' : dataResidency.deriveStatus(mechanism);

    db.prepare(
      'UPDATE data_residency_transfers SET mechanism = ?, mechanism_notes = ?, status = ?, '
      + "reviewed_at = datetime('now'), reviewed_by = ?, next_review_at = ? WHERE id = ?"
    ).run(mechanism, notes, status, actorOf(req), nextReview, id);

    auditLog(actorOf(req), 'RESIDENCY_TRANSFER_MECHANISM_SET', 'id=' + id + ' mechanism=' + mechanism, req.ip);
    const updated = db.prepare(
      'SELECT id, transfer_key, data_category, source_jurisdiction, dest_jurisdiction, provider_domicile, '
      + 'foreign_law_exposure, mechanism, mechanism_notes, status, reviewed_at, reviewed_by, next_review_at '
      + 'FROM data_residency_transfers WHERE id = ?'
    ).get(id);
    return res.json({ success: true, transfer: updated });
  } catch (e) {
    return res.status(500).json({ error: 'failed to update transfer' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Posture / drift re-check ────────────────────────────────────────────────

router.post('/evaluate', async (req, res) => {
  const db = getDb();
  try {
    try {
      dataResidency.reconcileTransfers(db);
    } catch (e) {
      logger.error('routes/data-residency: reconcile on evaluate failed', { error: e.message });
    }
    const posture = await buildPosture(db, req);
    return res.json(posture);
  } catch (e) {
    return res.status(500).json({ error: 'failed to evaluate residency posture' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.get('/posture', async (req, res) => {
  const db = getDb();
  try {
    const posture = await buildPosture(db, null);
    return res.json(posture);
  } catch (e) {
    return res.status(500).json({ error: 'failed to load residency posture' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;
