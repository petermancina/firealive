// =============================================================================
// FIREALIVE GD -- Data-Residency Admin Routes
//
// CRUD for the data-residency policy, per-destination jurisdiction declarations,
// and the cross-border transfer register, plus an on-demand posture re-check.
// Mounted in index.js behind authMiddleware + the config-lock chokepoint, so this
// router carries no auth of its own. Twins the Regional data-residency routes.
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
//   POST   /evaluate            reconcile + posture
//   GET    /posture             declared residency + per-destination state
//
// The posture reports the declared primary residency, per-destination compliance,
// and the transfer register. Detected-deployment-region comparison (declared vs
// detected, with a mismatch alert) is not wired on the GD side yet: the GD has no
// cloud-metadata self-detection service, so 'detected' is reported null and no
// mismatch is raised. buildPosture is structured so that detection can be wired in
// later without changing the endpoints.
//
// Audit events are pseudonymous (operator actor + jurisdiction), never analyst
// identity, drawn from the closed RESIDENCY_* set.
// =============================================================================

'use strict';

const express = require('express');
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const dataResidency = require('../services/gd-data-residency');
const regions = require('../services/gd-residency-regions');

const router = express.Router();

const VALID_MODES = ['enforce', 'warn'];
const VALID_MECHANISMS = ['adequacy', 'scc', 'bcr', 'derogation', 'none', 'unset'];

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, { userId: actorOf(req), eventType, detail, ip: (req && req.ip) || null, severity: 'info' });
  } catch (e) {
    try { console.warn('[data-residency] audit failed:', e && e.message); } catch (_e) { /* ignore */ }
  }
}

function requireObjectBody(req, res) {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    res.status(400).json({ error: 'request body required' });
    return false;
  }
  return true;
}

// Residency declarations and posture are scoped to a routed destination kind. Only
// reconciled categories are accepted; 'backup' is the default for back-compat.
function normalizeCategory(raw) {
  if (raw === undefined || raw === null || raw === '') return 'backup';
  const c = String(raw);
  return dataResidency.RECONCILED_CATEGORIES.indexOf(c) !== -1 ? c : null;
}

// Two-letter shorthands that are blocs / non-country codes, not ISO countries.
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

// Build the residency posture. Detected-deployment-region comparison is not wired
// on the GD side (no cloud-metadata self-detection service), so 'detected' is null
// and mismatch is always false. Structured so detection can be added later.
async function buildPosture(db) {
  const cfg = dataResidency.loadResidencyConfig(db);
  const declaredCountry = cfg.primaryResidency.country;

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
      detected: { provider: null, region: null, country: null },
      mismatch: false,
    },
    categories: cfg.categories,
    destinations: destinations,
    register: dataResidency.summarize(db),
  };
}

// -- Config -------------------------------------------------------------------
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    return res.json(dataResidency.loadResidencyConfig(db));
  } catch (_e) {
    return res.status(500).json({ error: 'failed to load data-residency config' });
  }
});

router.put('/config', (req, res) => {
  if (!requireObjectBody(req, res)) return undefined;
  try {
    const db = getDb();
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
    try { dataResidency.reconcileTransfers(db); }
    catch (e) { console.error('routes/data-residency: reconcile after config save failed:', e.message); }
    const enforcedList = Object.keys(categories)
      .filter(function (k) { return categories[k].mode === 'enforce'; }).join(',') || 'none';
    _audit(db, req, 'RESIDENCY_CONFIG_UPDATED',
      'enabled=' + enabled + ' primary=' + (primaryResidency.country || 'none') + ' enforced=' + enforcedList);
    return res.json({ success: true, config: cfg });
  } catch (_e) {
    return res.status(500).json({ error: 'failed to save data-residency config' });
  }
});

// -- Destination declarations -------------------------------------------------
router.get('/destinations', (req, res) => {
  try {
    const db = getDb();
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
  } catch (_e) {
    return res.status(500).json({ error: 'failed to list residency destinations' });
  }
});

router.put('/destinations/:ref', (req, res) => {
  if (!requireObjectBody(req, res)) return undefined;
  try {
    const db = getDb();
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

    try { dataResidency.reconcileTransfers(db); }
    catch (e) { console.error('routes/data-residency: reconcile after destination set failed:', e.message); }
    _audit(db, req, 'RESIDENCY_DESTINATION_SET',
      'category=' + category + ' ref=' + ref + ' country=' + (country || 'cleared') + ' domicile=' + (domicile || 'none'));

    const d = db.prepare('SELECT id, name, adapter, enabled FROM storage_destinations WHERE id = ?').get(ref);
    return res.json({ success: true, destination: destinationView(db, d, category) });
  } catch (_e) {
    return res.status(500).json({ error: 'failed to set residency destination' });
  }
});

// -- Transfer register --------------------------------------------------------
router.get('/transfers', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(
      'SELECT id, transfer_key, data_category, source_jurisdiction, dest_jurisdiction, destination_ref, '
      + 'provider_domicile, foreign_law_exposure, key_custody, mechanism, mechanism_notes, status, '
      + 'detected_at, reviewed_at, reviewed_by, next_review_at '
      + 'FROM data_residency_transfers ORDER BY detected_at DESC'
    ).all();
    return res.json({ transfers: rows, summary: dataResidency.summarize(db) });
  } catch (_e) {
    return res.status(500).json({ error: 'failed to list transfers' });
  }
});

router.put('/transfers/:id', (req, res) => {
  if (!requireObjectBody(req, res)) return undefined;
  try {
    const db = getDb();
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

    _audit(db, req, 'RESIDENCY_TRANSFER_MECHANISM_SET', 'id=' + id + ' mechanism=' + mechanism);
    const updated = db.prepare(
      'SELECT id, transfer_key, data_category, source_jurisdiction, dest_jurisdiction, provider_domicile, '
      + 'foreign_law_exposure, mechanism, mechanism_notes, status, reviewed_at, reviewed_by, next_review_at '
      + 'FROM data_residency_transfers WHERE id = ?'
    ).get(id);
    return res.json({ success: true, transfer: updated });
  } catch (_e) {
    return res.status(500).json({ error: 'failed to update transfer' });
  }
});

// -- Posture / drift re-check -------------------------------------------------
router.post('/evaluate', async (req, res) => {
  try {
    const db = getDb();
    try { dataResidency.reconcileTransfers(db); }
    catch (e) { console.error('routes/data-residency: reconcile on evaluate failed:', e.message); }
    const posture = await buildPosture(db);
    _audit(db, req, 'RESIDENCY_POSTURE_EVALUATED',
      'enabled=' + posture.enabled + ' transfers=' + posture.register.transfers + ' blocked=' + posture.register.blocked);
    return res.json(posture);
  } catch (_e) {
    return res.status(500).json({ error: 'failed to evaluate residency posture' });
  }
});

router.get('/posture', async (req, res) => {
  try {
    const db = getDb();
    const posture = await buildPosture(db);
    return res.json(posture);
  } catch (_e) {
    return res.status(500).json({ error: 'failed to load residency posture' });
  }
});

module.exports = router;
