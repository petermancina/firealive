// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Integration Manager (EDR scanner dispatcher)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Multi-provider malware-scanner orchestration for the GD, the GD twin of the
// Regional Server's integration-manager scanner engine. It registers and
// dispatches to scanner modules under services/gd-malware-scanners/<provider>.js,
// reads scanner configuration from the malware_scanner_integrations table,
// decrypts credentials at scan-time only (via the GD Tier-1 KEK, gd-encryption),
// and runs scans in one of two modes:
//
//   - single_with_fallback (default):
//       Try active scanners in priority order. The first authoritative result
//       (clean OR flagged) wins. A scanner error falls through to the next
//       scanner. If every scanner errors, fail-closed.
//
//   - all_configured:
//       Run ALL active scanners in parallel. The upload passes only if every
//       scanner returns clean=true. Any flagged verdict, any scanner error,
//       fails the upload. The config-baseline import forces this mode.
//
// Both modes update last_scan_at + the aggregate counters per scanner row.
//
// This is EDR-only: the MC's legacy integration_status tracking is not carried
// (the GD uses gd-integration-health for operational integration status). Each
// vendor is a vetted adapter module that knows the vendor's specific API shape;
// there is no operator-controllable URL forwarding (no SSRF surface).
//
// inspectFile(content, fileName, fileType, opts) accepts a non-empty string OR
// Buffer (restore scans pass raw SQLite bytes) and returns
// {clean, skipped, threats, scanId, provider, latencyMs, ...}. MANDATORY-SCANNER
// enforcement is intentionally NOT in this layer: inspectFile returns
// skipped:true when no scanners are configured, and the route/primitive layer
// decides whether that is acceptable for the operation.
// -----------------------------------------------------------------------------

const path = require('path');
const crypto = require('crypto');

const { sealTier1, openTier1 } = require('./gd-tier1-seal');

const INSPECTOR_VERSION = '2.0.0';

const DEFAULT_SCAN_MODE = 'single_with_fallback';
const VALID_SCAN_MODES = ['single_with_fallback', 'all_configured'];

const SCANNER_DIR = path.join(__dirname, 'gd-malware-scanners');

const VALID_PROVIDER_TYPES = [
  'clamav', 'virustotal',
  'crowdstrike_falcon', 'microsoft_defender', 'sentinelone', 'cisco_amp',
  'fortinet_fortisandbox', 'palo_alto_wildfire',
  'trellix_atd', 'sophos_intelix',
  'joe_sandbox', 'hybrid_analysis',
  'blackberry_cylance', 'trend_micro_ddan', 'kaspersky_sandbox',
];

// Map provider_type -> scanner module filename. Filenames use kebab-case while
// provider_type values use snake_case for SQL friendliness.
const PROVIDER_MODULE_NAMES = {
  'clamav':                'clamav',
  'virustotal':            'virustotal',
  'crowdstrike_falcon':    'crowdstrike-falcon',
  'microsoft_defender':    'microsoft-defender',
  'sentinelone':           'sentinelone',
  'cisco_amp':             'cisco-amp',
  'fortinet_fortisandbox': 'fortinet-fortisandbox',
  'palo_alto_wildfire':    'palo-alto-wildfire',
  'trellix_atd':           'trellix-atd',
  'sophos_intelix':        'sophos-intelix',
  'joe_sandbox':           'joe-sandbox',
  'hybrid_analysis':       'hybrid-analysis',
  'blackberry_cylance':    'blackberry-cylance',
  'trend_micro_ddan':      'trend-micro-ddan',
  'kaspersky_sandbox':     'kaspersky-sandbox',
};

class IntegrationManager {
  constructor(db) {
    this.db = db;
    this._scannerModuleCache = new Map();
  }

  // -- Scanner management ------------------------------------------------------

  // List all configured scanners with credentials redacted. Ordered by priority
  // (asc) then configured_at (asc) so the result matches the dispatcher order.
  listScanners() {
    return this.db.prepare(`
      SELECT id, provider_type, display_name, priority, enabled,
             configured_by, configured_at,
             last_test_at, last_test_status, last_test_error,
             last_scan_at, total_scans, total_threats_detected, total_failures
      FROM malware_scanner_integrations
      ORDER BY priority ASC, configured_at ASC
    `).all().map(this._normalizeScannerRow);
  }

  // Return one scanner config with credentials redacted, or null if not found.
  getScanner(id) {
    const row = this.db.prepare(`
      SELECT id, provider_type, display_name, priority, enabled,
             configured_by, configured_at,
             last_test_at, last_test_status, last_test_error,
             last_scan_at, total_scans, total_threats_detected, total_failures
      FROM malware_scanner_integrations WHERE id = ?
    `).get(id);
    if (!row) return null;
    return this._normalizeScannerRow(row);
  }

  // Add a new scanner. Returns the new row id.
  // args: { provider_type, display_name, credentials, priority?, enabled?,
  //         configured_by? }
  addScanner(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('addScanner requires an args object');
    }
    const { provider_type, display_name, credentials, priority, enabled, configured_by } = args;

    if (!VALID_PROVIDER_TYPES.includes(provider_type)) {
      throw new Error(`invalid provider_type: ${provider_type}`);
    }
    if (typeof display_name !== 'string' || display_name.trim().length === 0) {
      throw new Error('display_name is required');
    }
    if (display_name.length > 256) {
      throw new Error('display_name exceeds 256 character limit');
    }
    if (!credentials || typeof credentials !== 'object') {
      throw new Error('credentials object is required');
    }
    const prio = priority !== undefined ? Number(priority) : 100;
    if (!Number.isInteger(prio) || prio < 1 || prio > 1000) {
      throw new Error('priority must be an integer between 1 and 1000');
    }
    const enabledInt = (enabled === false || enabled === 0) ? 0 : 1;

    const id = crypto.randomBytes(16).toString('hex');
    const credEncrypted = sealTier1('malware_scanner_integrations.credentials_encrypted', credentials);

    this.db.prepare(`INSERT INTO malware_scanner_integrations
      (id, provider_type, display_name, credentials_encrypted,
       priority, enabled, configured_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      id, provider_type, display_name.trim(), credEncrypted,
      prio, enabledInt,
      configured_by || null
    );

    return id;
  }

  // Update a scanner. Any subset of fields may be supplied. Credentials are only
  // re-encrypted if a new credentials object is provided -- omitting it leaves
  // the existing credentials untouched.
  // args: { display_name?, credentials?, priority?, enabled? }
  updateScanner(id, args) {
    if (typeof id !== 'string' || id.length === 0) {
      throw new Error('id is required');
    }
    if (!args || typeof args !== 'object') {
      throw new Error('updateScanner requires an args object');
    }

    const existing = this.db.prepare("SELECT id FROM malware_scanner_integrations WHERE id = ?").get(id);
    if (!existing) throw new Error(`scanner not found: ${id}`);

    const sets = [];
    const params = [];

    if (args.display_name !== undefined) {
      if (typeof args.display_name !== 'string' || args.display_name.trim().length === 0) {
        throw new Error('display_name must be a non-empty string');
      }
      if (args.display_name.length > 256) {
        throw new Error('display_name exceeds 256 character limit');
      }
      sets.push('display_name = ?');
      params.push(args.display_name.trim());
    }
    if (args.credentials !== undefined) {
      if (!args.credentials || typeof args.credentials !== 'object') {
        throw new Error('credentials must be an object when provided');
      }
      sets.push('credentials_encrypted = ?');
      params.push(sealTier1('malware_scanner_integrations.credentials_encrypted', args.credentials));
      // Reset last_test fields since credentials changed -- the old test result
      // no longer reflects the current credentials.
      sets.push('last_test_at = NULL');
      sets.push('last_test_status = NULL');
      sets.push('last_test_error = NULL');
    }
    if (args.priority !== undefined) {
      const prio = Number(args.priority);
      if (!Number.isInteger(prio) || prio < 1 || prio > 1000) {
        throw new Error('priority must be an integer between 1 and 1000');
      }
      sets.push('priority = ?');
      params.push(prio);
    }
    if (args.enabled !== undefined) {
      sets.push('enabled = ?');
      params.push((args.enabled === false || args.enabled === 0) ? 0 : 1);
    }

    if (sets.length === 0) {
      return; // nothing to update
    }

    params.push(id);
    this.db.prepare(`UPDATE malware_scanner_integrations
      SET ${sets.join(', ')}
      WHERE id = ?`).run(...params);
  }

  // Delete a scanner.
  deleteScanner(id) {
    if (typeof id !== 'string' || id.length === 0) {
      throw new Error('id is required');
    }
    const result = this.db.prepare("DELETE FROM malware_scanner_integrations WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // Test a scanner's credentials by calling its testConnection() method.
  // Persists the result in last_test_at / last_test_status / last_test_error.
  async testScanner(id) {
    if (typeof id !== 'string' || id.length === 0) {
      throw new Error('id is required');
    }
    const row = this.db.prepare(`SELECT id, provider_type, credentials_encrypted
                                  FROM malware_scanner_integrations
                                  WHERE id = ?`).get(id);
    if (!row) throw new Error(`scanner not found: ${id}`);

    let scanner;
    try {
      scanner = this._loadScannerModule(row.provider_type);
    } catch (err) {
      this._recordTestResult(id, 'failed', `module load failed: ${err.message}`);
      return { ok: false, error: `module load failed: ${err.message}` };
    }

    let credentials;
    try {
      credentials = openTier1('malware_scanner_integrations.credentials_encrypted', row.credentials_encrypted);
    } catch (err) {
      this._recordTestResult(id, 'failed', `credential decryption failed: ${err.message}`);
      return { ok: false, error: `credential decryption failed: ${err.message}` };
    }

    let result;
    try {
      result = await scanner.testConnection(credentials);
    } catch (err) {
      this._recordTestResult(id, 'failed', err.message || String(err));
      return { ok: false, error: err.message || String(err) };
    }

    if (result && result.ok === true) {
      this._recordTestResult(id, 'success', null);
      return { ok: true, latencyMs: result.latencyMs || 0 };
    }
    const errMsg = (result && result.error) || 'unknown failure';
    this._recordTestResult(id, 'failed', errMsg);
    return { ok: false, error: errMsg, latencyMs: (result && result.latencyMs) || 0 };
  }

  _recordTestResult(id, status, errorMsg) {
    try {
      this.db.prepare(`UPDATE malware_scanner_integrations
        SET last_test_at = datetime('now'),
            last_test_status = ?,
            last_test_error = ?
        WHERE id = ?`).run(status, errorMsg, id);
    } catch (_e) { /* best-effort bookkeeping */ }
  }

  // -- Scan-mode persistence (in the config key/value table) -------------------

  getScanMode() {
    const row = this.db.prepare("SELECT value FROM config WHERE key = 'malware_scan_mode'").get();
    if (!row) return DEFAULT_SCAN_MODE;
    try {
      const parsed = JSON.parse(row.value);
      const mode = (parsed && parsed.mode) || row.value;
      return VALID_SCAN_MODES.includes(mode) ? mode : DEFAULT_SCAN_MODE;
    } catch (_e) {
      // legacy: stored as a raw string
      return VALID_SCAN_MODES.includes(row.value) ? row.value : DEFAULT_SCAN_MODE;
    }
  }

  setScanMode(mode) {
    if (!VALID_SCAN_MODES.includes(mode)) {
      throw new Error(`invalid scan mode: ${mode} (valid: ${VALID_SCAN_MODES.join(', ')})`);
    }
    this.db.prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`)
      .run('malware_scan_mode', JSON.stringify({ mode, updatedAt: new Date().toISOString() }));
  }

  // Resolve the effective scan mode for a single inspectFile call. An explicit,
  // valid opts.scanMode override (e.g. a config-baseline import forcing
  // all_configured) wins; otherwise the deployment's persisted mode applies. An
  // invalid override throws -- it is a programming error from a caller, never
  // user input.
  _resolveScanMode(opts = {}) {
    if (opts && typeof opts.scanMode === 'string') {
      if (!VALID_SCAN_MODES.includes(opts.scanMode)) {
        throw new Error(`invalid scan mode override: ${opts.scanMode} (valid: ${VALID_SCAN_MODES.join(', ')})`);
      }
      return opts.scanMode;
    }
    return this.getScanMode();
  }

  // -- File inspection (multi-provider dispatcher) -----------------------------
  //
  // Called after the layer-1 content sanitizer has cleared the content. Both
  // gates must pass for the upload/restore to land.
  //
  // Behavior contract:
  //   - At least one enabled scanner configured -> run scan-mode logic
  //   - No enabled scanners -> return {clean:true, skipped:true} so the caller
  //     can decide whether to enforce a mandatory-scanner policy.
  async inspectFile(content, fileName, fileType, opts = {}) {
    const startedAt = Date.now();
    const mode = this._resolveScanMode(opts);

    // Validate input. inspectFile accepts a non-empty string OR Buffer (restore
    // scans pass binary SQLite bytes). The scanner modules preserve Buffer input
    // unchanged; string input is converted to Buffer here.
    const isBufferContent = Buffer.isBuffer(content);
    if ((typeof content !== 'string' && !isBufferContent) || content.length === 0) {
      return {
        clean: false,
        skipped: false,
        threats: ['empty or invalid-type content rejected before scanner call'],
        scanId: null,
        provider: null,
        scanners: [],
        mode,
        latencyMs: Date.now() - startedAt,
        error: 'invalid content',
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    // Get enabled scanners in priority order.
    let scannerRows;
    try {
      scannerRows = this.db.prepare(`
        SELECT id, provider_type, display_name, credentials_encrypted, priority
        FROM malware_scanner_integrations
        WHERE enabled = 1
        ORDER BY priority ASC, configured_at ASC
      `).all();
    } catch (err) {
      return {
        clean: false,
        skipped: false,
        threats: [],
        scanId: null,
        provider: null,
        scanners: [],
        mode,
        latencyMs: Date.now() - startedAt,
        error: 'scanner registry query failed: ' + err.message,
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    if (scannerRows.length === 0) {
      // No scanners configured. Return skipped:true; the caller decides whether
      // to reject (mandatory-scanner path) or proceed.
      return {
        clean: true,
        skipped: true,
        threats: [],
        scanId: null,
        provider: null,
        scanners: [],
        mode,
        latencyMs: Date.now() - startedAt,
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    const buffer = Buffer.from(content, 'utf-8');
    const scanArgs = {
      content: buffer,
      fileName: typeof fileName === 'string' ? fileName.slice(0, 256) : 'upload',
      fileType: typeof fileType === 'string' ? fileType.slice(0, 64) : null,
    };

    if (mode === 'all_configured') {
      return await this._scanAllConfigured(scannerRows, scanArgs, startedAt);
    }
    // default: single_with_fallback
    return await this._scanSingleWithFallback(scannerRows, scanArgs, startedAt);
  }

  // -- Scan mode: single_with_fallback -----------------------------------------
  //
  // Try scanners in priority order. The FIRST scanner that produces an
  // authoritative result (clean OR flagged, no error) wins. Scanners that error
  // are recorded as attempted-with-error and we fall through to the next. If
  // every configured scanner errors, fail-closed.
  async _scanSingleWithFallback(scannerRows, scanArgs, startedAt) {
    const scannerDetails = [];

    for (const row of scannerRows) {
      const detail = await this._runScanner(row, scanArgs);
      scannerDetails.push(detail);

      // Authoritative result: scanner returned without error.
      if (!detail.error) {
        this._recordScanCounters(row.id, detail);
        return {
          clean: detail.clean,
          skipped: false,
          threats: detail.threats || [],
          scanId: detail.scanId || null,
          provider: row.provider_type,
          providerDisplayName: row.display_name,
          scanners: scannerDetails,
          mode: 'single_with_fallback',
          latencyMs: Date.now() - startedAt,
          inspectorVersion: INSPECTOR_VERSION,
        };
      }
      // Scanner errored -- record failure and try next.
      this._recordScanFailure(row.id);
    }

    // Every scanner errored. Fail-closed.
    return {
      clean: false,
      skipped: false,
      threats: [],
      scanId: null,
      provider: null,
      providerDisplayName: null,
      scanners: scannerDetails,
      mode: 'single_with_fallback',
      latencyMs: Date.now() - startedAt,
      error: `all ${scannerRows.length} configured scanner(s) errored -- fail-closed`,
      inspectorVersion: INSPECTOR_VERSION,
    };
  }

  // -- Scan mode: all_configured -----------------------------------------------
  //
  // Run all enabled scanners in parallel. The upload passes only if EVERY
  // scanner returns clean=true. Any flagged verdict, any scanner error, fails
  // the upload with the union of threat names.
  async _scanAllConfigured(scannerRows, scanArgs, startedAt) {
    const promises = scannerRows.map((row) => this._runScanner(row, scanArgs)
      .then((detail) => ({ row, detail })));
    const settled = await Promise.all(promises);

    const allThreats = [];
    let anyFailed = false;
    let anyErrored = false;
    const providers = [];
    const scanIds = [];

    for (const { row, detail } of settled) {
      if (detail.error) {
        anyErrored = true;
        this._recordScanFailure(row.id);
      } else {
        this._recordScanCounters(row.id, detail);
        if (!detail.clean) anyFailed = true;
        if (Array.isArray(detail.threats)) {
          for (const t of detail.threats) {
            // Tag threat with provider for clarity in audit.
            allThreats.push(`[${row.provider_type}] ${t}`);
          }
        }
      }
      providers.push(row.provider_type);
      if (detail.scanId) scanIds.push(`${row.provider_type}:${detail.scanId}`);
    }

    const clean = !anyFailed && !anyErrored;
    const detailsArray = settled.map((s) => s.detail);

    let error;
    if (anyErrored && !anyFailed) {
      const erroredCount = settled.filter((s) => s.detail.error).length;
      error = `${erroredCount}/${scannerRows.length} scanner(s) errored in all_configured mode -- fail-closed`;
    }

    return {
      clean,
      skipped: false,
      threats: allThreats.slice(0, 100),
      scanId: scanIds.join('|') || null,
      provider: providers.join(','),
      providerDisplayName: null,
      scanners: detailsArray,
      mode: 'all_configured',
      latencyMs: Date.now() - startedAt,
      ...(error ? { error } : {}),
      inspectorVersion: INSPECTOR_VERSION,
    };
  }

  // Run a single scanner against the supplied args. Returns a detail object with
  // the scanner's result merged with the row metadata. Never throws -- wraps
  // everything in fail-closed semantics. The detail object's `error` field is
  // set when the scanner errored.
  async _runScanner(row, scanArgs) {
    const scannerStarted = Date.now();
    const baseDetail = {
      id: row.id,
      provider_type: row.provider_type,
      display_name: row.display_name,
      attempted: true,
      clean: false,
      threats: [],
      scanId: null,
      latencyMs: 0,
    };

    let scanner;
    try {
      scanner = this._loadScannerModule(row.provider_type);
    } catch (err) {
      return Object.assign({}, baseDetail, { latencyMs: Date.now() - scannerStarted,
        error: `module load failed: ${err.message}` });
    }

    let credentials;
    try {
      credentials = openTier1('malware_scanner_integrations.credentials_encrypted', row.credentials_encrypted);
    } catch (err) {
      return Object.assign({}, baseDetail, { latencyMs: Date.now() - scannerStarted,
        error: `credential decryption failed: ${err.message}` });
    }

    let result;
    try {
      result = await scanner.inspectFile({
        content: scanArgs.content,
        fileName: scanArgs.fileName,
        fileType: scanArgs.fileType,
        credentials,
      });
    } catch (err) {
      return Object.assign({}, baseDetail, { latencyMs: Date.now() - scannerStarted,
        error: `scanner threw: ${err.message || String(err)}` });
    }

    if (!result || typeof result !== 'object') {
      return Object.assign({}, baseDetail, { latencyMs: Date.now() - scannerStarted,
        error: 'scanner returned non-object result' });
    }
    if (typeof result.clean !== 'boolean') {
      return Object.assign({}, baseDetail, { latencyMs: Date.now() - scannerStarted,
        error: 'scanner result missing required boolean clean field' });
    }
    // The scanner's own error field, if set, propagates as an error in our detail
    // -- even if clean=false was technically returned, the scanner is telling us
    // it did not actually complete an authoritative analysis.
    if (result.error) {
      return Object.assign({}, baseDetail, { latencyMs: result.latencyMs || (Date.now() - scannerStarted),
        error: result.error,
        clean: false,
        threats: Array.isArray(result.threats) ? result.threats.map(String).slice(0, 50) : [] });
    }

    return Object.assign({}, baseDetail, {
      clean: result.clean,
      threats: Array.isArray(result.threats) ? result.threats.map(String).slice(0, 50) : [],
      scanId: typeof result.scanId === 'string' ? result.scanId.slice(0, 128) : null,
      latencyMs: result.latencyMs || (Date.now() - scannerStarted),
    });
  }

  // -- Helpers -----------------------------------------------------------------

  // Load a scanner module by provider_type. Cached after first load.
  _loadScannerModule(providerType) {
    if (this._scannerModuleCache.has(providerType)) {
      return this._scannerModuleCache.get(providerType);
    }
    const moduleFile = PROVIDER_MODULE_NAMES[providerType];
    if (!moduleFile) {
      throw new Error(`no module mapping for provider_type: ${providerType}`);
    }
    const modulePath = path.join(SCANNER_DIR, moduleFile + '.js');
    let mod;
    try {
      mod = require(modulePath);
    } catch (err) {
      throw new Error(`require(${modulePath}) failed: ${err.message}`);
    }
    if (!mod || typeof mod.inspectFile !== 'function' || typeof mod.testConnection !== 'function') {
      throw new Error(`scanner module ${moduleFile}.js missing inspectFile/testConnection exports`);
    }
    if (mod.PROVIDER_TYPE !== providerType) {
      throw new Error(`scanner module ${moduleFile}.js has PROVIDER_TYPE=${mod.PROVIDER_TYPE}, expected ${providerType}`);
    }
    this._scannerModuleCache.set(providerType, mod);
    return mod;
  }

  // Update last_scan_at and aggregate counters for a successful scan.
  _recordScanCounters(scannerId, detail) {
    try {
      const flagged = !detail.clean ? 1 : 0;
      this.db.prepare(`UPDATE malware_scanner_integrations
        SET last_scan_at = datetime('now'),
            total_scans = total_scans + 1,
            total_threats_detected = total_threats_detected + ?
        WHERE id = ?`).run(flagged, scannerId);
    } catch (_e) { /* best-effort */ }
  }

  _recordScanFailure(scannerId) {
    try {
      this.db.prepare(`UPDATE malware_scanner_integrations
        SET last_scan_at = datetime('now'),
            total_failures = total_failures + 1
        WHERE id = ?`).run(scannerId);
    } catch (_e) { /* best-effort */ }
  }

  // Convert a raw DB row to the API-friendly shape (no encrypted credentials,
  // booleans for booleans). Never returns the encrypted credential blob to
  // callers -- only the dispatcher's internal _runScanner sees it.
  _normalizeScannerRow(row) {
    return {
      id: row.id,
      provider_type: row.provider_type,
      display_name: row.display_name,
      priority: row.priority,
      enabled: row.enabled === 1,
      configured_by: row.configured_by,
      configured_at: row.configured_at,
      last_test_at: row.last_test_at,
      last_test_status: row.last_test_status,
      last_test_error: row.last_test_error,
      last_scan_at: row.last_scan_at,
      total_scans: row.total_scans,
      total_threats_detected: row.total_threats_detected,
      total_failures: row.total_failures,
    };
  }
}

module.exports = {
  IntegrationManager,
  INSPECTOR_VERSION,
  VALID_PROVIDER_TYPES,
  VALID_SCAN_MODES,
  DEFAULT_SCAN_MODE,
};
