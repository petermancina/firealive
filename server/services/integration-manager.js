const https = require('https');
const http = require('http');

// EDR file-inspection defaults
const DEFAULT_EDR_TIMEOUT_MS = 15000;
const DEFAULT_EDR_SCAN_PATH = '/api/v1/scan/file';
const INSPECTOR_VERSION = '1.0.0';

class IntegrationManager {
  constructor(db) { this.db = db; this._initTables(); }
  _initTables() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS integration_status (
      id TEXT PRIMARY KEY, type TEXT, platform TEXT, endpoint TEXT,
      status TEXT DEFAULT 'not configured', last_check TEXT,
      last_success TEXT, error_count INTEGER DEFAULT 0
    )`).run();
  }
  async testConnection(type, endpoint) {
    try {
      const url = new URL(endpoint);
      return new Promise((resolve) => {
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request({ hostname: url.hostname, port: url.port, path: '/health', method: 'GET', timeout: 5000 }, (res) => {
          resolve({ connected: true, status: res.statusCode, type });
        });
        req.on('error', (e) => resolve({ connected: false, error: e.message, type }));
        req.on('timeout', () => { req.destroy(); resolve({ connected: false, error: 'Timeout', type }); });
        req.end();
      });
    } catch (e) { return { connected: false, error: e.message, type }; }
  }
  saveConfig(type, platform, endpoint, apiKeyHash) {
    this.db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
      `${type}_config`, JSON.stringify({ platform, endpoint, apiKeyHash, configuredAt: new Date().toISOString() })
    );
    this.db.prepare("INSERT OR REPLACE INTO integration_status (id, type, platform, endpoint, status, last_check) VALUES (?, ?, ?, ?, 'configured', ?)").run(
      type, type, platform, endpoint, new Date().toISOString()
    );
    return { saved: true, type, platform };
  }
  getAll() { return this.db.prepare("SELECT * FROM integration_status").all(); }
  getConfig(type) {
    const row = this.db.prepare("SELECT value FROM config WHERE key = ?").get(`${type}_config`);
    return row ? JSON.parse(row.value) : null;
  }

  // ── Layer-2 file inspection (EDR) ─────────────────────────────────────────
  //
  // Called from upload handlers (routes/ooda.js POST /policies and POST /aar)
  // AFTER the layer-1 content sanitizer has cleared the content. EDR catches
  // novel malware signatures and threat-intel matches that the internal
  // sanitizer cannot stay current on; the sanitizer catches FireAlive-domain
  // threats (prompt injection, scenario-tree tampering) that EDR doesn't
  // know exist. Both gates must pass.
  //
  // Behavior contract:
  //   - If EDR is configured  → call EDR, fail-closed on any error or threat
  //   - If EDR is NOT configured → return { skipped: true, clean: true }
  //                                  Caller is expected to have already run
  //                                  the layer-1 sanitizer; this skip does
  //                                  NOT mean "upload is OK," it means
  //                                  "this layer has nothing to add."
  //
  // Provider abstraction:
  //   This commit ships only the 'custom' provider — a deterministic HTTP
  //   POST to the configured endpoint with the file content in the body.
  //   The custom provider is provider-agnostic: any EDR with a "scan this
  //   blob and tell me if it's clean" REST endpoint can be wired up by
  //   pointing the integration at it. Vendor-specific providers (CrowdStrike
  //   Falcon, SentinelOne, Microsoft Defender) can land in feature phases
  //   when they have actual access to test against — adding their HTTP
  //   shapes here without a test instance would be guesswork.
  //
  // Returns: {
  //   clean: bool,            true only if EDR returned a clean determination
  //   skipped: bool,          true if EDR not configured (caller decides)
  //   threats: [string,...],  threat names from EDR if not clean
  //   scanId: string,         provider's scan id (for trace correlation)
  //   provider: string,       which provider performed the scan
  //   latencyMs: number,      end-to-end call time
  //   error: string,          present only on call failure (timeout, network,
  //                           non-2xx response, parse failure). When error
  //                           is set, clean is false (fail-closed).
  //   inspectorVersion: string  this module's INSPECTOR_VERSION for audit
  // }
  async inspectFile(content, fileName, fileType) {
    const startedAt = Date.now();

    const edrConfig = this.getConfig('edr');
    if (!edrConfig || !edrConfig.endpoint) {
      return {
        clean: true,
        skipped: true,
        threats: [],
        scanId: null,
        provider: null,
        latencyMs: 0,
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    if (typeof content !== 'string' || content.length === 0) {
      return {
        clean: false,
        skipped: false,
        threats: ['empty or non-string content rejected before EDR call'],
        scanId: null,
        provider: edrConfig.platform || 'unknown',
        latencyMs: Date.now() - startedAt,
        error: 'invalid content',
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    const platform = (edrConfig.platform || 'custom').toLowerCase();

    // For now, all platforms route through the custom HTTP shape. Vendor-
    // specific shapes (Falcon, SentinelOne, Defender) get added here as
    // separate cases when they're implemented.
    let scanResult;
    try {
      scanResult = await this._callCustomScanEndpoint(edrConfig, content, fileName, fileType);
    } catch (err) {
      return {
        clean: false,
        skipped: false,
        threats: [],
        scanId: null,
        provider: platform,
        latencyMs: Date.now() - startedAt,
        error: err.message || String(err),
        inspectorVersion: INSPECTOR_VERSION,
      };
    }

    const latencyMs = Date.now() - startedAt;

    // Touch integration_status to record success/failure for the
    // operational dashboard
    this._recordScanOutcome(platform, scanResult.clean ? 'success' : 'detected_threat');

    return {
      clean: scanResult.clean,
      skipped: false,
      threats: scanResult.threats || [],
      scanId: scanResult.scanId || null,
      provider: platform,
      latencyMs,
      inspectorVersion: INSPECTOR_VERSION,
    };
  }

  // Custom-provider HTTP shape. POST { fileName, fileType, content } as JSON
  // to <endpoint><scanPath>, expecting a JSON response of shape:
  //   { clean: bool, threats?: string[], scanId?: string }
  // Anything else (non-2xx, bad JSON, missing required field) is treated as
  // an error and the caller fail-closes.
  _callCustomScanEndpoint(edrConfig, content, fileName, fileType) {
    return new Promise((resolve, reject) => {
      let url;
      try {
        const scanPath = edrConfig.scanPath || DEFAULT_EDR_SCAN_PATH;
        url = new URL(scanPath, edrConfig.endpoint);
      } catch (urlErr) {
        return reject(new Error('invalid EDR endpoint: ' + urlErr.message));
      }

      const body = JSON.stringify({
        fileName: typeof fileName === 'string' ? fileName.slice(0, 256) : 'upload',
        fileType: typeof fileType === 'string' ? fileType.slice(0, 64) : 'text/plain',
        content,
      });

      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      };
      // The integration's saveConfig() persists apiKeyHash, not the raw key.
      // Senders that need bearer auth must pre-share the actual key out of
      // band; we forward the hash as the bearer token only if the deploying
      // org has configured the endpoint to accept it that way. For the
      // custom shape this is sufficient because the endpoint is operator-
      // controlled. Vendor providers will need real credential handling in
      // their respective branches.
      if (edrConfig.apiKeyHash) {
        headers['Authorization'] = 'Bearer ' + edrConfig.apiKeyHash;
      }

      const mod = url.protocol === 'https:' ? https : http;
      const timeoutMs = edrConfig.timeoutMs || DEFAULT_EDR_TIMEOUT_MS;

      const req = mod.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'POST',
        headers,
        timeout: timeoutMs,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error('EDR scan returned status ' + res.statusCode));
          }
          let parsed;
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch (parseErr) {
            return reject(new Error('EDR scan returned non-JSON body'));
          }
          if (typeof parsed.clean !== 'boolean') {
            return reject(new Error('EDR scan response missing required boolean field "clean"'));
          }
          resolve({
            clean: parsed.clean,
            threats: Array.isArray(parsed.threats) ? parsed.threats.map(String).slice(0, 50) : [],
            scanId: typeof parsed.scanId === 'string' ? parsed.scanId.slice(0, 128) : null,
          });
        });
      });

      req.on('error', (e) => reject(new Error('EDR scan network error: ' + e.message)));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('EDR scan timed out after ' + timeoutMs + 'ms'));
      });

      req.write(body);
      req.end();
    });
  }

  _recordScanOutcome(platform, status) {
    try {
      this.db.prepare(`UPDATE integration_status
        SET last_check = ?, status = ?
        WHERE id = 'edr'`).run(new Date().toISOString(), status);
    } catch (_) {
      // Best-effort; never let status bookkeeping fail the scan call
    }
  }
}
module.exports = { IntegrationManager, INSPECTOR_VERSION };
