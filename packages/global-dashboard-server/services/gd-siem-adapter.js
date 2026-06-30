// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — SIEM CEF/Syslog Output Adapter (B6a)
//
// GD-server twin of the regional SIEM adapter. Forwards GD security events and
// the GD metrics line to the operator's SIEM as CEF over syslog (tcp / udp /
// tls). Events describe the GD server ITSELF as a protected asset (ingest-trust
// failures, signing-key anomalies, runtime/FIM/auth anomalies) -- never analyst
// data, which the GD never holds.
//
// Differences from the regional adapter: the GD has no cef-archive-spool yet
// (the GD durable CEF archive is a B6b concern), so this adapter does not tee;
// the CEF device-product is "GlobalDashboard" with the real GD version so GD
// events are distinguishable in the SIEM; and a sendRaw() entry sends a pre-
// formatted CEF line (the GD metrics-collector toCEF output).
//
// Best-effort: a send never throws -- it resolves { sent, error }. TLS verifies
// the SIEM certificate (rejectUnauthorized: true).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const dgram = require('dgram');
const net = require('net');
const tls = require('tls');

const SEND_TIMEOUT_MS = 5000;
const DEFAULT_SYSLOG_PORT = 6514;

// Read the GD version once for the CEF device-version field (defensive).
let _pkgVersion = 'unknown';
try {
  const p = require('../package.json');
  if (typeof p.version === 'string') _pkgVersion = p.version;
} catch (_) { /* leave 'unknown' */ }

class GdSiemAdapter {
  constructor(endpoint, protocol = 'tcp') {
    this.endpoint = endpoint;
    this.protocol = String(protocol || 'tcp').toLowerCase(); // tcp | udp | tls
    this._parseEndpoint();
  }

  _parseEndpoint() {
    try {
      const url = new URL(this.endpoint);
      this.host = url.hostname;
      this.port = parseInt(url.port, 10) || DEFAULT_SYSLOG_PORT;
    } catch {
      const parts = (this.endpoint || '').split(':');
      this.host = parts[0] || 'localhost';
      this.port = parseInt(parts[1], 10) || DEFAULT_SYSLOG_PORT;
    }
  }

  // Build + send a CEF event line for a GD security event. detail is sanitized
  // (CEF reserves | and \ ) so an attacker-influenced field cannot break the
  // CEF framing.
  async sendEvent(eventType, severity, detail) {
    const type = String(eventType || 'GD_EVENT').replace(/[|\\]/g, '_');
    const safe = String(detail == null ? '' : detail).replace(/[|\\]/g, '_');
    const cef = `CEF:0|FireAlive|GlobalDashboard|${_pkgVersion}|${type}|${type}|${severity}|msg=${safe} ts=${new Date().toISOString()}`;
    return this.sendRaw(cef);
  }

  // Send a pre-formatted CEF line (e.g. the GD metrics-collector toCEF output)
  // wrapped in an RFC 5424 syslog frame. Resolves { sent } or { sent:false,
  // error }; never throws.
  async sendRaw(cefLine) {
    const syslog = `<134>1 ${new Date().toISOString()} firealive-gd - - - ${cefLine}`;
    return new Promise((resolve) => {
      try {
        if (this.protocol === 'udp') {
          const client = dgram.createSocket('udp4');
          const buf = Buffer.from(syslog);
          client.send(buf, this.port, this.host, (err) => {
            try { client.close(); } catch (_) { /* ignore */ }
            resolve(err ? { sent: false, error: err.message } : { sent: true });
          });
        } else if (this.protocol === 'tls') {
          const client = tls.connect({ host: this.host, port: this.port, rejectUnauthorized: true }, () => {
            client.write(syslog + '\n');
            client.end();
            resolve({ sent: true });
          });
          client.on('error', (e) => resolve({ sent: false, error: e.message }));
          client.setTimeout(SEND_TIMEOUT_MS, () => { client.destroy(); resolve({ sent: false, error: 'Timeout' }); });
        } else {
          const client = new net.Socket();
          client.connect(this.port, this.host, () => {
            client.write(syslog + '\n');
            client.end();
            resolve({ sent: true });
          });
          client.on('error', (e) => resolve({ sent: false, error: e.message }));
          client.setTimeout(SEND_TIMEOUT_MS, () => { client.destroy(); resolve({ sent: false, error: 'Timeout' }); });
        }
      } catch (e) {
        resolve({ sent: false, error: e && e.message });
      }
    });
  }

  async testConnection() {
    return this.sendEvent('GD_SIEM_TEST', 3, 'FireAlive Global Dashboard SIEM connectivity test');
  }
}

module.exports = { GdSiemAdapter };
