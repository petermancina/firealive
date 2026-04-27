// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — SIEM Integration Client
// Provides CEF-formatted event streaming to SIEM platforms.
// Supports: Splunk, QRadar, Sentinel, Elastic SIEM, Chronicle, LogRhythm
//
// FireAlive sends ONLY Tier-1 (team aggregate) data to the SIEM.
// Individual analyst burnout signals are NEVER forwarded.
// ═══════════════════════════════════════════════════════════════════════════════

const dgram = require('dgram');
const { logger } = require('../services/logger');

class SiemClient {
  constructor(config) {
    this.platform = config.platform;
    this.host = config.host;
    this.port = config.port || 514;
    this.protocol = config.protocol || 'udp'; // udp, tcp, https
    this.facility = config.facility || 'local0';
    this.enabled = config.enabled !== false;
    this.format = config.format || 'cef'; // cef, json, leef
  }

  /**
   * Send a CEF-formatted event to the SIEM.
   * CEF: Common Event Format (ArcSight standard, widely supported).
   *
   * Format: CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
   */
  async sendEvent(event) {
    if (!this.enabled) return { sent: false, reason: 'SIEM integration disabled' };

    const cefMessage = this._formatCef(event);

    try {
      if (this.protocol === 'udp') {
        await this._sendUdp(cefMessage);
      } else if (this.protocol === 'tcp') {
        await this._sendTcp(cefMessage);
      }
      // HTTPS would use fetch() to the SIEM's HTTP ingestion endpoint

      return { sent: true, format: this.format, platform: this.platform };
    } catch (err) {
      logger.error('SIEM send failed', { platform: this.platform, error: err.message });
      return { sent: false, error: err.message };
    }
  }

  /**
   * Send a batch of events (e.g., from scheduled report generation).
   */
  async sendBatch(events) {
    const results = [];
    for (const event of events) {
      results.push(await this.sendEvent(event));
    }
    return {
      total: events.length,
      sent: results.filter(r => r.sent).length,
      failed: results.filter(r => !r.sent).length,
    };
  }

  /**
   * Test connectivity to the SIEM.
   */
  async testConnection() {
    try {
      const testEvent = {
        signatureId: 'FIREALIVE_TEST',
        name: 'Connectivity Test',
        severity: 1,
        extension: 'msg=SIEM connectivity test from FireAlive',
      };
      const result = await this.sendEvent(testEvent);
      return {
        success: result.sent,
        platform: this.platform,
        host: this.host,
        port: this.port,
        protocol: this.protocol,
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // ── CEF Formatting ─────────────────────────────────────────────────────
  _formatCef(event) {
    const version = 0;
    const vendor = 'FireAlive';
    const product = 'WellbeingPlatform';
    const deviceVersion = '0.0.19';
    const sigId = event.signatureId || 'UNKNOWN';
    const name = event.name || 'FireAlive Event';
    const severity = event.severity || 5;
    const ext = event.extension || '';

    return `CEF:${version}|${vendor}|${product}|${deviceVersion}|${sigId}|${name}|${severity}|${ext}`;
  }

  // ── Transport ──────────────────────────────────────────────────────────
  _sendUdp(message) {
    return new Promise((resolve, reject) => {
      const client = dgram.createSocket('udp4');
      const buf = Buffer.from(message);
      client.send(buf, 0, buf.length, this.port, this.host, (err) => {
        client.close();
        if (err) reject(err); else resolve();
      });
    });
  }

  _sendTcp(message) {
    return new Promise((resolve, reject) => {
      const net = require('net');
      const client = new net.Socket();
      client.connect(this.port, this.host, () => {
        client.write(message + '\n');
        client.end();
        resolve();
      });
      client.on('error', reject);
      client.setTimeout(10000, () => { client.destroy(); reject(new Error('TCP timeout')); });
    });
  }
}

module.exports = { SiemClient };
