// FireAlive v1.0.0 — SIEM CEF/Syslog Output Adapter
const dgram = require('dgram');
const net = require('net');
const tls = require('tls');

class SiemAdapter {
  constructor(endpoint, protocol = 'tcp') {
    this.endpoint = endpoint;
    this.protocol = protocol; // tcp, udp, tls
    this._parseEndpoint();
  }

  _parseEndpoint() {
    try {
      const url = new URL(this.endpoint);
      this.host = url.hostname;
      this.port = parseInt(url.port) || 6514;
    } catch {
      const parts = (this.endpoint || '').split(':');
      this.host = parts[0] || 'localhost';
      this.port = parseInt(parts[1]) || 6514;
    }
  }

  async sendCEF(metrics) {
    const cef = `CEF:0|FireAlive|SOC-Wellbeing|v1.0.0|METRICS|Team Health|5|` +
      `teamHealth=${metrics.team_health?.avgCapacity || 0} ` +
      `analysts=${metrics.team_health?.analysts || 0} ` +
      `routingEnabled=${metrics.routing?.enabled || false} ` +
      `panicMode=${metrics.routing?.panicMode || false} ` +
      `peerSessions=${metrics.peer_sessions?.last24h || 0} ` +
      `authFailures=${metrics.auth?.failures24h || 0} ` +
      `auditIntact=${metrics.audit_integrity?.intact || false} ` +
      `fuse=${metrics.system?.fuse || 1}`;
    return this._send(cef);
  }

  async sendEvent(eventType, severity, detail) {
    const cef = `CEF:0|FireAlive|SOC-Wellbeing|v1.0.0|${eventType}|${eventType}|${severity}|msg=${detail} ts=${new Date().toISOString()}`;
    return this._send(cef);
  }

  async _send(message) {
    const syslog = `<134>1 ${new Date().toISOString()} firealive - - - ${message}`;
    return new Promise((resolve) => {
      if (this.protocol === 'udp') {
        const client = dgram.createSocket('udp4');
        const buf = Buffer.from(syslog);
        client.send(buf, this.port, this.host, (err) => {
          client.close();
          resolve(err ? { sent: false, error: err.message } : { sent: true });
        });
      } else if (this.protocol === 'tls') {
        const client = tls.connect({ host: this.host, port: this.port, rejectUnauthorized: true }, () => {
          client.write(syslog + '\n');
          client.end();
          resolve({ sent: true });
        });
        client.on('error', e => resolve({ sent: false, error: e.message }));
        client.setTimeout(5000, () => { client.destroy(); resolve({ sent: false, error: 'Timeout' }); });
      } else {
        const client = new net.Socket();
        client.connect(this.port, this.host, () => {
          client.write(syslog + '\n');
          client.end();
          resolve({ sent: true });
        });
        client.on('error', e => resolve({ sent: false, error: e.message }));
        client.setTimeout(5000, () => { client.destroy(); resolve({ sent: false, error: 'Timeout' }); });
      }
    });
  }

  async testConnection() {
    return this.sendEvent('TEST', 1, 'FireAlive SIEM connectivity test');
  }
}

module.exports = { SiemAdapter };
