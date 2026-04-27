// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Bandwidth & Throughput Monitor
// Tracks bytes in/out per rolling window. Alerts on anomalous spikes that
// could indicate data exfiltration, C2 activity, or compromised endpoints.
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('./logger');

const WINDOW_MS = 15 * 60 * 1000;  // 15-minute rolling window
const ALERT_MULTIPLIER = 5;         // alert if current > 5x rolling average
const MAX_SINGLE_RESPONSE_MB = 50;  // alert if any single response > 50MB
const CHECK_INTERVAL_MS = 60000;    // check every 60 seconds

class BandwidthMonitor {
  constructor() {
    this.windows = [];      // [{ timestamp, bytesIn, bytesOut }]
    this.currentWindow = { bytesIn: 0, bytesOut: 0, requests: 0, startedAt: Date.now() };
    this.rollingAvgIn = 0;
    this.rollingAvgOut = 0;
    this.alertCallback = null;
    this.intervalId = null;
  }

  /**
   * Set callback for bandwidth alerts.
   * @param {function} fn - called with { type, message, currentBytes, avgBytes, timestamp }
   */
  onAlert(fn) {
    this.alertCallback = fn;
  }

  /**
   * Express middleware — tracks request/response sizes.
   */
  middleware() {
    return (req, res, next) => {
      // Track incoming bytes
      const contentLength = parseInt(req.headers['content-length'], 10) || 0;
      this.currentWindow.bytesIn += contentLength;
      this.currentWindow.requests++;

      // Track outgoing bytes by wrapping res.write and res.end
      const originalWrite = res.write;
      const originalEnd = res.end;
      let bytesOut = 0;

      res.write = function(chunk, ...args) {
        if (chunk) bytesOut += Buffer.byteLength(chunk);
        return originalWrite.apply(this, [chunk, ...args]);
      };

      res.end = function(chunk, ...args) {
        if (chunk) bytesOut += Buffer.byteLength(chunk);

        // Record
        this.currentWindow = this.currentWindow || {};
        return originalEnd.apply(this, [chunk, ...args]);
      }.bind({ currentWindow: this.currentWindow });

      // On response finish, record outgoing bytes
      res.on('finish', () => {
        this.currentWindow.bytesOut += bytesOut;

        // Check for oversized single response
        if (bytesOut > MAX_SINGLE_RESPONSE_MB * 1024 * 1024) {
          this._alert({
            type: 'LARGE_RESPONSE',
            message: `Single response exceeded ${MAX_SINGLE_RESPONSE_MB}MB (${(bytesOut / 1024 / 1024).toFixed(2)}MB)`,
            path: req.path,
            bytesOut,
          });
        }
      });

      next();
    };
  }

  /**
   * Start the periodic check.
   */
  start() {
    this.intervalId = setInterval(() => this._rotateWindow(), CHECK_INTERVAL_MS);
    logger.info('Bandwidth monitor started', { windowMs: WINDOW_MS, alertMultiplier: ALERT_MULTIPLIER });
  }

  stop() {
    if (this.intervalId) clearInterval(this.intervalId);
  }

  /**
   * Get current stats.
   */
  getStats() {
    return {
      currentWindow: { ...this.currentWindow, durationMs: Date.now() - this.currentWindow.startedAt },
      rollingAvgBytesIn: Math.round(this.rollingAvgIn),
      rollingAvgBytesOut: Math.round(this.rollingAvgOut),
      windowCount: this.windows.length,
      alertMultiplier: ALERT_MULTIPLIER,
    };
  }

  // ── Internal ───────────────────────────────────────────────────────────

  _rotateWindow() {
    const now = Date.now();

    // Archive current window
    this.windows.push({
      timestamp: now,
      bytesIn: this.currentWindow.bytesIn,
      bytesOut: this.currentWindow.bytesOut,
      requests: this.currentWindow.requests,
    });

    // Drop windows older than the rolling period
    const cutoff = now - WINDOW_MS;
    this.windows = this.windows.filter(w => w.timestamp > cutoff);

    // Compute rolling averages
    if (this.windows.length > 1) {
      const totalIn = this.windows.reduce((s, w) => s + w.bytesIn, 0);
      const totalOut = this.windows.reduce((s, w) => s + w.bytesOut, 0);
      this.rollingAvgIn = totalIn / this.windows.length;
      this.rollingAvgOut = totalOut / this.windows.length;

      // Check for anomalous spike
      const lastWindow = this.windows[this.windows.length - 1];

      if (this.rollingAvgOut > 0 && lastWindow.bytesOut > this.rollingAvgOut * ALERT_MULTIPLIER) {
        this._alert({
          type: 'BANDWIDTH_SPIKE_OUT',
          message: `Outbound bandwidth spike: ${(lastWindow.bytesOut / 1024).toFixed(1)}KB vs avg ${(this.rollingAvgOut / 1024).toFixed(1)}KB (${ALERT_MULTIPLIER}x threshold)`,
          currentBytes: lastWindow.bytesOut,
          avgBytes: this.rollingAvgOut,
        });
      }

      if (this.rollingAvgIn > 0 && lastWindow.bytesIn > this.rollingAvgIn * ALERT_MULTIPLIER) {
        this._alert({
          type: 'BANDWIDTH_SPIKE_IN',
          message: `Inbound bandwidth spike: ${(lastWindow.bytesIn / 1024).toFixed(1)}KB vs avg ${(this.rollingAvgIn / 1024).toFixed(1)}KB`,
          currentBytes: lastWindow.bytesIn,
          avgBytes: this.rollingAvgIn,
        });
      }
    }

    // Reset current window
    this.currentWindow = { bytesIn: 0, bytesOut: 0, requests: 0, startedAt: now };
  }

  _alert(data) {
    const alert = { ...data, timestamp: new Date().toISOString() };
    logger.warn('BANDWIDTH ALERT', alert);
    if (this.alertCallback) this.alertCallback(alert);
  }
}

// Singleton
const bandwidthMonitor = new BandwidthMonitor();

module.exports = { bandwidthMonitor, BandwidthMonitor };
