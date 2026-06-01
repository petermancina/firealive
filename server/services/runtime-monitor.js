// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Runtime Monitor
// Continuous monitoring during operation:
//   - File integrity monitoring (watches server source files for changes)
//   - CPU/memory consumption tracking with spike alerts
//   - Database read anomaly detection (injection indicator)
//   - Resource consumption metrics for SIEM export
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { logger } = require('./logger');

const SERVER_ROOT = path.join(__dirname, '..');
const CHECK_INTERVAL_MS = 30000;   // FIM check every 30 seconds
const METRICS_INTERVAL_MS = 15000; // resource metrics every 15 seconds
const CPU_SPIKE_THRESHOLD = 80;    // alert if >80% CPU
const MEM_SPIKE_MULTIPLIER = 3;    // alert if 3x baseline memory
// Sustained-load detection (hysteresis + dwell + cooldown). Defaults are
// SOC-grade and admin-overridable at runtime via configureThresholds() (the
// alert-config route wires stored overrides). Spikes above stay as low-severity
// early warnings; sustained breaches are higher-severity ('high').
const CPU_SUSTAINED_ENTER = 80;       // enter threshold (%)
const CPU_SUSTAINED_EXIT = 65;        // exit threshold (%) — hysteresis band
const CPU_SUSTAINED_DWELL = 8;        // ~2 min at the 15s metrics interval
const MEM_SUSTAINED_ENTER_MULT = 2;   // >=2x baseline RSS
const MEM_SUSTAINED_EXIT_MULT = 1.5;
const MEM_SUSTAINED_DWELL = 8;        // ~2 min
const DBREAD_SUSTAINED_ENTER_MULT = 5; // >=5x baseline reads
const DBREAD_SUSTAINED_EXIT_MULT = 3;
const DBREAD_SUSTAINED_DWELL = 2;     // ~1 min at the 30s FIM interval
const SUSTAINED_COOLDOWN_MS = 600000; // 10 min per alert type

class RuntimeMonitor {
  constructor() {
    this.fileHashes = {};
    this.fimInterval = null;
    this.metricsInterval = null;
    this.baselineMemory = null;
    this.lastCpu = null;
    this.alertCallback = null;
    this.dbReadCounts = [];        // sliding window of DB reads per interval
    this.dbReadBaseline = null;
    this.metrics = { cpu: 0, memMB: 0, heapMB: 0, dbReadsPerMin: 0, uptime: 0 };
    this.sustained = {};  // per-key { count, active, lastAlert } hysteresis state
    this.thresholds = {
      cpuEnter: CPU_SUSTAINED_ENTER, cpuExit: CPU_SUSTAINED_EXIT, cpuDwell: CPU_SUSTAINED_DWELL,
      memEnterMult: MEM_SUSTAINED_ENTER_MULT, memExitMult: MEM_SUSTAINED_EXIT_MULT, memDwell: MEM_SUSTAINED_DWELL,
      dbEnterMult: DBREAD_SUSTAINED_ENTER_MULT, dbExitMult: DBREAD_SUSTAINED_EXIT_MULT, dbDwell: DBREAD_SUSTAINED_DWELL,
      cooldownMs: SUSTAINED_COOLDOWN_MS,
    };
  }

  onAlert(fn) { this.alertCallback = fn; }

  // Merge admin overrides over the default sustained-load thresholds. Called by
  // the alert-config route / startup wiring; unknown keys are ignored.
  configureThresholds(overrides) {
    if (overrides && typeof overrides === 'object') {
      const next = { ...this.thresholds };
      for (const k of Object.keys(this.thresholds)) {
        if (typeof overrides[k] === 'number' && isFinite(overrides[k])) next[k] = overrides[k];
      }
      this.thresholds = next;
    }
    return { ...this.thresholds };
  }

  // Hysteresis + dwell evaluator. Increments a per-key counter while value is at
  // or above `enter`; resets only once value falls below `exit` (the band between
  // exit and enter holds the counter, preventing flapping). Fires once when the
  // counter reaches `dwell` and the per-key cooldown has elapsed; re-arms after
  // the value recovers below `exit`.
  _evalSustained(key, value, enter, exit, dwell) {
    const s = this.sustained[key] || (this.sustained[key] = { count: 0, active: false, lastAlert: 0 });
    if (value >= enter) s.count++;
    else if (value < exit) { s.count = 0; s.active = false; }
    const now = Date.now();
    if (s.count >= dwell && !s.active && (now - s.lastAlert) >= this.thresholds.cooldownMs) {
      s.active = true;
      s.lastAlert = now;
      return true;
    }
    return false;
  }

  // ── File Integrity Monitoring ──────────────────────────────────────────

  _hashFile(filePath) {
    try {
      return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
    } catch { return null; }
  }

  _scanFiles() {
    const files = {};
    const dirs = ['routes', 'middleware', 'services', 'integrations', 'db'];
    const indexPath = path.join(SERVER_ROOT, 'index.js');
    if (fs.existsSync(indexPath)) files['server/index.js'] = this._hashFile(indexPath);

    for (const dir of dirs) {
      const dirPath = path.join(SERVER_ROOT, dir);
      if (!fs.existsSync(dirPath)) continue;
      for (const f of fs.readdirSync(dirPath).filter(f => f.endsWith('.js'))) {
        files[`server/${dir}/${f}`] = this._hashFile(path.join(dirPath, f));
      }
    }
    return files;
  }

  _initFIM() {
    this.fileHashes = this._scanFiles();
    logger.info('FIM baseline established', { files: Object.keys(this.fileHashes).length });
  }

  _checkFIM() {
    const current = this._scanFiles();

    for (const [file, hash] of Object.entries(this.fileHashes)) {
      if (!current[file]) {
        this._alert({ type: 'FIM_FILE_DELETED', severity: 'critical', file, message: `Source file deleted during runtime: ${file}` });
      } else if (current[file] !== hash) {
        this._alert({ type: 'FIM_FILE_MODIFIED', severity: 'critical', file, message: `Source file modified during runtime: ${file}` });
        this.fileHashes[file] = current[file]; // update so we don't spam
      }
    }

    for (const file of Object.keys(current)) {
      if (!this.fileHashes[file]) {
        this._alert({ type: 'FIM_FILE_ADDED', severity: 'warning', file, message: `New source file detected during runtime: ${file}` });
        this.fileHashes[file] = current[file];
      }
    }
  }

  // ── CPU/Memory Monitoring ──────────────────────────────────────────────

  _collectMetrics() {
    const mem = process.memoryUsage();
    const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
    const rssMB = Math.round(mem.rss / 1024 / 1024);

    // CPU usage (approximate via process.cpuUsage)
    const cpuUsage = process.cpuUsage(this.lastCpu);
    this.lastCpu = process.cpuUsage();
    const cpuPercent = Math.round((cpuUsage.user + cpuUsage.system) / (METRICS_INTERVAL_MS * 1000) * 100);

    this.metrics = {
      cpu: Math.min(cpuPercent, 100),
      memMB: rssMB,
      heapMB,
      uptime: Math.floor(process.uptime()),
      dbReadsPerMin: this.dbReadBaseline ? Math.round(this.dbReadCounts.reduce((s, v) => s + v, 0) / Math.max(this.dbReadCounts.length, 1)) : 0,
      loadAvg: os.loadavg(),
      freeMemMB: Math.round(os.freemem() / 1024 / 1024),
      totalMemMB: Math.round(os.totalmem() / 1024 / 1024),
    };

    // Set baseline on first collection
    if (!this.baselineMemory) this.baselineMemory = rssMB;

    // CPU spike detection
    if (this.metrics.cpu > CPU_SPIKE_THRESHOLD) {
      this._alert({ type: 'CPU_SPIKE', severity: 'warning', cpu: this.metrics.cpu, message: `CPU usage at ${this.metrics.cpu}% (threshold: ${CPU_SPIKE_THRESHOLD}%)` });
    }

    // Memory spike detection
    if (rssMB > this.baselineMemory * MEM_SPIKE_MULTIPLIER) {
      this._alert({ type: 'MEMORY_SPIKE', severity: 'warning', memMB: rssMB, baselineMB: this.baselineMemory,
        message: `Memory usage ${rssMB}MB (${MEM_SPIKE_MULTIPLIER}x baseline of ${this.baselineMemory}MB)` });
    }

    // Sustained CPU (hysteresis + dwell) — distinct, higher-severity signal than
    // the transient spike above.
    const t = this.thresholds;
    if (this._evalSustained('cpu', this.metrics.cpu, t.cpuEnter, t.cpuExit, t.cpuDwell)) {
      const mins = Math.round((t.cpuDwell * METRICS_INTERVAL_MS) / 60000);
      this._alert({ type: 'CPU_SUSTAINED', severity: 'high', cpu: this.metrics.cpu,
        message: `CPU sustained >=${t.cpuEnter}% for ${t.cpuDwell} intervals (~${mins} min)` });
    }

    // Sustained memory
    if (this.baselineMemory) {
      const memEnter = this.baselineMemory * t.memEnterMult;
      const memExit = this.baselineMemory * t.memExitMult;
      if (this._evalSustained('mem', rssMB, memEnter, memExit, t.memDwell)) {
        this._alert({ type: 'MEMORY_SUSTAINED', severity: 'high', memMB: rssMB, baselineMB: this.baselineMemory,
          message: `Memory sustained >=${t.memEnterMult}x baseline (${Math.round(memEnter)}MB) for ${t.memDwell} intervals` });
      }
    }
  }

  // ── Database Read Anomaly Detection ────────────────────────────────────
  // Middleware records DB reads. Spikes may indicate SQL injection attempts.

  recordDbRead() {
    if (this.dbReadCounts.length === 0) this.dbReadCounts.push(0);
    this.dbReadCounts[this.dbReadCounts.length - 1]++;
  }

  _checkDbReads() {
    this.dbReadCounts.push(0);
    if (this.dbReadCounts.length > 60) this.dbReadCounts.shift(); // keep 60 intervals

    if (this.dbReadCounts.length >= 5) {
      const recent = this.dbReadCounts.slice(-5);
      const avg = this.dbReadCounts.slice(0, -1).reduce((s, v) => s + v, 0) / (this.dbReadCounts.length - 1);
      const current = recent[recent.length - 1];
      this.dbReadBaseline = avg;

      if (avg > 0 && current > avg * 5) {
        this._alert({ type: 'DB_READ_SPIKE', severity: 'warning', current, baseline: Math.round(avg),
          message: `Database reads spiked to ${current} (baseline: ${Math.round(avg)}). Possible injection attempt.` });
      }

      // Sustained DB reads (hysteresis + dwell) — a held read-rate elevation, as
      // opposed to a single-interval spike.
      if (avg > 0) {
        const t = this.thresholds;
        const dbEnter = avg * t.dbEnterMult;
        const dbExit = avg * t.dbExitMult;
        if (this._evalSustained('dbreads', current, dbEnter, dbExit, t.dbDwell)) {
          this._alert({ type: 'DB_READ_SUSTAINED', severity: 'high', current, baseline: Math.round(avg),
            message: `Database reads sustained >=${t.dbEnterMult}x baseline for ${t.dbDwell} intervals (current ${current}, baseline ${Math.round(avg)})` });
        }
      }
    }
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  start() {
    this._initFIM();
    this.lastCpu = process.cpuUsage();

    this.fimInterval = setInterval(() => {
      this._checkFIM();
      this._checkDbReads();
    }, CHECK_INTERVAL_MS);

    this.metricsInterval = setInterval(() => this._collectMetrics(), METRICS_INTERVAL_MS);

    logger.info('Runtime monitor started', { fimInterval: CHECK_INTERVAL_MS, metricsInterval: METRICS_INTERVAL_MS });
  }

  stop() {
    if (this.fimInterval) clearInterval(this.fimInterval);
    if (this.metricsInterval) clearInterval(this.metricsInterval);
  }

  getMetrics() { return { ...this.metrics, fileCount: Object.keys(this.fileHashes).length }; }

  _alert(data) {
    const alert = { ...data, timestamp: new Date().toISOString() };
    logger.warn('RUNTIME ALERT', alert);
    if (this.alertCallback) this.alertCallback(alert);
  }
}

const runtimeMonitor = new RuntimeMonitor();

module.exports = { runtimeMonitor };
