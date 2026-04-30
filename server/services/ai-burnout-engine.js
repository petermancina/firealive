// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — AI Burnout Engine
// Handles: baseline creation, signal drift detection, message generation,
// recent impact tracking, training recommendations from gap analysis
// ═══════════════════════════════════════════════════════════════════════════════

class AiBurnoutEngine {
  constructor(db) {
    this.db = db;
  }

  // Record a signal reading from the AC
  recordSignal(analystId, signal, value) {
    this.db.prepare("INSERT INTO signal_readings (analyst_id, signal, value) VALUES (?, ?, ?)").run(analystId, signal, value);
    this._updateBaseline(analystId, signal, value);
  }

  // Build/update baseline from accumulated readings
  _updateBaseline(analystId, signal, value) {
    const existing = this.db.prepare("SELECT * FROM analyst_baselines WHERE analyst_id = ?").get(analystId);
    const col = this._signalToColumn(signal);
    if (!col) return;
    if (!existing) {
      // First reading — create baseline row
      const row = { analyst_id: analystId, cognitive_load: null, task_switching: null, queue_pressure: null, response_latency: null, break_compliance: null, shift_overtime: null, established_at: null, sample_count: 0 };
      row[col] = value;
      row.sample_count = 1;
      this.db.prepare("INSERT INTO analyst_baselines (analyst_id, cognitive_load, task_switching, queue_pressure, response_latency, break_compliance, shift_overtime, sample_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(analystId, row.cognitive_load, row.task_switching, row.queue_pressure, row.response_latency, row.break_compliance, row.shift_overtime, row.sample_count);
    } else {
      // Running average
      const count = existing.sample_count + 1;
      const oldVal = existing[col] || value;
      const newAvg = ((oldVal * existing.sample_count) + value) / count;
      const established = count >= 8 ? (existing.established_at || new Date().toISOString()) : null; // 8 readings = 1 shift baseline
      this.db.prepare(`UPDATE analyst_baselines SET ${col} = ?, sample_count = ?, established_at = COALESCE(?, established_at) WHERE analyst_id = ?`).run(newAvg, count, established, analystId);
    }
  }

  _signalToColumn(signal) {
    // SECURITY: Whitelist-only column mapping prevents SQL injection via column name
    const SAFE_COLUMNS = { 'cognitive_load': 'cognitive_load', 'task_switching': 'task_switching', 'queue_pressure': 'queue_pressure', 'response_latency': 'response_latency', 'break_compliance': 'break_compliance', 'shift_overtime': 'shift_overtime' };
    const col = SAFE_COLUMNS[signal];
    if (!col) throw new Error('Invalid signal name');
    return col;
  }

  // Get baseline + current for an analyst
  getSignals(analystId) {
    const baseline = this.db.prepare("SELECT * FROM analyst_baselines WHERE analyst_id = ?").get(analystId);
    if (!baseline || !baseline.established_at) {
      return { status: 'calibrating', message: 'Baseline pending — first-shift calibration required', signals: [], sampleCount: baseline?.sample_count || 0, samplesNeeded: 8 };
    }
    // Get last hour of readings
    const recent = this.db.prepare("SELECT signal, AVG(value) as avg FROM signal_readings WHERE analyst_id = ? AND recorded_at > datetime('now', '-1 hour') GROUP BY signal").all(analystId);
    const signals = ['cognitive_load', 'task_switching', 'queue_pressure', 'response_latency', 'break_compliance', 'shift_overtime'].map(sig => {
      const current = recent.find(r => r.signal === sig);
      const base = baseline[sig];
      const cur = current?.avg || base;
      const drift = base ? Math.abs((cur - base) / base) : 0;
      return { signal: sig, baseline: Math.round(base * 10) / 10, current: Math.round(cur * 10) / 10, drift: Math.round(drift * 100), status: drift > 0.2 ? 'elevated' : drift > 0.1 ? 'watch' : 'normal' };
    });
    const elevated = signals.filter(s => s.status === 'elevated').length;
    const message = elevated === 0 ? 'All signals within baseline range.' : elevated <= 2 ? `${elevated} signal${elevated > 1 ? 's' : ''} drifting — monitor closely.` : 'Multiple signals elevated — consider reduced ticket load.';
    return { status: 'active', message, signals, established: baseline.established_at };
  }

  // Record a positive impact
  recordImpact(analystId, type, description) {
    this.db.prepare("INSERT INTO analyst_impacts (analyst_id, type, description) VALUES (?, ?, ?)").run(analystId, type, description);
  }

  // Get recent impacts
  getImpacts(analystId) {
    return this.db.prepare("SELECT * FROM analyst_impacts WHERE analyst_id = ? ORDER BY recorded_at DESC LIMIT 10").all(analystId);
  }

  // AI training recommendations based on gap analysis
  getTrainingRecommendations(analystId) {
    const skills = this.db.prepare("SELECT * FROM analyst_skills WHERE analyst_id = ?").all(analystId);
    if (!skills.length) return { status: 'pending', message: 'Complete your first skills assessment to receive AI-generated training recommendations.', recommendations: [] };
    // Find gaps (skills below 70%)
    const gaps = skills.filter(s => s.score < 70).sort((a, b) => a.score - b.score);
    const TRAINING_MAP = {
      'siem': [{ module: 'SOC Level 1', url: 'https://tryhackme.com/room/introtosoc', platform: 'TryHackMe' }, { module: 'Alert Correlation', url: 'https://app.letsdefend.io/training/lessons/alert-correlation', platform: 'LetsDefend' }],
      'investigation': [{ module: 'SOC Analyst Path', url: 'https://academy.hackthebox.com/path/preview/soc-analyst', platform: 'HackTheBox' }, { module: 'Incident Investigation', url: 'https://app.letsdefend.io/training/lessons/incident-investigation', platform: 'LetsDefend' }],
      'escalation': [{ module: 'GCIH Prep', url: 'https://www.sans.org/cyber-security-courses/hacker-techniques-incident-handling/', platform: 'SANS' }],
      'threat_hunting': [{ module: 'Threat Hunting Splunk', url: 'https://cyberdefenders.org/blueteam-ctf-challenges/threat-hunting-splunk/', platform: 'CyberDefenders' }],
      'malware_analysis': [{ module: 'MalDoc101', url: 'https://cyberdefenders.org/blueteam-ctf-challenges/maldoc101/', platform: 'CyberDefenders' }],
    };
    const recommendations = gaps.map(g => ({ skill: g.skill, score: g.score, gap: 70 - g.score, training: TRAINING_MAP[g.skill] || [{ module: 'Custom training needed', url: '', platform: 'Contact Team Lead' }] }));
    return { status: 'active', message: `${gaps.length} skill gap${gaps.length !== 1 ? 's' : ''} identified. Training recommendations below.`, recommendations };
  }
}

module.exports = { AiBurnoutEngine };
