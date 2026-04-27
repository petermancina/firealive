const crypto = require('crypto');

class AssessmentService {
  constructor(db) { this.db = db; this._initTables(); }
  _initTables() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS assessments (
      id TEXT PRIMARY KEY, category TEXT, platform TEXT,
      target_analyst TEXT, status TEXT DEFAULT 'pending',
      score REAL, created_at TEXT, completed_at TEXT
    )`).run();
    this.db.prepare(`CREATE TABLE IF NOT EXISTS analyst_skills (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analyst_id TEXT, skill TEXT, score REAL, source TEXT,
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(analyst_id, skill)
    )`).run();
    this.db.prepare(`CREATE TABLE IF NOT EXISTS ir_policies (
      id TEXT PRIMARY KEY, name TEXT, content TEXT,
      uploaded_by TEXT, uploaded_at TEXT
    )`).run();
  }
  create(category, platform, targetAnalyst, createdBy) {
    const id = crypto.randomUUID();
    this.db.prepare("INSERT INTO assessments (id, category, platform, target_analyst, status, created_at) VALUES (?, ?, ?, ?, 'sent', ?)").run(id, category, platform, targetAnalyst, new Date().toISOString());
    return { id, status: 'sent' };
  }
  submitResults(assessmentId, score) {
    this.db.prepare("UPDATE assessments SET status='completed', score=?, completed_at=? WHERE id=?").run(score, new Date().toISOString(), assessmentId);
    const assessment = this.db.prepare("SELECT * FROM assessments WHERE id=?").get(assessmentId);
    if (assessment) {
      this.db.prepare("INSERT OR REPLACE INTO analyst_skills (analyst_id, skill, score, source, updated_at) VALUES (?, ?, ?, 'assessment', datetime('now'))").run(assessment.target_analyst, assessment.category, score);
    }
    return { success: true, gapAnalysisTriggered: true };
  }
  getForAnalyst(analystId) { return this.db.prepare("SELECT * FROM assessments WHERE target_analyst = ? ORDER BY created_at DESC").all(analystId); }
  getSkills(analystId) { return this.db.prepare("SELECT * FROM analyst_skills WHERE analyst_id = ? ORDER BY score ASC").all(analystId); }
  getAll() { return this.db.prepare("SELECT * FROM assessments ORDER BY created_at DESC").all(); }
}
module.exports = { AssessmentService };
