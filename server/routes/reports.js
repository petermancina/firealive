// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Reports Routes
// GET  /api/reports           — list generated reports
// POST /api/reports/generate  — generate on-demand report
// GET  /api/reports/config    — get report schedule config
// PUT  /api/reports/config    — update report schedule config
// GET  /api/reports/:id       — get specific report content
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { version } = require('../lib/version');
const { buildReportPdf, buildReportDocx } = require('../services/report-doc-builder');
const { signReport, getInstanceLabel } = require('../services/report-signer');

// ── Report model transform (structured sections -> doc-builder model) ────────
function humanize(key) {
  return String(key)
    .replace(/_/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^./, (c) => c.toUpperCase());
}
function fmtVal(v) {
  if (typeof v === 'number' && !Number.isInteger(v)) return v.toFixed(2);
  return String(v);
}
// Flatten one section's structured value into readable bullet lines. Scalars
// become "Label: value"; arrays of rows become one indented bullet per row;
// nested objects flatten one level.
function flattenToBullets(obj) {
  const bullets = [];
  for (const [k, val] of Object.entries(obj || {})) {
    if (val === null || val === undefined) continue;
    if (Array.isArray(val)) {
      if (val.length === 0) { bullets.push(`${humanize(k)}: (none)`); continue; }
      bullets.push(`${humanize(k)}:`);
      for (const row of val) {
        if (row && typeof row === 'object') {
          bullets.push('  ' + Object.entries(row).map(([rk, rv]) => `${humanize(rk)}=${fmtVal(rv)}`).join(', '));
        } else {
          bullets.push('  ' + fmtVal(row));
        }
      }
    } else if (typeof val === 'object') {
      for (const [nk, nv] of Object.entries(val)) {
        bullets.push(`${humanize(k)} / ${humanize(nk)}: ${fmtVal(nv)}`);
      }
    } else {
      bullets.push(`${humanize(k)}: ${fmtVal(val)}`);
    }
  }
  return bullets;
}
// Build the doc-builder model from a generated report. A section's `citations`
// array (if present) is passed through VERBATIM and excluded from the bullet
// flattening -- the anti-hallucination invariant: KB-cited synthesis is
// rendered exactly as produced, never reformatted or invented.
function reportModel(report) {
  const sections = Object.entries(report.sections || {}).map(([key, val]) => {
    const sec = { heading: humanize(key) };
    let data = val;
    if (val && typeof val === 'object' && Array.isArray(val.citations)) {
      sec.citations = val.citations.slice();
      data = Object.fromEntries(Object.entries(val).filter(([k]) => k !== 'citations'));
    }
    sec.bullets = flattenToBullets(data);
    return sec;
  });
  return {
    title: 'FireAlive Management Report',
    subtitle: `Generated ${report.generatedAt}`,
    meta: [['Version', report.version], ['Generated', report.generatedAt], ['Sections', String(sections.length)]],
    sections,
  };
}

// ── List Reports ─────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const db = getDb();
    const reports = db.prepare(`
      SELECT id, type, format, sections_count, generated_at,
             (SELECT name FROM users WHERE id = reports.generated_by) AS generated_by_name,
             LENGTH(content) AS content_size
      FROM reports ORDER BY generated_at DESC LIMIT ?
    `).all(Math.min(parseInt(limit, 10) || 20, 100));
    db.close();
    res.json({ reports });
  } catch (err) {
    logger.error('List reports error', { error: err.message });
    res.status(500).json({ error: 'Failed to list reports' });
  }
});

// ── Get Report Content ───────────────────────────────────────────────────────
router.get('/:id', (req, res) => {
  try {
    const db = getDb();
    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
    db.close();

    if (!report) return res.status(404).json({ error: 'Report not found' });

    // Binary document formats stream the stored signed bytes as a download.
    if (report.format === 'pdf' || report.format === 'docx') {
      const ctype = report.format === 'pdf'
        ? 'application/pdf'
        : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      res.setHeader('Content-Type', ctype);
      res.setHeader('Content-Disposition', `attachment; filename=firealive-report-${report.id}.${report.format}`);
      return res.send(report.content);
    }

    const content = report.content.toString('utf-8');
    let parsed;
    try { parsed = JSON.parse(content); } catch { parsed = content; }

    res.json({ id: report.id, type: report.type, format: report.format, generatedAt: report.generated_at, content: parsed });
  } catch (err) {
    logger.error('Get report error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch report' });
  }
});

// ── Generate On-Demand Report ────────────────────────────────────────────────
router.post('/generate', async (req, res) => {
  try {
    const db = getDb();

    // Load config for which sections to include
    const configRow = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
    const sections = configRow?.sections ? JSON.parse(configRow.sections) : {};
    const format = req.body.format || configRow?.format || 'json';

    // ── Gather data ────────────────────────────────────────────────────────
    const report = { generatedAt: new Date().toISOString(), version, sections: {} };
    let sectionCount = 0;

    // Team Health (depersonalized)
    if (sections.teamHealth !== false) {
      const analysts = db.prepare("SELECT COUNT(*) AS total FROM users WHERE role = 'analyst'").get();
      const signals = db.prepare(`
        SELECT risk_tier, COUNT(*) AS count FROM analyst_signals
        WHERE recorded_at = (SELECT MAX(recorded_at) FROM analyst_signals AS sub WHERE sub.analyst_id = analyst_signals.analyst_id)
        GROUP BY risk_tier
      `).all();
      report.sections.teamHealth = { totalAnalysts: analysts.total, riskDistribution: signals };
      sectionCount++;
    }

    // Utilization
    if (sections.utilization !== false) {
      const caps = db.prepare(`
        SELECT u.tier, AVG(rc.max_complexity) AS avg_cap
        FROM routing_caps rc JOIN users u ON u.id = rc.analyst_id
        GROUP BY u.tier
      `).all();
      report.sections.utilization = { byTier: caps };
      sectionCount++;
    }

    // Tier Breakdown
    if (sections.tierBreakdown !== false) {
      const tiers = db.prepare("SELECT tier, COUNT(*) AS count FROM users WHERE role = 'analyst' GROUP BY tier").all();
      report.sections.tierBreakdown = { tiers };
      sectionCount++;
    }

    // Automation Rate
    if (sections.automationRate !== false) {
      const systems = db.prepare('SELECT name, type, status, max_capacity FROM automation_systems').all();
      const operational = systems.filter(s => s.status === 'operational');
      report.sections.automationRate = {
        totalSystems: systems.length,
        operational: operational.length,
        totalCapacity: operational.reduce((sum, s) => sum + s.max_capacity, 0),
        systems: systems.map(s => ({ name: s.name, type: s.type, status: s.status })),
      };
      sectionCount++;
    }

    // Trend Analysis (SLA over last 30 days)
    if (sections.trendAnalysis !== false) {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
      const slaData = db.prepare(`
        SELECT priority, AVG(mtta_seconds) AS avg_mtta, AVG(mttr_seconds) AS avg_mttr, COUNT(*) AS count
        FROM sla_measurements WHERE measured_at >= ?
        GROUP BY priority
      `).all(thirtyDaysAgo);
      report.sections.trendAnalysis = { period: '30d', sla: slaData };
      sectionCount++;
    }

    // KB Insights
    if (sections.kbInsights !== false) {
      report.sections.kbInsights = {
        note: 'KB contains 42 peer-reviewed entries across 15 topic categories. AI synthesis engine generates contextual prompts constrained to KB-only citations.',
      };
      sectionCount++;
    }

    // Skill Progression (depersonalized by cohort tier)
    if (sections.skillProgress !== false) {
      const skillData = db.prepare(`
        SELECT u.tier, ar.skill_id, AVG(ar.score) AS avg_score, COUNT(DISTINCT ar.analyst_id) AS analyst_count
        FROM assessment_results ar
        JOIN users u ON u.id = ar.analyst_id
        GROUP BY u.tier, ar.skill_id
        ORDER BY u.tier, ar.skill_id
      `).all();
      report.sections.skillProgress = { byTierAndSkill: skillData };
      sectionCount++;
    }

    // Upskilling Gaps (depersonalized)
    if (sections.upskillingGaps !== false) {
      const gaps = db.prepare(`
        SELECT u.tier, ar.skill_id, COUNT(*) AS analysts_below_threshold
        FROM assessment_results ar
        JOIN users u ON u.id = ar.analyst_id
        WHERE ar.score < 70
        AND ar.completed_at = (
          SELECT MAX(ar2.completed_at) FROM assessment_results ar2
          WHERE ar2.analyst_id = ar.analyst_id AND ar2.skill_id = ar.skill_id
        )
        GROUP BY u.tier, ar.skill_id
        HAVING analysts_below_threshold > 0
        ORDER BY analysts_below_threshold DESC
      `).all();
      report.sections.upskillingGaps = { gaps, threshold: 70 };
      sectionCount++;
    }

    // Store report
    const id = crypto.randomBytes(16).toString('hex');

    let content;
    let verification = null;
    if (format === 'pdf' || format === 'docx') {
      // Render a signed, watermarked document and store its bytes. The footer
      // is bytes-mode (no hash printed); the signature is taken over the
      // rendered bytes, so the verify key is the file's own SHA-256.
      const model = reportModel(report);
      const keyRow = db.prepare("SELECT public_key_fingerprint FROM report_signing_keys WHERE is_active = 1 LIMIT 1").get();
      const footer = {
        instanceLabel: getInstanceLabel(db),
        keyFingerprint: keyRow ? keyRow.public_key_fingerprint : null,
        signedAt: new Date().toISOString(),
      };
      content = format === 'pdf'
        ? await buildReportPdf(model, footer)
        : await buildReportDocx(model, footer);
      verification = signReport({
        db,
        reportType: 'report_engine',
        subjectRef: id,
        material: content,
        metadata: { format, sections: sectionCount, app_version: report.version },
      });
    } else {
      content = Buffer.from(JSON.stringify(report, null, 2));
    }

    db.prepare('INSERT INTO reports (id, type, format, content, sections_count, generated_by) VALUES (?, ?, ?, ?, ?, ?)').run(
      id, 'on-demand', format, content, sectionCount, req.user.id
    );

    db.close();
    auditLog(req.user.id, 'REPORT_GENERATED', `type=on-demand format=${format} sections=${sectionCount}`, req.ip);
    res.status(201).json({
      id,
      sections: sectionCount,
      format,
      generatedAt: report.generatedAt,
      verificationId: verification ? verification.verificationId : null,
    });
  } catch (err) {
    logger.error('Generate report error', { error: err.message });
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// ── Report Config ────────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
    db.close();
    res.json(config || { schedule: 'weekly', day_of_week: 'monday', time_of_day: '08:00', format: 'json', sections: '{}' });
  } catch (err) {
    logger.error('Get report config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get report config' });
  }
});

router.put('/config', (req, res) => {
  const { schedule, dayOfWeek, timeOfDay, format, recipients, siemFeed, sections } = req.body;

  const validSchedules = ['daily', 'weekly', 'biweekly', 'monthly'];
  const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
  const validFormats = ['json', 'html', 'pdf', 'txt'];

  try {
    const db = getDb();
    db.prepare(`
      UPDATE report_config SET
        schedule = ?, day_of_week = ?, time_of_day = ?, format = ?,
        recipients = ?, siem_feed = ?, sections = ?, updated_by = ?, updated_at = datetime('now')
      WHERE id = 'default'
    `).run(
      validSchedules.includes(schedule) ? schedule : 'weekly',
      validDays.includes(dayOfWeek) ? dayOfWeek : 'monday',
      /^\d{2}:\d{2}$/.test(timeOfDay) ? timeOfDay : '08:00',
      validFormats.includes(format) ? format : 'json',
      (recipients || '').slice(0, 1024),
      siemFeed ? 1 : 0,
      typeof sections === 'object' ? JSON.stringify(sections) : '{}',
      req.user.id
    );
    db.close();
    auditLog(req.user.id, 'REPORT_CONFIG_UPDATED', `schedule=${schedule}`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Update report config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update report config' });
  }
});

module.exports = router;
