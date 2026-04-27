// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Training Certificates Routes
// NO outbound internet connections for training access.
// Instead: track training recommendations, accept certificate uploads
// or verification codes as proof of completion, signal growth to leads.
//
// GET  /api/training/recommendations    — analyst's gap-driven training list
// POST /api/training/certificates       — upload/submit certificate proof
// GET  /api/training/certificates       — list submitted certificates
// PUT  /api/training/certificates/:id/verify — lead verifies a certificate
// GET  /api/training/completions        — lead views team completions
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// Max certificate data size (base64 encoded): 5MB
const MAX_CERT_SIZE = 5 * 1024 * 1024;

// Training platform reference data (NO URLs — just names and descriptions)
const TRAINING_PLATFORMS = [
  { id: 'letsdefend', name: 'LetsDefend', desc: 'SOC analyst simulation platform. Search for courses on their website.' },
  { id: 'htb', name: 'Hack The Box', desc: 'Penetration testing labs and challenges. Search Academy courses.' },
  { id: 'thm', name: 'TryHackMe', desc: 'Guided cybersecurity learning paths. Search their rooms catalog.' },
  { id: 'cyberdefenders', name: 'CyberDefenders', desc: 'Blue team CTF challenges. Search their challenge library.' },
  { id: 'sans', name: 'SANS Institute', desc: 'Professional cybersecurity courses. Contact your lead for enrollment.' },
  { id: 'immersive', name: 'Immersive Labs', desc: 'Hands-on cyber skills platform. Access through your org portal.' },
  { id: 'internal', name: 'Internal Training', desc: 'Organization-specific training materials.' },
];

// ── Training Recommendations (for analyst) ───────────────────────────────────
router.get('/recommendations', async (req, res) => {
  try {
    const db = getDb();

    // Get analyst's skill gaps from assessment results
    const gaps = db.prepare(`
      SELECT ar.skill_id, ar.score,
             COALESCE(ask.custom_name, ar.skill_id) AS skill_name
      FROM assessment_results ar
      LEFT JOIN assessment_skills ask ON ask.assessment_id = ar.assessment_id AND ask.skill_id = ar.skill_id
      WHERE ar.analyst_id = ? AND ar.score < 70
      AND ar.completed_at = (
        SELECT MAX(ar2.completed_at) FROM assessment_results ar2
        WHERE ar2.analyst_id = ar.analyst_id AND ar2.skill_id = ar.skill_id
      )
      ORDER BY ar.score ASC
    `).all(req.user.id);

    // Already completed certifications
    const completed = db.prepare(`
      SELECT skill_id FROM team_config
      WHERE key LIKE 'cert_${req.user.id}_%'
    `).all();
    const completedSkills = new Set(completed.map(c => {
      try { return JSON.parse(c.value)?.skillId; } catch { return null; }
    }).filter(Boolean));

    // Build recommendations — platform name + what to search for, NO URLs
    const recommendations = gaps
      .filter(g => !completedSkills.has(g.skill_id))
      .map(g => ({
        skillId: g.skill_id,
        skillName: g.skill_name,
        currentScore: g.score,
        gap: 70 - g.score,
        platforms: TRAINING_PLATFORMS.map(p => ({
          id: p.id,
          name: p.name,
          searchTerm: `${g.skill_name} training`,
          description: p.desc,
        })),
      }));

    db.close();
    res.json({
      recommendations,
      note: 'For security, FireAlive does not link to external training sites. Use the platform names and search terms above to find courses directly. Submit your completion certificate or verification code below.',
    });
  } catch (err) {
    logger.error('Training recommendations error', { error: err.message });
    res.status(500).json({ error: 'Failed to get recommendations' });
  }
});

// ── Submit Certificate/Verification Code ─────────────────────────────────────
router.post('/certificates', (req, res) => {
  const { skillId, platformId, verificationCode, certificateData, courseName } = req.body;

  if (!skillId || !platformId) {
    return res.status(400).json({ error: 'skillId and platformId required' });
  }
  if (!verificationCode && !certificateData) {
    return res.status(400).json({ error: 'Either verificationCode or certificateData required' });
  }

  // Validate certificate data size
  if (certificateData && certificateData.length > MAX_CERT_SIZE) {
    return res.status(400).json({ error: `Certificate data too large (max ${MAX_CERT_SIZE / 1024 / 1024}MB)` });
  }

  // Block executable content in certificate uploads
  if (certificateData) {
    const header = certificateData.slice(0, 50).toLowerCase();
    if (header.includes('tvqq') || header.includes('elf') || header.includes('<script') || header.includes('#!/')) {
      logger.warn('Blocked executable upload', { userId: req.user.id, skillId });
      return res.status(400).json({ error: 'Executable content not allowed in certificate uploads' });
    }
  }

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');

    const cert = {
      id,
      analystId: req.user.id,
      skillId: skillId.slice(0, 100),
      platformId: platformId.slice(0, 50),
      courseName: courseName?.slice(0, 256) || null,
      verificationCode: verificationCode?.slice(0, 256) || null,
      hasCertificateFile: !!certificateData,
      status: 'pending', // pending → verified | rejected
      submittedAt: new Date().toISOString(),
      verifiedAt: null,
      verifiedBy: null,
    };

    // Store certificate metadata
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `cert_${req.user.id}_${id}`, JSON.stringify(cert), req.user.id
    );

    // Store certificate file data separately (encrypted) if provided
    if (certificateData) {
      const { encryptTier3 } = require('../services/encryption');
      const encrypted = encryptTier3(certificateData);
      db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
        `certfile_${id}`, encrypted.toString('base64'), req.user.id
      );
    }

    db.close();
    auditLog(req.user.id, 'CERT_SUBMITTED', `skill=${skillId} platform=${platformId}`, req.ip);
    res.status(201).json({ id, status: 'pending' });
  } catch (err) {
    logger.error('Submit certificate error', { error: err.message });
    res.status(500).json({ error: 'Failed to submit certificate' });
  }
});

// ── List My Certificates ─────────────────────────────────────────────────────
router.get('/certificates', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE ?").all(`cert_${req.user.id}_%`);
    db.close();

    const certs = rows
      .map(r => { try { return JSON.parse(r.value); } catch { return null; } })
      .filter(Boolean)
      .sort((a, b) => b.submittedAt.localeCompare(a.submittedAt));

    res.json({ certificates: certs });
  } catch (err) {
    logger.error('List certificates error', { error: err.message });
    res.status(500).json({ error: 'Failed to list certificates' });
  }
});

// ── Lead: Verify Certificate ─────────────────────────────────────────────────
router.put('/certificates/:id/verify', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can verify certificates' });

  const { approved, notes } = req.body;

  try {
    const db = getDb();

    // Find the certificate across all analysts
    const rows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE ?").all(`cert_%_${req.params.id}`);
    if (rows.length === 0) { db.close(); return res.status(404).json({ error: 'Certificate not found' }); }

    const row = rows[0];
    const cert = JSON.parse(row.value);

    cert.status = approved ? 'verified' : 'rejected';
    cert.verifiedAt = new Date().toISOString();
    cert.verifiedBy = req.user.id;
    cert.verificationNotes = notes?.slice(0, 500) || null;

    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(cert), row.key);
    db.close();

    auditLog(req.user.id, approved ? 'CERT_VERIFIED' : 'CERT_REJECTED',
      `analyst=${cert.analystId} skill=${cert.skillId}`, req.ip);

    res.json({ ok: true, status: cert.status });
  } catch (err) {
    logger.error('Verify certificate error', { error: err.message });
    res.status(500).json({ error: 'Failed to verify certificate' });
  }
});

// ── Lead: View Team Completions ──────────────────────────────────────────────
router.get('/completions', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can view team completions' });

  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'cert_%' AND key NOT LIKE 'certfile_%'").all();

    const certs = rows
      .map(r => { try { return JSON.parse(r.value); } catch { return null; } })
      .filter(Boolean);

    // Group by analyst with names
    const byAnalyst = {};
    for (const c of certs) {
      if (!byAnalyst[c.analystId]) {
        const user = db.prepare('SELECT name, tier FROM users WHERE id = ?').get(c.analystId);
        byAnalyst[c.analystId] = { name: user?.name, tier: user?.tier, certs: [] };
      }
      byAnalyst[c.analystId].certs.push({
        id: c.id, skillId: c.skillId, platformId: c.platformId,
        courseName: c.courseName, status: c.status, submittedAt: c.submittedAt,
      });
    }

    db.close();

    const pending = certs.filter(c => c.status === 'pending').length;
    res.json({ completions: byAnalyst, totalCerts: certs.length, pendingReview: pending });
  } catch (err) {
    logger.error('Team completions error', { error: err.message });
    res.status(500).json({ error: 'Failed to get completions' });
  }
});

module.exports = router;
