// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduler Service
// Handles: scheduled reports, backup automation, signal aggregation,
// lighter queue expiry, SLA measurement
// ═══════════════════════════════════════════════════════════════════════════════

const cron = require('node-cron');
const { logger } = require('./logger');

const schedulerService = {
  jobs: [],

  start() {
    // ── Expire lighter queue requests ────────────────────────────────────
    this.jobs.push(cron.schedule('*/5 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const db = getDb();
        const expired = db.prepare(
          'UPDATE lighter_queue_requests SET status = ? WHERE status = ? AND expires_at < datetime("now")'
        ).run('expired', 'active');
        if (expired.changes > 0) {
          logger.info(`Expired ${expired.changes} lighter queue request(s)`);
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: lighter queue expiry failed', { error: err.message });
      }
    }));

    // ── Scheduled report generation ──────────────────────────────────────
    this.jobs.push(cron.schedule('0 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const db = getDb();
        const config = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
        if (!config) { db.close(); return; }

        const now = new Date();
        const dayNames = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
        const currentDay = dayNames[now.getDay()];
        const currentHour = now.getHours().toString().padStart(2, '0') + ':00';

        if (config.schedule === 'daily' && currentHour === config.time_of_day) {
          generateReport(db, config, 'scheduled');
        } else if (config.schedule === 'weekly' && currentDay === config.day_of_week && currentHour === config.time_of_day) {
          generateReport(db, config, 'scheduled');
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: report generation failed', { error: err.message });
      }
    }));

    // ── Automated backup ─────────────────────────────────────────────────
    const backupSchedule = process.env.BACKUP_SCHEDULE || '0 2 * * *';
    this.jobs.push(cron.schedule(backupSchedule, () => {
      try {
        logger.info('Starting scheduled backup');
        // Backup logic will be in backup route/service
        const { performBackup } = require('./backup');
        performBackup('daily-auto');
      } catch (err) {
        logger.error('Scheduler: backup failed', { error: err.message });
      }
    }));

    logger.info(`Scheduler started with ${this.jobs.length} jobs`);
  },

  stop() {
    this.jobs.forEach(j => j.stop());
    this.jobs = [];
    logger.info('Scheduler stopped');
  }
};

function generateReport(db, config, type) {
  const crypto = require('crypto');
  const sections = JSON.parse(config.sections || '{}');
  const analysts = db.prepare('SELECT * FROM users WHERE role = ?').all('analyst');

  const report = {
    generated: new Date().toISOString(),
    platform: 'FireAlive v0.0.18',
    type,
    depersonalized: true,
    sections: {},
  };

  if (sections.teamHealth) {
    report.sections.teamHealth = {
      totalAnalysts: analysts.length,
      byShift: { day: analysts.filter(a => a.shift === 'day').length, swing: analysts.filter(a => a.shift === 'swing').length, night: analysts.filter(a => a.shift === 'night').length },
    };
  }
  if (sections.tierBreakdown) {
    report.sections.tierBreakdown = {
      l1: analysts.filter(a => a.tier === 1).length,
      l2: analysts.filter(a => a.tier === 2).length,
      l3: analysts.filter(a => a.tier === 3).length,
    };
  }

  const content = JSON.stringify(report, null, 2);
  db.prepare('INSERT INTO reports (type, format, content, sections_count) VALUES (?, ?, ?, ?)')
    .run(type, config.format, Buffer.from(content), Object.keys(report.sections).length);

  logger.info(`Report generated: ${type}, ${Object.keys(report.sections).length} sections`);
}

module.exports = { schedulerService };
