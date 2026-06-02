// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Database Seed (demo data for testing)
// ═══════════════════════════════════════════════════════════════════════════════

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

const { getDb, initDb } = require('./init');
const { appendAuditEntry } = require('../services/audit-chain');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

async function seed() {
  initDb();
  const db = getDb();

  const hash = (pw) => bcrypt.hashSync(pw, 10);
  const id = () => crypto.randomBytes(16).toString('hex');

  // ── Admin user ─────────────────────────────────────────────────────────
  const adminId = id();
  db.prepare(`INSERT OR IGNORE INTO users (id, username, password_hash, role, name) VALUES (?, ?, ?, ?, ?)`)
    .run(adminId, 'admin', hash('admin'), 'admin', 'System Admin');

  // ── Team Lead ──────────────────────────────────────────────────────────
  const leadId = id();
  db.prepare(`INSERT OR IGNORE INTO users (id, username, password_hash, role, name, tier, shift) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(leadId, 'lead', hash('lead'), 'lead', 'Team Lead', 3, 'day');

  // ── Analysts (matches frontend demo data) ──────────────────────────────
  const analysts = [
    { name: 'Maya C.', user: 'maya', tier: 2, shift: 'day' },
    { name: 'Jordan P.', user: 'jordan', tier: 1, shift: 'day' },
    { name: 'Sam R.', user: 'sam', tier: 3, shift: 'day' },
    { name: 'Alex K.', user: 'alex', tier: 1, shift: 'day' },
    { name: 'Dana O.', user: 'dana', tier: 2, shift: 'day' },
    { name: 'Priya S.', user: 'priya', tier: 1, shift: 'day' },
    { name: 'Carlos M.', user: 'carlos', tier: 3, shift: 'swing' },
    { name: 'Li W.', user: 'li', tier: 2, shift: 'swing' },
    { name: 'Aisha B.', user: 'aisha', tier: 1, shift: 'swing' },
    { name: 'Tom H.', user: 'tom', tier: 1, shift: 'swing' },
    { name: 'Nina V.', user: 'nina', tier: 2, shift: 'swing' },
    { name: 'Jake F.', user: 'jake', tier: 1, shift: 'swing' },
    { name: 'Kenji T.', user: 'kenji', tier: 3, shift: 'night' },
    { name: 'Rosa D.', user: 'rosa', tier: 2, shift: 'night' },
    { name: 'Marcus J.', user: 'marcus', tier: 1, shift: 'night' },
    { name: 'Elena P.', user: 'elena', tier: 1, shift: 'night' },
    { name: 'Ben S.', user: 'ben', tier: 2, shift: 'night' },
    { name: 'Fatima A.', user: 'fatima', tier: 1, shift: 'night' },
  ];

  const insertAnalyst = db.prepare(
    `INSERT OR IGNORE INTO users (id, username, password_hash, role, name, tier, shift) VALUES (?, ?, ?, ?, ?, ?, ?)`
  );

  const insertCap = db.prepare(
    `INSERT OR IGNORE INTO routing_caps (analyst_id, max_complexity) VALUES (?, ?)`
  );

  const analystIds = {};
  for (const a of analysts) {
    const aid = id();
    analystIds[a.user] = aid;
    insertAnalyst.run(aid, a.user, hash(a.user), 'analyst', a.name, a.tier, a.shift);
    insertCap.run(aid, a.tier === 3 ? 5 : a.tier === 2 ? 3 : 2);
  }

  // ── Automation Systems ─────────────────────────────────────────────────
  const insertAuto = db.prepare(
    `INSERT OR IGNORE INTO automation_systems (id, name, type, handles_l1, handles_l2, handles_l3, max_capacity, capacity_unit, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insertAuto.run(id(), 'CrowdStrike Falcon', 'EDR/XDR', 1, 1, 0, 800, 'alerts/hr', 'operational');
  insertAuto.run(id(), 'Palo Alto IDS/IPS', 'IDS/IPS', 1, 0, 0, 2000, 'events/hr', 'operational');
  insertAuto.run(id(), 'Torq AI Triage', 'AI/SOAR', 1, 1, 0, 500, 'tickets/hr', 'operational');
  insertAuto.run(id(), 'Abnormal Security', 'Email AI', 1, 0, 0, 1200, 'emails/hr', 'operational');

  // ── Seed audit log ─────────────────────────────────────────────────────
  // Chained append (audit_log hash chain) so the seed's SYSTEM_INIT row links
  // to the chain instead of writing a NULL hash. initDb() above has already
  // established the chain and installed the append-only triggers.
  appendAuditEntry(db, {
    userId: adminId,
    eventType: 'SYSTEM_INIT',
    detail: 'Database seeded with demo data',
  });

  console.log('Seed complete:', analysts.length, 'analysts, 1 lead, 1 admin, 4 automation systems');
  db.close();
}

seed().catch(err => { console.error('Seed failed:', err); process.exit(1); });
