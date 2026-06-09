// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Query Tools
// 1. SIEM Query Generator — builds copy-pasteable queries for configured SIEM
// 2. Internal Query Tool — regex search over app data for orgs without SIEM
//
// GET  /api/query/siem/generate   — generate SIEM query
// POST /api/query/internal        — run internal query
// GET  /api/query/siem/templates  — available query templates
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// ── SIEM Query Templates ─────────────────────────────────────────────────────
const QUERY_TEMPLATES = [
  { id: 'team_health', name: 'Team Health Overview', fields: ['risk_tier', 'timestamp'], desc: 'Current team health distribution' },
  { id: 'burnout_trend', name: 'Burnout Trend', fields: ['risk_tier', 'timestamp', 'date_range'], desc: 'Risk tier changes over time' },
  { id: 'sla_performance', name: 'SLA Performance', fields: ['priority', 'mtta', 'mttr', 'date_range'], desc: 'MTTA/MTTR by priority' },
  { id: 'routing_equity', name: 'Routing Equity', fields: ['analyst_tier', 'complexity', 'count'], desc: 'Alert distribution by tier' },
  { id: 'automation_rate', name: 'Automation Rate', fields: ['system', 'status', 'capacity'], desc: 'Automation system performance' },
  { id: 'skill_gaps', name: 'Skill Gap Summary', fields: ['tier', 'skill', 'avg_score'], desc: 'Skills below threshold by tier' },
  { id: 'peer_support', name: 'Peer Support Activity', fields: ['sessions', 'ratings', 'date_range'], desc: 'Peer chat session metrics' },
  { id: 'audit_events', name: 'Audit Events', fields: ['event_type', 'timestamp', 'user'], desc: 'Filtered audit trail' },
];

// ── Generate SIEM Query ──────────────────────────────────────────────────────
router.get('/siem/generate', (req, res) => {
  const { templateId, siemType, dateFrom, dateTo, filters } = req.query;

  if (!templateId) return res.status(400).json({ error: 'templateId required', templates: QUERY_TEMPLATES.map(t => t.id) });

  const template = QUERY_TEMPLATES.find(t => t.id === templateId);
  if (!template) return res.status(404).json({ error: 'Template not found' });

  const siem = siemType || 'splunk'; // default
  const from = dateFrom || 'now-7d';
  const to = dateTo || 'now';
  const parsedFilters = filters ? JSON.parse(filters) : {};

  let query;
  switch (siem) {
    case 'splunk':
      query = generateSplunkQuery(template, from, to, parsedFilters);
      break;
    case 'qradar':
      query = generateQRadarQuery(template, from, to, parsedFilters);
      break;
    case 'elastic':
      query = generateElasticQuery(template, from, to, parsedFilters);
      break;
    case 'sentinel':
      query = generateSentinelQuery(template, from, to, parsedFilters);
      break;
    default:
      query = generateSplunkQuery(template, from, to, parsedFilters); // fallback
  }

  res.json({ siem, templateId, query, copyReady: true });
});

router.get('/siem/templates', (req, res) => {
  res.json({ templates: QUERY_TEMPLATES, supportedSiems: ['splunk', 'qradar', 'elastic', 'sentinel'] });
});

// ── Internal Query Tool ──────────────────────────────────────────────────────
router.post('/internal', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can run queries' });

  const { dataSource, dateFrom, dateTo, textFilter, regexFilter, limit = 100 } = req.body;

  const validSources = ['audit_log', 'sla_measurements', 'reports', 'assessment_results'];
  if (!validSources.includes(dataSource)) {
    return res.status(400).json({ error: `Invalid dataSource. Valid: ${validSources.join(', ')}` });
  }

  try {
    const db = getDb();
    let sql = `SELECT * FROM ${dataSource} WHERE 1=1`;
    const params = [];

    // Date filtering
    const dateCol = dataSource === 'audit_log' ? 'timestamp' : dataSource === 'sla_measurements' ? 'measured_at' : dataSource === 'reports' ? 'generated_at' : 'completed_at';
    if (dateFrom) { sql += ` AND ${dateCol} >= ?`; params.push(dateFrom); }
    if (dateTo) { sql += ` AND ${dateCol} <= ?`; params.push(dateTo); }

    sql += ` ORDER BY ${dateCol} DESC LIMIT ?`;
    params.push(Math.min(parseInt(limit, 10) || 100, 1000));

    let rows = db.prepare(sql).all(...params);
    db.close();

    // Apply a literal, case-insensitive text filter client-side (SQLite
    // has no native regex). The value is matched as a plain substring
    // against each row's JSON and is never compiled into a RegExp, so a
    // user-controlled pattern cannot cause regex injection or catastrophic
    // backtracking (ReDoS). textFilter is the field name; regexFilter is
    // accepted as a backward-compatible alias.
    const filterText = (textFilter !== undefined && textFilter !== '') ? textFilter : regexFilter;
    if (filterText) {
      const needle = String(filterText).toLowerCase();
      rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(needle));
    }

    res.json({ dataSource, resultCount: rows.length, results: rows });
  } catch (err) {
    logger.error('Internal query error', { error: err.message });
    res.status(500).json({ error: 'Failed to run query' });
  }
});

// ── SIEM-Specific Query Generators ───────────────────────────────────────────

function generateSplunkQuery(template, from, to, filters) {
  const base = `index=firealive sourcetype=firealive:${template.id}`;
  const timeRange = `earliest="${from}" latest="${to}"`;
  const filterStr = Object.entries(filters).map(([k, v]) => `${k}="${v}"`).join(' ');

  switch (template.id) {
    case 'team_health':
      return `${base} ${timeRange} ${filterStr}\n| stats count by risk_tier\n| sort -count`;
    case 'burnout_trend':
      return `${base} ${timeRange} ${filterStr}\n| timechart span=1d count by risk_tier`;
    case 'sla_performance':
      return `${base} ${timeRange} ${filterStr}\n| stats avg(mtta_seconds) as avg_mtta, avg(mttr_seconds) as avg_mttr, count by priority\n| eval avg_mtta_min=round(avg_mtta/60,1), avg_mttr_min=round(avg_mttr/60,1)`;
    case 'routing_equity':
      return `${base} ${timeRange} ${filterStr}\n| stats count by analyst_tier, complexity\n| eventstats sum(count) as total\n| eval pct=round(count/total*100,1)`;
    case 'audit_events':
      return `${base} ${timeRange} ${filterStr}\n| table _time, event_type, user_name, detail, ip_address\n| sort -_time`;
    default:
      return `${base} ${timeRange} ${filterStr}\n| table *`;
  }
}

function generateQRadarQuery(template, from, to, filters) {
  const filterStr = Object.entries(filters).map(([k, v]) => `AND "${k}" = '${v}'`).join(' ');
  switch (template.id) {
    case 'team_health':
      return `SELECT risk_tier, COUNT(*) as count FROM events WHERE LOGSOURCENAME(logsourceid) = 'FireAlive' ${filterStr} GROUP BY risk_tier LAST ${from === 'now-7d' ? '7' : '30'} DAYS`;
    case 'sla_performance':
      return `SELECT priority, AVG(mtta_seconds)/60 as avg_mtta_min, AVG(mttr_seconds)/60 as avg_mttr_min, COUNT(*) FROM events WHERE LOGSOURCENAME(logsourceid) = 'FireAlive' AND category = 'SLA' ${filterStr} GROUP BY priority LAST ${from === 'now-7d' ? '7' : '30'} DAYS`;
    default:
      return `SELECT * FROM events WHERE LOGSOURCENAME(logsourceid) = 'FireAlive' ${filterStr} ORDER BY starttime DESC LIMIT 100`;
  }
}

function generateElasticQuery(template, from, to, filters) {
  const must = Object.entries(filters).map(([k, v]) => `{ "match": { "${k}": "${v}" } }`);
  return `GET firealive-*/_search\n{\n  "query": {\n    "bool": {\n      "must": [\n        { "range": { "@timestamp": { "gte": "${from}", "lte": "${to}" } } }${must.length ? ',\n        ' + must.join(',\n        ') : ''}\n      ]\n    }\n  },\n  "size": 100,\n  "sort": [{ "@timestamp": "desc" }]\n}`;
}

function generateSentinelQuery(template, from, to, filters) {
  const filterStr = Object.entries(filters).map(([k, v]) => `| where ${k} == "${v}"`).join('\n');
  const timeRange = from === 'now-7d' ? '7d' : '30d';
  switch (template.id) {
    case 'team_health':
      return `FireAlive_CL\n| where TimeGenerated > ago(${timeRange})\n${filterStr}\n| summarize count() by risk_tier\n| sort by count_ desc`;
    case 'sla_performance':
      return `FireAlive_CL\n| where TimeGenerated > ago(${timeRange})\n| where Category == "SLA"\n${filterStr}\n| summarize avg(mtta_seconds), avg(mttr_seconds), count() by priority`;
    default:
      return `FireAlive_CL\n| where TimeGenerated > ago(${timeRange})\n${filterStr}\n| take 100\n| sort by TimeGenerated desc`;
  }
}

module.exports = router;
