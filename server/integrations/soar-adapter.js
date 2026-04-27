// FireAlive v1.0.0 — SOAR Platform Adapters
// Implements actual API protocols for each SOAR platform
const https = require('https');
const http = require('http');

class SoarAdapter {
  constructor(platform, endpoint, apiKey) {
    this.platform = platform;
    this.endpoint = endpoint;
    this.apiKey = apiKey;
  }

  async distributeTicket(ticketId, analystPseudonym, priority, reason) {
    const payload = this._formatPayload(ticketId, analystPseudonym, priority, reason);
    return this._send(payload);
  }

  _formatPayload(ticketId, analyst, priority, reason) {
    switch (this.platform) {
      case 'splunk_soar':
        return { action: 'assign_ticket', container_id: ticketId, parameters: { assignee: analyst, priority, comment: `FireAlive routing: ${reason}` } };
      case 'xsoar':
        return { method: 'updateIncident', body: { id: ticketId, owner: analyst, severity: priority === 'P1' ? 4 : priority === 'P2' ? 3 : 2, comment: `FireAlive: ${reason}` } };
      case 'qradar_soar':
        return { type: 'task', incident_id: ticketId, assignee: analyst, priority: priority === 'P1' ? 'High' : 'Medium', note: reason };
      case 'tines':
        return { story_id: ticketId, action: 'assign', agent: analyst, metadata: { source: 'firealive', reason } };
      case 'torq':
        return { workflow_id: 'ticket_assign', inputs: { ticket: ticketId, analyst, priority, source: 'firealive-routing' } };
      case 'swimlane':
        return { application: 'incident-management', record: ticketId, fields: { assignee: analyst, priority, notes: reason } };
      default:
        return { ticket_id: ticketId, assignee: analyst, priority, reason, source: 'firealive' };
    }
  }

  _getPath() {
    switch (this.platform) {
      case 'splunk_soar': return '/rest/action_run';
      case 'xsoar': return '/incident';
      case 'qradar_soar': return '/api/v2/tasks';
      case 'tines': return '/api/v1/stories/trigger';
      case 'torq': return '/api/v1/workflows/run';
      case 'swimlane': return '/api/records';
      default: return '/api/assign';
    }
  }

  _getAuthHeader() {
    switch (this.platform) {
      case 'splunk_soar': return { 'ph-auth-token': this.apiKey };
      case 'xsoar': return { 'Authorization': this.apiKey };
      case 'qradar_soar': return { 'SEC': this.apiKey };
      default: return { 'Authorization': 'Bearer ' + this.apiKey };
    }
  }

  async _send(payload) {
    return new Promise((resolve, reject) => {
      try {
        const url = new URL(this.endpoint + this._getPath());
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request({
          hostname: url.hostname, port: url.port, path: url.pathname,
          method: 'POST', timeout: 10000,
          headers: { 'Content-Type': 'application/json', ...this._getAuthHeader() }
        }, (res) => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
            catch { resolve({ status: res.statusCode, body: data }); }
          });
        });
        req.on('error', e => resolve({ status: 0, error: e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'Timeout' }); });
        req.write(JSON.stringify(payload));
        req.end();
      } catch (e) { resolve({ status: 0, error: e.message }); }
    });
  }
}

module.exports = { SoarAdapter };
