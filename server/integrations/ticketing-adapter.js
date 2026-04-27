// FireAlive v1.0.0 — Ticketing Platform Adapters (READ-ONLY)
const https = require('https');
const http = require('http');

class TicketingAdapter {
  constructor(platform, endpoint, apiKey) {
    this.platform = platform;
    this.endpoint = endpoint;
    this.apiKey = apiKey;
  }

  async getQueueMetadata() {
    const path = this._getQueuePath();
    return this._fetch(path);
  }

  async getTicketDetails(ticketId) {
    const path = this._getTicketPath(ticketId);
    return this._fetch(path);
  }

  _getQueuePath() {
    switch (this.platform) {
      case 'servicenow': return '/api/now/table/incident?sysparm_query=active=true&sysparm_fields=number,priority,category,assigned_to&sysparm_limit=50';
      case 'jira': return '/rest/api/2/search?jql=status!=Done&maxResults=50&fields=priority,assignee,summary';
      case 'zendesk': return '/api/v2/views/active.json';
      case 'pagerduty': return '/incidents?statuses[]=triggered&statuses[]=acknowledged';
      case 'freshservice': return '/api/v2/tickets?filter=open';
      default: return '/api/tickets?status=open';
    }
  }

  _getTicketPath(id) {
    switch (this.platform) {
      case 'servicenow': return `/api/now/table/incident/${id}`;
      case 'jira': return `/rest/api/2/issue/${id}`;
      case 'zendesk': return `/api/v2/tickets/${id}.json`;
      case 'pagerduty': return `/incidents/${id}`;
      case 'freshservice': return `/api/v2/tickets/${id}`;
      default: return `/api/tickets/${id}`;
    }
  }

  _getAuthHeader() {
    switch (this.platform) {
      case 'servicenow': return { 'Authorization': 'Basic ' + Buffer.from(this.apiKey).toString('base64') };
      case 'jira': return { 'Authorization': 'Basic ' + Buffer.from(this.apiKey).toString('base64') };
      case 'pagerduty': return { 'Authorization': 'Token token=' + this.apiKey };
      default: return { 'Authorization': 'Bearer ' + this.apiKey };
    }
  }

  async _fetch(path) {
    return new Promise((resolve) => {
      try {
        const url = new URL(this.endpoint + path);
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request({
          hostname: url.hostname, port: url.port, path: url.pathname + (url.search || ''),
          method: 'GET', timeout: 10000,
          headers: { 'Accept': 'application/json', ...this._getAuthHeader() }
        }, (res) => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
            catch { resolve({ status: res.statusCode, data }); }
          });
        });
        req.on('error', e => resolve({ status: 0, error: e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'Timeout' }); });
        req.end();
      } catch (e) { resolve({ status: 0, error: e.message }); }
    });
  }
}

module.exports = { TicketingAdapter };
