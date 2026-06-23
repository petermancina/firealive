// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — LDAP/Active Directory Integration Client (Phase B5b)
// Provides directory-backed presence checks, LDAP authentication, and user
// provisioning via LDAP/LDAPS.
//
// Built on `ldapts` (promise-based, actively maintained). The long-standing
// `ldapjs` package has been decommissioned by its author and is no longer
// maintained, so it is deliberately NOT used here.
//
// Capabilities:
//   - testConnection()        verify connectivity + service-account bind
//   - searchUsers(filter)      directory search (group/user filters)
//   - userExists(identifier)   directory-presence check for the offboarding
//                              detector — fail-SAFE (a directory error is never
//                              reported as "absent")
//   - authenticate(user, pw)   bind AS the user to verify credentials (the
//                              allow_password LDAP login path)
//   - syncUsers(db)            JIT provisioning / attribute sync
//
// Two roles in B5b: the always-available directory-presence source the
// offboarding detector reads, and LDAP-as-auth under the off-by-default
// allow_password exception. LDAPS (encrypted) is strongly preferred; an
// unencrypted ldap:// bind is allowed but logged as a warning.
// ═══════════════════════════════════════════════════════════════════════════════

const { Client, InvalidCredentialsError } = require('ldapts');
const { logger } = require('../services/logger');
const { handleForGuid } = require('../lib/identity-handle');

// ── Role Mapping from AD Groups ──────────────────────────────────────────────
const DEFAULT_GROUP_MAPPING = {
  'CN=SOC-Analysts,OU=Security,DC=corp': 'analyst',
  'CN=SOC-Leads,OU=Security,DC=corp': 'lead',
  'CN=IT-Admins,OU=IT,DC=corp': 'admin',
};

const SEARCH_ATTRS = ['sAMAccountName', 'userPrincipalName', 'displayName', 'cn', 'mail', 'memberOf', 'objectGUID', 'entryUUID', 'c'];
const OP_TIMEOUT_MS = 10000;

// RFC 4515 filter escaping — anything user-supplied that enters a search filter
// MUST pass through this to prevent LDAP filter injection.
function escapeFilterValue(s) {
  return String(s).replace(/[\\*()\u0000]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

// AD objectGUID is a 16-byte binary value; format it as the canonical GUID
// string (AD stores the first three groups little-endian). Falls back to a
// base64 rendering for non-16-byte values (e.g. an OpenLDAP entryUUID already
// arriving as a string is handled separately in _mapEntry).
function formatGuid(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== 16) {
    try { return Buffer.from(buf).toString('base64'); } catch (_) { return null; }
  }
  const h = buf.toString('hex');
  return [
    h.substr(6, 2) + h.substr(4, 2) + h.substr(2, 2) + h.substr(0, 2),
    h.substr(10, 2) + h.substr(8, 2),
    h.substr(14, 2) + h.substr(12, 2),
    h.substr(16, 4),
    h.substr(20, 12),
  ].join('-');
}

function firstValue(v) {
  if (Array.isArray(v)) return v.length ? v[0] : null;
  return v == null ? null : v;
}

// Normalize an LDAP country attribute (RFC 4519 countryName, attribute 'c') to
// a 2-letter ISO-3166-1 alpha-2 code in uppercase, or null when the directory
// has no usable value. Anything that is not exactly two letters is treated as
// absent rather than stored, so a malformed directory value never becomes a
// geo-fence.
function normalizeCountry(v) {
  const s = firstValue(v);
  if (!s) return null;
  const c = String(s).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(c) ? c : null;
}

class LdapClient {
  constructor(config) {
    this.config = config || {};
    this.url = this._buildUrl(this.config);
    this.baseDn = this.config.baseDn;
    this.bindDn = this.config.bindDn;
    this.bindPassword = this.config.bindPassword;
    this.groupFilter = this.config.groupFilter || '';
    this.userFilter = this.config.userFilter || '(&(objectClass=user)(objectCategory=person))';
    this.userIdAttr = this.config.userIdAttr || 'sAMAccountName';
    this.syncInterval = this.config.syncInterval || 3600; // seconds
    this.groupMapping = this.config.groupMapping || DEFAULT_GROUP_MAPPING;
    this.tlsOptions = {
      rejectUnauthorized: this.config.verifyCert !== false,
      ca: this.config.caCert || undefined,
    };
  }

  // Accept either a full URL in `server` (ldaps://host:port) or the MC form's
  // hostname + port + useTLS triple.
  _buildUrl(config) {
    const s = String(config.server || '').trim();
    if (/^ldaps?:\/\//i.test(s)) return s;
    const scheme = config.useTLS === false ? 'ldap' : 'ldaps';
    const port = config.port || (scheme === 'ldaps' ? 636 : 389);
    return `${scheme}://${s}:${port}`;
  }

  _newClient() {
    return new Client({
      url: this.url,
      timeout: OP_TIMEOUT_MS,
      connectTimeout: OP_TIMEOUT_MS,
      tlsOptions: this.tlsOptions,
    });
  }

  _isEncrypted() {
    return this.url.toLowerCase().startsWith('ldaps://');
  }

  _mapEntry(e) {
    let oid = null;
    if (e.objectGUID) oid = formatGuid(e.objectGUID);
    else if (e.entryUUID) oid = firstValue(e.entryUUID);
    return {
      dn: e.dn,
      sAMAccountName: firstValue(e.sAMAccountName),
      userPrincipalName: firstValue(e.userPrincipalName),
      displayName: firstValue(e.displayName) || firstValue(e.cn),
      mail: firstValue(e.mail),
      country: normalizeCountry(e.c),
      memberOf: Array.isArray(e.memberOf) ? e.memberOf : (e.memberOf ? [e.memberOf] : []),
      objectGUID: oid,
    };
  }

  // ── Test bind credentials and connectivity ──────────────────────────────────
  async testConnection() {
    if (!this.config.server) return { success: false, error: 'LDAP server URL required' };
    if (!this.baseDn) return { success: false, error: 'Base DN required' };
    if (!this.bindDn || !this.bindPassword) return { success: false, error: 'Bind credentials required' };

    const encrypted = this._isEncrypted();
    if (!encrypted) logger.warn('LDAP connection is not encrypted (use ldaps://)');

    const client = this._newClient();
    const t0 = Date.now();
    try {
      await client.bind(this.bindDn, this.bindPassword);
      return { success: true, server: this.url, baseDn: this.baseDn, encrypted, latencyMs: Date.now() - t0 };
    } catch (err) {
      const msg = err instanceof InvalidCredentialsError ? 'Invalid bind credentials' : (err && err.message) || 'bind failed';
      logger.error('LDAP test failed', { server: this.url, error: msg });
      return { success: false, encrypted, error: msg };
    } finally {
      try { await client.unbind(); } catch (_) { /* ignore */ }
    }
  }

  // ── Search the directory for users ──────────────────────────────────────────
  async searchUsers(filter) {
    if (!this.bindDn || !this.bindPassword) return { success: false, error: 'Bind credentials required' };
    const searchFilter = filter || (this.groupFilter ? `(&${this.userFilter}${this.groupFilter})` : this.userFilter);
    const client = this._newClient();
    try {
      await client.bind(this.bindDn, this.bindPassword);
      const { searchEntries } = await client.search(this.baseDn, {
        scope: 'sub',
        filter: searchFilter,
        attributes: SEARCH_ATTRS,
        explicitBufferAttributes: ['objectGUID'],
        sizeLimit: 1000,
      });
      const users = searchEntries.map((e) => this._mapEntry(e));
      logger.info('LDAP search', { baseDn: this.baseDn, filter: searchFilter, count: users.length });
      return { success: true, users, filter: searchFilter };
    } catch (err) {
      logger.error('LDAP search failed', { error: err && err.message });
      return { success: false, error: (err && err.message) || 'search failed' };
    } finally {
      try { await client.unbind(); } catch (_) { /* ignore */ }
    }
  }

  // ── Directory-presence check (offboarding detector) ─────────────────────────
  // Returns { found: boolean, entry?, error? }. CRITICAL: a directory error
  // returns found:false WITH an error field set; the offboarding detector must
  // treat "error present" as UNKNOWN (not absent) so a transient LDAP failure
  // can never cause a real analyst to be flagged for offboarding.
  async userExists(identifier) {
    if (!identifier) return { found: false };
    if (!this.bindDn || !this.bindPassword) return { found: false, error: 'Bind credentials required' };
    const esc = escapeFilterValue(identifier);
    const filter = `(|(${this.userIdAttr}=${esc})(sAMAccountName=${esc})(userPrincipalName=${esc})(mail=${esc}))`;
    const client = this._newClient();
    try {
      await client.bind(this.bindDn, this.bindPassword);
      const { searchEntries } = await client.search(this.baseDn, {
        scope: 'sub',
        filter,
        attributes: SEARCH_ATTRS,
        explicitBufferAttributes: ['objectGUID'],
        sizeLimit: 2,
      });
      if (!searchEntries.length) return { found: false };
      return { found: true, entry: this._mapEntry(searchEntries[0]) };
    } catch (err) {
      return { found: false, error: (err && err.message) || 'search failed' };
    } finally {
      try { await client.unbind(); } catch (_) { /* ignore */ }
    }
  }

  // ── Authenticate a user via LDAP bind (allow_password login path) ────────────
  async authenticate(username, password) {
    if (!username || !password) return { success: false, error: 'Username and password required' };

    // 1. Resolve the user's DN. With a service account, search for it; without
    //    one, fall back to a best-effort DN (works for simple flat directories).
    let userDn = null;
    let entry = null;
    if (this.bindDn && this.bindPassword) {
      const esc = escapeFilterValue(username);
      const filter = `(|(${this.userIdAttr}=${esc})(sAMAccountName=${esc})(userPrincipalName=${esc}))`;
      const findClient = this._newClient();
      try {
        await findClient.bind(this.bindDn, this.bindPassword);
        const { searchEntries } = await findClient.search(this.baseDn, {
          scope: 'sub',
          filter,
          attributes: SEARCH_ATTRS,
          explicitBufferAttributes: ['objectGUID'],
          sizeLimit: 2,
        });
        if (searchEntries.length > 1) return { success: false, error: 'Ambiguous username' };
        if (searchEntries.length === 0) return { success: false, error: 'User not found' };
        userDn = searchEntries[0].dn;
        entry = this._mapEntry(searchEntries[0]);
      } catch (err) {
        logger.error('LDAP auth lookup failed', { error: err && err.message });
        return { success: false, error: 'Directory lookup failed' };
      } finally {
        try { await findClient.unbind(); } catch (_) { /* ignore */ }
      }
    } else {
      userDn = `${this.userIdAttr}=${username},${this.baseDn}`;
    }

    // 2. Bind AS the user with the supplied password — this is the credential check.
    const userClient = this._newClient();
    try {
      await userClient.bind(userDn, password);
      return { success: true, username, dn: userDn, entry };
    } catch (err) {
      return { success: false, error: 'Invalid LDAP credentials' };
    } finally {
      try { await userClient.unbind(); } catch (_) { /* ignore */ }
    }
  }

  // ── Sync users from directory to FireAlive DB (JIT provisioning) ─────────────
  // Creates users found in the directory, updates changed attributes. Does NOT
  // delete or deactivate here — offboarding is surfaced (never auto-applied) by
  // the account-review detector.
  async syncUsers(db) {
    try {
      const searchResult = await this.searchUsers();
      if (!searchResult.success) return searchResult;

      let created = 0;
      let updated = 0;

      for (const adUser of searchResult.users) {
        if (!adUser.objectGUID || !adUser.sAMAccountName) continue;
        const role = this._mapGroupToRole(adUser.memberOf);
        // Identity minimization: persist only the opaque directory id
        // (objectGUID, in external_id) and a non-identifying handle derived from
        // it. The directory's displayName and sAMAccountName are NEVER stored, so
        // a database read cannot map a pseudonym back to a real person.
        const handle = handleForGuid(adUser.objectGUID);
        const existing = db.prepare('SELECT * FROM users WHERE external_id = ? AND auth_method = ?').get(adUser.objectGUID, 'ldap');

        if (!existing) {
          db.prepare(
            'INSERT INTO users (username, name, role, tier, auth_method, external_id, geo_country) VALUES (?, ?, ?, ?, ?, ?, ?)'
          ).run(handle, handle, role, role === 'analyst' ? 1 : null, 'ldap', adUser.objectGUID, adUser.country);
          created++;
        } else {
          // Sync the role, and self-heal any row provisioned before identity
          // minimization (whose username/name still held the real values) onto
          // the handle. The directory is authoritative for geo_country only
          // WHEN it supplies the country attribute (c); when the directory
          // omits it, the stored value is kept so an LDAP sync never wipes a
          // manually-assigned country.
          const nextGeo = adUser.country || existing.geo_country || null;
          if (
            existing.role !== role ||
            existing.username !== handle ||
            existing.name !== handle ||
            (existing.geo_country || null) !== nextGeo
          ) {
            db.prepare("UPDATE users SET username = ?, name = ?, role = ?, geo_country = ?, updated_at = datetime('now') WHERE id = ?").run(handle, handle, role, nextGeo, existing.id);
            updated++;
          }
        }
      }

      logger.info('LDAP sync complete', { created, updated });
      return { success: true, created, updated, deactivated: 0 };
    } catch (err) {
      logger.error('LDAP sync failed', { error: err && err.message });
      return { success: false, error: err && err.message };
    }
  }

  // ── Group → Role Mapping ───────────────────────────────────────────────
  _mapGroupToRole(memberOfList) {
    if (!Array.isArray(memberOfList)) return 'analyst';
    for (const group of memberOfList) {
      for (const [pattern, role] of Object.entries(this.groupMapping)) {
        if (group.includes(pattern) || group === pattern) return role;
      }
    }
    return 'analyst'; // default
  }
}

module.exports = { LdapClient, DEFAULT_GROUP_MAPPING, escapeFilterValue, formatGuid };
