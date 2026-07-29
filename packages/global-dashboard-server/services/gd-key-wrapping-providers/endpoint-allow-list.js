// =============================================================================
// FIREALIVE GD -- KMS endpoint host allow-list  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// Two key-wrapping providers accept an operator-supplied URL:
//
//   hashicorp-vault   config.vault_addr   -> raw https.request (postJson)
//   azure-keyvault    config.vault_url    -> @azure/keyvault-keys SDK
//
// On this server the environment variable is GD_KMS_ALLOWED_HOSTS, and the
// Regional Server's list does NOT authorise a host here: separate trust realms,
// separate allow-lists, asserted by a test.
//
// Before this module neither was constrained beyond "parses, and uses https:".
// base.requireUrl validated the scheme and nothing else, so an operator who can
// configure a KMS provider could point it at
//
//   https://169.254.169.254/latest/meta-data/iam/security-credentials/
//
// and the server would issue an authenticated request to the cloud instance
// metadata endpoint, or to any host reachable from inside the deployment's
// network. That is server-side request forgery with credentials attached, by a
// configuration path rather than an exploit.
//
// THE GD TWIN of server/services/key-wrapping-providers/endpoint-allow-list.js.
// Behaviour is identical by construction; only the header differs. See the
// Regional Server copy for why a twin rather than an import: The Global Dashboard
// server is fully self-contained: it declares no local package dependency, never
// requires from server/, and 86 of its services are twins of a server/services
// file. That separation is deliberate -- the two are independent deployments in
// separate trust realms -- so a module loaded by both does not exist here.
//
// What must NOT differ is the behaviour. B6g adds the GD's provider registry,
// and the obvious build hardens the new one while leaving the Regional Server
// as it is: the same code, written twice, hardened once, which is the
// split-quality outcome the master principle rejects. The twin is a copy with
// one constant changed, which keeps the two diffable.
//
// The allow-list environment variable is a PARAMETER rather than a constant read
// here, so that one constant is the only difference.
//
// FAIL-CLOSED, AND THE DIRECTION IS THE WHOLE POINT. An unset or empty
// allow-list denies every URL-taking provider rather than permitting them. An
// operator who has not decided which hosts are legitimate has not authorised
// any, and a KMS endpoint is not a setting where "unconfigured" should mean
// "anything". The AWS and GCP providers are unaffected: they take a region and
// a key id, never a URL, so there is no endpoint for an operator to redirect.
//
// HOSTNAME-ONLY, EXACT, CASE-INSENSITIVE. No wildcards and no subdomain
// semantics, because both are how an allow-list becomes decorative:
// `*.vault.example.com` is satisfied by `evil.vault.example.com` if an attacker
// controls any subdomain, and a suffix match on `vault.example.com` is
// satisfied by `notvault.example.com`. The port and path are deliberately not
// matched -- an operator who has authorised a host has authorised the service on
// it, and matching ports would produce a second thing to keep in sync for no
// security gain.
//
// CHECKED AT THREE POINTS, not one. Config validation alone would leave the
// window open: rows already in the database predate the allow-list, and an
// allow-list that only runs on write cannot constrain what was written before
// it existed. So it runs at config-write, at connection test, and again at
// every wrap and unwrap.
//

/**
 * Read the configured allow-list.
 *
 * @param {string} envName  'KMS_ALLOWED_HOSTS' or 'GD_KMS_ALLOWED_HOSTS'
 * @param {object} [env]    process.env by default; injectable for tests
 * @returns {string[]}      lower-cased hostnames, empty when unset
 */
function allowedHosts(envName, env) {
  const source = env || process.env;
  const raw = source[envName];
  if (typeof raw !== 'string' || raw.trim() === '') return [];
  return raw
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h !== '');
}

/**
 * Is this URL's host authorised?
 *
 * Returns a result object rather than a boolean so every caller can surface the
 * same message. A caller that only needs a boolean reads `.ok`.
 *
 * @param {string} urlStr
 * @param {string} envName
 * @param {object} [env]
 * @returns {{ok: boolean, error?: string, host?: string}}
 */
function checkEndpoint(urlStr, envName, env) {
  if (typeof urlStr !== 'string' || urlStr === '') {
    return { ok: false, error: 'endpoint URL required' };
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (_) {
    return { ok: false, error: 'endpoint is not a valid URL' };
  }

  // Scheme is re-checked here as well as in requireUrl. This function is the
  // one called on the wrap and unwrap paths, and a check that only runs during
  // config validation does not constrain a row written before it existed.
  if (parsed.protocol !== 'https:') {
    return { ok: false, error: 'endpoint must use https' };
  }

  const hosts = allowedHosts(envName, env);
  if (hosts.length === 0) {
    return {
      ok: false,
      error:
        `${envName} is not set, so no KMS endpoint host is authorised. ` +
        'Set it to a comma-separated list of exact hostnames before configuring ' +
        'a provider that takes a URL.',
    };
  }

  // URL already lower-cases the hostname, but an allow-list is not a place to
  // rely on a normalisation performed elsewhere.
  const host = parsed.hostname.toLowerCase();

  if (!hosts.includes(host)) {
    return {
      ok: false,
      error:
        `endpoint host '${host}' is not in ${envName}. ` +
        'Matching is exact and hostname-only: no wildcards, no subdomain suffixes.',
      host,
    };
  }

  return { ok: true, host };
}

module.exports = {
  allowedHosts,
  checkEndpoint,
};
