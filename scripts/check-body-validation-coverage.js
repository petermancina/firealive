#!/usr/bin/env node
//
// FIREALIVE -- Request-Body Shape Validation Coverage Guard (CI)
//
// Fails the build if a route persists req.body wholesale without a body-shape
// guard, or if the body-validation middleware stops rejecting malformed
// shapes. Two invariants:
//
//   A. BEHAVIOR  -- requireObjectBody / requireArrayBody / requireStructuredBody
//      reject the wrong shapes with HTTP 400 and pass the right ones.
//      Catches: a regression that weakens or breaks a guard.
//
//   B. COVERAGE  -- every route that persists req.body wholesale (a handler
//      containing JSON.stringify(req.body)) declares a body-shape guard as a
//      middleware on its route definition.
//      Catches: a new wholesale-persist endpoint added without a guard -- the
//      exact drift that left the config-write routes type-confusable (CWE-843).
//
// Scope note: routes that read named fields off req.body (const { a } = req.body)
// are a different, safer pattern and are not required to carry a guard. This
// guard targets JSON.stringify(req.body) -- the shape that lets a caller poison
// a stored row with arbitrary structured input.
//
// Run:  node scripts/check-body-validation-coverage.js
// Exits non-zero (failing CI) with a list of problems, or 0 when consistent.
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SERVER = path.join(ROOT, 'server');
const NL = String.fromCharCode(10);

const {
  requireStructuredBody,
  requireArrayBody,
  requireObjectBody,
} = require(path.join(SERVER, 'middleware', 'body-validation.js'));

const failures = [];
const fail = (m) => failures.push(m);

const GUARD_NAMES = ['requireObjectBody', 'requireArrayBody', 'requireStructuredBody'];
const PERSIST_NEEDLE = 'JSON.stringify(req.body)';
const METHODS = ['get', 'put', 'post', 'patch', 'delete', 'all'];

// ---------------------------------------------------------------------------
// CHECK A: guard behavior.
// ---------------------------------------------------------------------------

function invoke(mw, body, method) {
  const req = { method: method || 'PUT', body: body };
  const res = { statusCode: null };
  res.status = function (code) { res.statusCode = code; return res; };
  res.json = function () { return res; };
  let nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  return { nextCalled: nextCalled, statusCode: res.statusCode };
}

function describe(body) {
  if (body === null) return 'null';
  if (body === undefined) return 'undefined';
  if (Array.isArray(body)) return 'an array';
  return 'a ' + typeof body;
}

function expectReject(name, mw, body, method) {
  const r = invoke(mw, body, method);
  if (r.nextCalled || r.statusCode !== 400) {
    fail('behavior: ' + name + ' should reject ' + describe(body) +
      ' with 400 (got next=' + r.nextCalled + ', status=' + r.statusCode + ')');
  }
}

function expectAccept(name, mw, body, method) {
  const r = invoke(mw, body, method);
  if (!r.nextCalled || r.statusCode !== null) {
    fail('behavior: ' + name + ' should accept ' + describe(body) +
      ' (got next=' + r.nextCalled + ', status=' + r.statusCode + ')');
  }
}

// requireObjectBody: only a plain (non-array) object passes.
expectReject('requireObjectBody', requireObjectBody, null);
expectReject('requireObjectBody', requireObjectBody, undefined);
expectReject('requireObjectBody', requireObjectBody, 'x');
expectReject('requireObjectBody', requireObjectBody, 7);
expectReject('requireObjectBody', requireObjectBody, true);
expectReject('requireObjectBody', requireObjectBody, [1, 2]);
expectAccept('requireObjectBody', requireObjectBody, {});
expectAccept('requireObjectBody', requireObjectBody, { mode: 'active' });

// requireArrayBody: only an array passes.
expectReject('requireArrayBody', requireArrayBody, {});
expectReject('requireArrayBody', requireArrayBody, 'x');
expectReject('requireArrayBody', requireArrayBody, null);
expectAccept('requireArrayBody', requireArrayBody, []);
expectAccept('requireArrayBody', requireArrayBody, [{ id: 1 }]);

// requireStructuredBody: object or array passes; primitives rejected; a
// non-body method (GET) passes through without inspecting the body.
expectAccept('requireStructuredBody', requireStructuredBody, {});
expectAccept('requireStructuredBody', requireStructuredBody, []);
expectReject('requireStructuredBody', requireStructuredBody, null);
expectReject('requireStructuredBody', requireStructuredBody, 'x');
expectReject('requireStructuredBody', requireStructuredBody, 5);
expectAccept('requireStructuredBody', requireStructuredBody, 'x', 'GET');

// ---------------------------------------------------------------------------
// CHECK B: coverage -- wholesale req.body persist requires a guard.
// ---------------------------------------------------------------------------

function isRouteDef(line) {
  for (let i = 0; i < METHODS.length; i++) {
    if (line.indexOf('router.' + METHODS[i] + '(') === 0) return true;
  }
  return false;
}

function parseRouteDef(line) {
  const dot = line.indexOf('.');
  const paren = line.indexOf('(', dot);
  const method = line.slice(dot + 1, paren).toUpperCase();
  const q1 = line.indexOf("'", paren);
  const q2 = line.indexOf("'", q1 + 1);
  const routePath = (q1 !== -1 && q2 !== -1) ? line.slice(q1 + 1, q2) : '(unparsed)';
  return { method: method, routePath: routePath };
}

function lineHasGuard(line) {
  for (let i = 0; i < GUARD_NAMES.length; i++) {
    if (line.indexOf(GUARD_NAMES[i]) !== -1) return true;
  }
  return false;
}

const routesDir = path.join(SERVER, 'routes');
const routeFiles = fs.readdirSync(routesDir)
  .filter((f) => f.length > 3 && f.slice(f.length - 3) === '.js')
  .map((f) => path.join(routesDir, f));

let persistRoutes = 0;

for (const file of routeFiles) {
  const lines = fs.readFileSync(file, 'utf8').split(NL);
  let curPath = null;
  let curMethod = null;
  let curHasGuard = false;
  let curCounted = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (isRouteDef(line)) {
      const info = parseRouteDef(line);
      curPath = info.routePath;
      curMethod = info.method;
      curHasGuard = lineHasGuard(line);
      curCounted = false;
    }
    if (curPath !== null && line.indexOf(PERSIST_NEEDLE) !== -1 && !curCounted) {
      curCounted = true;
      persistRoutes = persistRoutes + 1;
      if (!curHasGuard) {
        fail('coverage: ' + path.relative(ROOT, file) + ' ' + curMethod + ' ' +
          curPath + ' persists req.body without a body-shape guard');
      }
    }
  }
}

// ---------------------------------------------------------------------------

if (failures.length > 0) {
  console.error('Body-validation coverage guard FAILED:');
  for (const f of failures) console.error('  - ' + f);
  console.error(NL + failures.length + ' problem(s). Apply a guard from ' +
    'server/middleware/body-validation.js to every route that persists ' +
    'req.body, and keep the guards rejecting malformed shapes.');
  process.exit(1);
}

console.log('Body-validation coverage guard passed: guards reject malformed ' +
  'bodies; ' + persistRoutes + ' wholesale req.body persist route(s) all guarded.');
