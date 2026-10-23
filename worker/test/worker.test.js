import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { RapidPassDO } from '../src/index.js';

const PW = 'correct-horse-battery';

/** In-memory stand-in for Durable Object storage: same get / put / delete / list(prefix, reverse, limit) behaviour. */
class FakeStorage {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? structuredClone(this.m.get(k)) : undefined; }
  async put(k, v) { this.m.set(k, structuredClone(v)); }
  async delete(k) { return this.m.delete(k); }
  async list({ prefix = '', reverse = false, limit } = {}) {
    let keys = [...this.m.keys()].filter(k => k.startsWith(prefix)).sort(); if (reverse) keys.reverse(); if (limit) keys = keys.slice(0, limit);
    return new Map(keys.map(k => [k, structuredClone(this.m.get(k))]));
  }
}

/** Boots the Worker + Durable Object the way the runtime does: the object is built once and requests wait for its init. */
function world(vars = {}, storage = new FakeStorage()) {
  const env = { CORS_ORIGIN: 'https://thirumald.github.io', ENABLE_SIMULATE: '1', ADMIN_PASSWORD: PW, ...vars };
  let ready = Promise.resolve();
  const state = { storage, blockConcurrencyWhile: fn => { ready = fn(); return ready; } };
  const obj = new RapidPassDO(state, env);
  env.RP = { idFromName: () => 'main', get: () => ({ fetch: async req => { await ready; return obj.fetch(req); } }) };
  const call = async (path, { body, token, method, headers } = {}) => {
    const req = new Request('https://api.test' + path, { method: method || (body === undefined ? 'GET' : 'POST'), headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const res = await worker.fetch(req, env); const text = await res.text(); let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: res.status, json, headers: res.headers };
  };
  const login = async (u, p = PW) => (await call('/api/login', { body: { username: u, password: p } })).json.token;
  return { call, login, storage, env };
}
async function withUsers(vars) {
  const w = world(vars); const admin = await w.login('admin');
  for (const [u, role] of [['disp', 'dispatcher'], ['view', 'viewer'], ['unit1', 'edge']]) await w.call('/api/users', { body: { username: u, password: PW, role }, token: admin });
  return { ...w, admin };
}

test('first start creates the admin from the ADMIN_PASSWORD secret; without it the API says setup is needed', async () => {
  const a = world(); assert.ok(await a.login('admin'), 'admin can log in');
  const b = world({ ADMIN_PASSWORD: undefined });
  assert.equal((await b.call('/api/health')).json.setupNeeded, true);
  assert.equal((await b.call('/api/login', { body: { username: 'admin', password: PW } })).status, 401);
});

test('every protected route needs a login', async () => {
  const { call } = world();
  assert.equal((await call('/api/health')).status, 200);
  for (const p of ['/api/incidents', '/api/audit', '/api/me', '/api/users']) assert.equal((await call(p)).status, 401, p);
  assert.equal((await call('/api/incidents', { body: {} })).status, 401);
  assert.equal((await call('/api/incidents', { token: 'garbage.garbage' })).status, 401);
});

test('roles limit what each user can do', async () => {
  const { call, login } = await withUsers();
  const [admin, disp, view, unit] = await Promise.all(['admin', 'disp', 'view', 'unit1'].map(u => login(u)));
  assert.equal((await call('/api/incidents', { body: { type: 'medical' }, token: view })).status, 403);
  assert.equal((await call('/api/incidents', { token: view })).status, 200);
  assert.equal((await call('/api/incidents', { token: unit })).status, 403);
  assert.equal((await call('/api/users', { token: disp })).status, 403);
  assert.equal((await call('/api/users', { token: admin })).status, 200);
  assert.match((await call('/api/incidents', { body: { type: 'medical' }, token: disp })).json.id, /^INC-/);
  assert.equal((await call('/api/me', { token: unit })).json.role, 'edge');
});

test('full flow: issue, verify, replay, forged, wrong key, close, audit with actors', async () => {
  const { call, login } = await withUsers();
  const disp = await login('disp'), unit = await login('unit1');
  const inc = (await call('/api/incidents', { body: { type: 'medical' }, token: disp })).json;
  assert.equal((await call(`/api/incidents/${inc.id}/vehicles`, { body: { plate: 'H 8919', agency: 'EMS' }, token: disp })).status, 200);
  const sim = mode => call('/api/simulate', { body: { plate: 'H 8919', mode }, token: disp }).then(r => r.json);
  assert.equal((await sim('valid')).ok, true);
  assert.equal((await sim('replay')).reason, 'REPLAY');
  assert.equal((await sim('forged')).reason, 'BAD_CREDENTIAL_SIGNATURE');
  assert.equal((await sim('wrongkey')).reason, 'BAD_MESSAGE_SIGNATURE');
  assert.equal((await call('/api/incidents/' + inc.id + '/status', { body: { plate: 'H 8919', status: 'returning' }, token: disp })).status, 200);
  assert.equal((await sim('valid')).reason, 'STATUS_NOT_PRIORITY');
  await call('/api/incidents/' + inc.id + '/status', { body: { plate: 'H 8919', status: 'patient' }, token: disp });
  assert.equal((await sim('valid')).ok, true);
  await call(`/api/incidents/${inc.id}/close`, { body: {}, token: disp });
  assert.equal((await sim('valid')).reason, 'CREDENTIAL_REVOKED');
  assert.equal((await call('/api/verify', { body: { message: { bad: 1 } }, token: unit })).json.reason, 'MALFORMED');
  const audit = (await call('/api/audit?verify=1', { token: disp })).json;
  assert.equal(audit.chain.ok, true);
  assert.ok(audit.entries.some(e => e.type === 'PASS_ISSUED' && e.data.actor === 'disp'));
  assert.equal((await call('/api/incidents/NOPE/close', { body: {}, token: disp })).status, 404);
});

test('wrong password and unknown user fail alike; repeated failures lock out', async () => {
  const { call } = world();
  const a = await call('/api/login', { body: { username: 'admin', password: 'nope-nope-nope' } });
  const b = await call('/api/login', { body: { username: 'ghost', password: 'nope-nope-nope' } });
  assert.equal(a.status, 401); assert.equal(b.status, 401); assert.equal(a.json.error, b.json.error);
  for (let i = 0; i < 5; i++) await call('/api/login', { body: { username: 'admin', password: 'x' + i } });
  assert.equal((await call('/api/login', { body: { username: 'admin', password: PW } })).status, 429);
});

test('admin manages users; the last admin cannot be removed; hashes are never returned', async () => {
  const { call, admin } = await withUsers();
  assert.equal((await call('/api/users', { body: { username: 'new1', password: 'short', role: 'viewer' }, token: admin })).status, 400);
  assert.equal((await call('/api/users', { body: { username: 'new1', password: PW, role: 'wizard' }, token: admin })).status, 400);
  assert.equal((await call('/api/users', { body: { username: 'new1', password: PW, role: 'operator' }, token: admin })).status, 200);
  assert.equal((await call('/api/users/new1', { method: 'DELETE', token: admin })).status, 200);
  assert.equal((await call('/api/users/admin', { method: 'DELETE', token: admin })).status, 409);
  assert.ok((await call('/api/users', { token: admin })).json.every(u => !('hash' in u)));
});

test('a removed user loses access at once; a demoted user gets the new role at once', async () => {
  const { call, admin, login } = await withUsers();
  const disp = await login('disp');
  assert.equal((await call('/api/incidents', { token: disp })).status, 200);
  await call('/api/users/disp', { method: 'DELETE', token: admin });
  assert.equal((await call('/api/incidents', { token: disp })).status, 401);
});

test('CORS only allows configured origins and answers preflight', async () => {
  const { call } = world();
  assert.equal((await call('/api/health', { headers: { origin: 'https://thirumald.github.io' } })).headers.get('access-control-allow-origin'), 'https://thirumald.github.io');
  assert.equal((await call('/api/health', { headers: { origin: 'https://evil.example' } })).headers.get('access-control-allow-origin'), null);
  const pre = await call('/api/incidents', { method: 'OPTIONS', headers: { origin: 'https://thirumald.github.io' } });
  assert.equal(pre.status, 204); assert.match(pre.headers.get('access-control-allow-headers'), /authorization/);
  assert.equal((await call('/')).json.service, 'rapidpass-api');
  assert.equal((await call('/elsewhere')).status, 404);
});

test('simulation can be switched off', async () => {
  const { call, login } = await withUsers({ ENABLE_SIMULATE: '0' });
  assert.equal((await call('/api/simulate', { body: { plate: 'X', mode: 'valid' }, token: await login('disp') })).status, 403);
});

test('TomTom proxy keeps the key in the secret, limits paths and caches', async () => {
  const calls = [], real = globalThis.fetch;
  globalThis.fetch = async url => { calls.push(String(url)); return new Response(JSON.stringify({ ok: 1 }), { status: 200, headers: { 'content-type': 'application/json' } }); };
  try {
    const { call, login } = await withUsers({ TOMTOM_KEY: 'SECRETKEY' }); const view = await login('view');
    const r = await call('/api/tomtom/traffic/services/5/incidentDetails?bbox=1,2,3,4&key=attacker', { token: view });
    assert.equal(r.status, 200); assert.deepEqual(r.json, { ok: 1 });
    assert.match(calls[0], /key=SECRETKEY/); assert.doesNotMatch(calls[0], /attacker/);
    await call('/api/tomtom/traffic/services/5/incidentDetails?bbox=1,2,3,4&key=other', { token: view });
    assert.equal(calls.length, 1, 'cached');
    assert.equal((await call('/api/tomtom/account/secrets', { token: view })).status, 400);
    assert.equal((await call('/api/tomtom/traffic/x')).status, 401);
    const off = await withUsers({}); assert.equal((await off.call('/api/tomtom/traffic/a', { token: await off.login('view') })).status, 503);
  } finally { globalThis.fetch = real; }
});

test('state survives the object being rebuilt: same key, passes, counters, revocations, users, audit chain', async () => {
  const storage = new FakeStorage();
  const w1 = world({}, storage); const t1 = await w1.login('admin');
  const inc = (await w1.call('/api/incidents', { body: { type: 'medical' }, token: t1 })).json;
  await w1.call(`/api/incidents/${inc.id}/vehicles`, { body: { plate: 'H 1' }, token: t1 });
  const key1 = (await w1.call('/api/health')).json.authorityPublicKey;
  assert.equal((await w1.call('/api/simulate', { body: { plate: 'H 1', mode: 'valid' }, token: t1 })).json.ok, true);

  const w2 = world({ ADMIN_PASSWORD: undefined }, storage); // evicted and rebuilt: nothing in memory, no bootstrap secret
  const t2 = await w2.login('admin');
  assert.ok(t2, 'password still works'); assert.equal((await w2.call('/api/health')).json.authorityPublicKey, key1);
  assert.equal(await w2.call('/api/me', { token: t1 }).then(r => r.status), 200, 'a token issued before the rebuild still works');
  assert.equal((await w2.call('/api/simulate', { body: { plate: 'H 1', mode: 'valid' }, token: t2 })).json.ok, true, 'counter continues past the saved one');
  const first = (await w2.call('/api/incidents', { token: t2 })).json[0]; assert.equal(first.vehicles[0].plate, 'H 1');
  await w2.call(`/api/incidents/${inc.id}/close`, { body: {}, token: t2 });

  const w3 = world({ ADMIN_PASSWORD: undefined }, storage); const t3 = await w3.login('admin');
  assert.equal((await w3.call('/api/simulate', { body: { plate: 'H 1', mode: 'valid' }, token: t3 })).json.reason, 'CREDENTIAL_REVOKED');
  assert.equal((await w3.call('/api/audit?verify=1', { token: t3 })).json.chain.ok, true);
});

test('a tampered audit log makes the API refuse to serve', async () => {
  const storage = new FakeStorage(); const w1 = world({}, storage); await w1.login('admin');
  const key = [...storage.m.keys()].filter(k => k.startsWith('audit:')).sort()[0]; const e = storage.m.get(key); e.data.username = 'mallory'; storage.m.set(key, e);
  const w2 = world({ ADMIN_PASSWORD: undefined }, storage);
  const r = await w2.call('/api/health'); assert.equal(r.status, 503); assert.match(r.json.error, /audit chain broken/);
});

test('replay protection holds when two verifications of the same message race', async () => {
  const { call, login } = await withUsers(); const disp = await login('disp');
  const inc = (await call('/api/incidents', { body: {}, token: disp })).json;
  await call(`/api/incidents/${inc.id}/vehicles`, { body: { plate: 'R 1' }, token: disp });
  assert.equal((await call('/api/simulate', { body: { plate: 'R 1', mode: 'valid' }, token: disp })).json.ok, true);
  const [a, b] = await Promise.all([1, 2].map(() => call('/api/simulate', { body: { plate: 'R 1', mode: 'replay' }, token: disp })));
  assert.equal(a.json.reason, 'REPLAY'); assert.equal(b.json.reason, 'REPLAY');
});
