import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp, bootstrap } from '../src/server.js';
import { Auth } from '../src/auth.js';
import { RapidPass } from '../src/rapidpass.js';

const PW = 'correct-horse-battery';

async function boot(opts = {}) {
  const auth = new Auth();
  await auth.addUser('admin', PW, 'admin');
  await auth.addUser('disp', PW, 'dispatcher');
  await auth.addUser('view', PW, 'viewer');
  await auth.addUser('unit1', PW, 'edge');
  const server = createApp({ auth, ...opts }).listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, { body, token, method, headers } = {}) => {
    const r = await fetch(base + path, { method: method || (body === undefined ? 'GET' : 'POST'), headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: r.status, json, headers: r.headers };
  };
  const login = async u => (await call('/api/login', { body: { username: u, password: PW } })).json.token;
  return { server, call, login, auth };
}

test('every protected route needs a login', async () => {
  const { server, call } = await boot();
  try {
    assert.equal((await call('/api/health')).status, 200);
    for (const p of ['/api/incidents', '/api/audit', '/api/me', '/api/users']) assert.equal((await call(p)).status, 401, p);
    assert.equal((await call('/api/incidents', { body: {} })).status, 401);
    assert.equal((await call('/api/incidents', { token: 'garbage.garbage' })).status, 401);
  } finally { server.close(); }
});

test('roles limit what each user can do', async () => {
  const { server, call, login } = await boot();
  try {
    const [admin, disp, view, unit] = await Promise.all(['admin', 'disp', 'view', 'unit1'].map(login));
    assert.equal((await call('/api/incidents', { body: { type: 'medical' }, token: view })).status, 403, 'viewer cannot write');
    assert.equal((await call('/api/incidents', { token: view })).status, 200, 'viewer can read');
    assert.equal((await call('/api/incidents', { token: unit })).status, 403, 'edge cannot read');
    assert.equal((await call('/api/users', { token: disp })).status, 403, 'dispatcher is not admin');
    assert.equal((await call('/api/users', { token: admin })).status, 200);
    const inc = (await call('/api/incidents', { body: { type: 'medical' }, token: disp })).json;
    assert.match(inc.id, /^INC-/);
    assert.equal((await call('/api/me', { token: unit })).json.role, 'edge');
  } finally { server.close(); }
});

test('full flow with login: issue, verify, replay, close, audit with actors', async () => {
  const { server, call, login } = await boot();
  try {
    const disp = await login('disp'), unit = await login('unit1');
    const inc = (await call('/api/incidents', { body: { type: 'medical' }, token: disp })).json;
    assert.equal((await call(`/api/incidents/${inc.id}/vehicles`, { body: { plate: 'H 8919', agency: 'EMS' }, token: disp })).status, 200);
    assert.equal((await call('/api/simulate', { body: { plate: 'H 8919', mode: 'valid' }, token: disp })).json.ok, true);
    assert.equal((await call('/api/simulate', { body: { plate: 'H 8919', mode: 'replay' }, token: disp })).json.reason, 'REPLAY');
    assert.equal((await call('/api/simulate', { body: { plate: 'H 8919', mode: 'forged' }, token: disp })).json.reason, 'BAD_CREDENTIAL_SIGNATURE');
    assert.equal((await call(`/api/incidents/${inc.id}/close`, { body: {}, token: disp })).status, 200);
    assert.equal((await call('/api/simulate', { body: { plate: 'H 8919', mode: 'valid' }, token: disp })).json.reason, 'CREDENTIAL_REVOKED');
    // an edge unit may verify but nothing else
    assert.equal((await call('/api/verify', { body: { message: { bad: 1 } }, token: unit })).json.reason, 'MALFORMED');
    const audit = (await call('/api/audit', { token: disp })).json;
    assert.equal(audit.chain.ok, true);
    assert.ok(audit.entries.some(e => e.type === 'PASS_ISSUED' && e.data.actor === 'disp'));
    assert.equal((await call('/api/incidents/NOPE/close', { body: {}, token: disp })).status, 404);
  } finally { server.close(); }
});

test('wrong password and unknown user fail the same way; repeated failures lock out', async () => {
  const { server, call } = await boot();
  try {
    const a = await call('/api/login', { body: { username: 'admin', password: 'nope-nope-nope' } });
    const b = await call('/api/login', { body: { username: 'ghost', password: 'nope-nope-nope' } });
    assert.equal(a.status, 401); assert.equal(b.status, 401); assert.equal(a.json.error, b.json.error);
    for (let i = 0; i < 5; i++) await call('/api/login', { body: { username: 'admin', password: 'x' + i } });
    assert.equal((await call('/api/login', { body: { username: 'admin', password: PW } })).status, 429, 'locked even with the right password');
  } finally { server.close(); }
});

test('admin manages users; the last admin cannot be removed', async () => {
  const { server, call, login } = await boot();
  try {
    const admin = await login('admin');
    assert.equal((await call('/api/users', { body: { username: 'new1', password: 'short', role: 'viewer' }, token: admin })).status, 400);
    assert.equal((await call('/api/users', { body: { username: 'new1', password: PW, role: 'wizard' }, token: admin })).status, 400);
    assert.equal((await call('/api/users', { body: { username: 'new1', password: PW, role: 'operator' }, token: admin })).status, 200);
    assert.equal((await call('/api/users/new1', { method: 'DELETE', token: admin })).status, 200);
    assert.equal((await call('/api/users/admin', { method: 'DELETE', token: admin })).status, 409);
    const users = (await call('/api/users', { token: admin })).json;
    assert.ok(users.every(u => !('hash' in u)), 'password hashes are never returned');
  } finally { server.close(); }
});

test('a removed or demoted user loses access at once', async () => {
  const { server, call, login, auth } = await boot();
  try {
    const disp = await login('disp');
    assert.equal((await call('/api/incidents', { token: disp })).status, 200);
    auth.users.get('disp').role = 'viewer';
    assert.equal((await call('/api/incidents', { body: {}, token: disp })).status, 403);
    auth.removeUser('disp');
    assert.equal((await call('/api/incidents', { token: disp })).status, 401);
  } finally { server.close(); }
});

test('CORS only allows configured origins and answers preflight', async () => {
  const { server, call } = await boot({ env: { CORS_ORIGIN: 'https://thirumald.github.io' } });
  try {
    const ok = await call('/api/health', { headers: { origin: 'https://thirumald.github.io' } });
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://thirumald.github.io');
    const no = await call('/api/health', { headers: { origin: 'https://evil.example' } });
    assert.equal(no.headers.get('access-control-allow-origin'), null);
    const pre = await call('/api/incidents', { method: 'OPTIONS', headers: { origin: 'https://thirumald.github.io' } });
    assert.equal(pre.status, 204);
    assert.match(pre.headers.get('access-control-allow-headers'), /authorization/);
  } finally { server.close(); }
});

test('simulation can be switched off for production', async () => {
  const { server, call, login } = await boot({ env: { ENABLE_SIMULATE: '0' } });
  try {
    const disp = await login('disp');
    assert.equal((await call('/api/simulate', { body: { plate: 'X', mode: 'valid' }, token: disp })).status, 403);
  } finally { server.close(); }
});

test('TomTom proxy keeps the key server-side, limits paths and caches', async () => {
  const calls = [];
  const fetchImpl = async url => { calls.push(url); return new Response(JSON.stringify({ ok: 1 }), { status: 200, headers: { 'content-type': 'application/json' } }); };
  const { server, call, login } = await boot({ env: { TOMTOM_KEY: 'SECRETKEY' }, fetchImpl });
  try {
    const view = await login('view');
    const r = await call('/api/tomtom/traffic/services/5/incidentDetails?bbox=1,2,3,4&key=attacker', { token: view });
    assert.equal(r.status, 200); assert.deepEqual(r.json, { ok: 1 });
    assert.match(calls[0], /key=SECRETKEY/); assert.doesNotMatch(calls[0], /attacker/);
    await call('/api/tomtom/traffic/services/5/incidentDetails?bbox=1,2,3,4&key=other', { token: view });
    assert.equal(calls.length, 1, 'second identical request is served from cache');
    assert.equal((await call('/api/tomtom/account/secrets', { token: view })).status, 400);
    assert.equal((await call('/api/tomtom/traffic/x', {})).status, 401);
  } finally { server.close(); }
  const off = await boot({ env: {} });
  try { assert.equal((await off.call('/api/tomtom/traffic/a', { token: await off.login('view') })).status, 503); } finally { off.server.close(); }
});

test('state survives a restart: same signing key, passes, revocations, users and audit chain', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rp-'));
  const env = { DATA_FILE: join(dir, 'state.json'), ADMIN_PASSWORD: PW };
  const first = await bootstrap(env);
  assert.match(first.notice, /Created admin/);
  const s1 = first.app.listen(0), base1 = `http://127.0.0.1:${s1.address().port}`;
  const api = base => async (path, body, token) => { const r = await fetch(base + path, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, json: await r.json() }; };
  const a = api(base1);
  const token = (await a('/api/login', { username: 'admin', password: PW })).json.token;
  const inc = (await a('/api/incidents', { type: 'medical' }, token)).json;
  const credential = (await a(`/api/incidents/${inc.id}/vehicles`, { plate: 'H 1', agency: 'EMS' }, token)).json.credential;
  const key1 = (await (await fetch(base1 + '/api/health')).json()).authorityPublicKey;
  s1.close(); await first.store.flush();

  const second = await bootstrap(env);
  assert.equal(second.notice, '', 'existing admin is kept, no new one created');
  const s2 = second.app.listen(0), b = api(`http://127.0.0.1:${s2.address().port}`);
  try {
    const t2 = (await b('/api/login', { username: 'admin', password: PW })).json.token;
    assert.ok(t2, 'password still works after restart');
    assert.equal((await b('/api/health')).json.authorityPublicKey, key1, 'same signing key');
    const incs = (await b('/api/incidents', null, t2)).json;
    assert.equal(incs[0].vehicles[0].plate, 'H 1');
    const sim = (await b('/api/simulate', { plate: 'H 1', mode: 'valid' }, t2)).json;
    assert.equal(sim.ok, true, 'a pass issued before the restart still verifies: ' + sim.reason);
    assert.equal(credential.kid, incs[0].vehicles[0].kid);
    assert.equal((await b('/api/audit', null, t2)).json.chain.ok, true);
    await b(`/api/incidents/${inc.id}/close`, {}, t2);
  } finally { s2.close(); await second.store.flush(); }

  const third = await bootstrap(env); // revocation was saved too
  const s3 = third.app.listen(0), c = api(`http://127.0.0.1:${s3.address().port}`);
  try {
    const t3 = (await c('/api/login', { username: 'admin', password: PW })).json.token;
    assert.equal((await c('/api/simulate', { plate: 'H 1', mode: 'valid' }, t3)).json.reason, 'CREDENTIAL_REVOKED');
  } finally { s3.close(); await third.store.flush(); }
});

test('a state file with an edited audit log is refused', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rp-'));
  const file = join(dir, 'state.json'), env = { DATA_FILE: file, ADMIN_PASSWORD: PW };
  const first = await bootstrap(env);
  const s = first.app.listen(0); s.close(); await first.store.flush();
  const state = JSON.parse(await readFile(file, 'utf8'));
  const rp = RapidPass.import(state.rp); rp.createIncident({ type: 'medical' }, 'x');
  const bad = { ...state, rp: rp.export() };
  bad.rp.audit[0].data.id = 'FAKE';
  await writeFile(file, JSON.stringify(bad));
  await assert.rejects(() => bootstrap(env), /audit chain broken/);
});
