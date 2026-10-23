import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';

test('HTTP flow: issue, verify, replay, close', async () => {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, body) => {
    const r = await fetch(base + path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, json: await r.json() };
  };
  try {
    const inc = (await call('/api/incidents', { type: 'medical' })).json;
    const pass = await call(`/api/incidents/${inc.id}/vehicles`, { plate: 'H 8919', agency: 'EMS' });
    assert.equal(pass.status, 200);
    assert.equal((await call('/api/simulate', { plate: 'H 8919', mode: 'valid' })).json.ok, true);
    assert.equal((await call('/api/simulate', { plate: 'H 8919', mode: 'replay' })).json.reason, 'REPLAY');
    assert.equal((await call('/api/simulate', { plate: 'H 8919', mode: 'forged' })).json.reason, 'BAD_CREDENTIAL_SIGNATURE');
    assert.equal((await call('/api/simulate', { plate: 'H 8919', mode: 'wrongkey' })).json.reason, 'BAD_MESSAGE_SIGNATURE');
    await call(`/api/incidents/${inc.id}/close`, {});
    assert.equal((await call('/api/simulate', { plate: 'H 8919', mode: 'valid' })).json.reason, 'CREDENTIAL_REVOKED');
    const audit = (await call('/api/audit')).json;
    assert.equal(audit.chain.ok, true);
    assert.equal((await call('/api/incidents/NOPE/close', {})).status, 404);
  } finally { server.close(); }
});
