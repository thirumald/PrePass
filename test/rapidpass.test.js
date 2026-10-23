import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RapidPass } from '../src/rapidpass.js';

function setup(opts) {
  const rp = new RapidPass(opts);
  const inc = rp.createIncident({ type: 'medical' });
  const { credential, devicePrivateKey } = rp.issuePass(inc.id, { plate: 'H 8919', agency: 'EMS' });
  const send = (ctr, ts = rp.now()) => rp.verify(RapidPass.buildMessage(credential, devicePrivateKey, ctr, ts), 'S1 EB');
  return { rp, inc, credential, devicePrivateKey, send };
}

test('accepts a valid message from a dispatched vehicle', () => {
  const { send } = setup();
  assert.deepEqual(send(1), { ok: true, reason: 'OK', alert: false });
});

test('rejects a replayed message and raises an alert (S3)', () => {
  const { rp, credential, devicePrivateKey } = setup();
  const msg = RapidPass.buildMessage(credential, devicePrivateKey, 1, rp.now());
  assert.equal(rp.verify(msg).ok, true);
  const again = rp.verify(msg);
  assert.equal(again.reason, 'REPLAY');
  assert.equal(again.alert, true);
});

test('rejects a counter that goes backwards', () => {
  const { send } = setup();
  send(5);
  assert.equal(send(4).reason, 'REPLAY');
});

test('rejects a tampered credential as a clone or forgery (S2)', () => {
  const { rp, credential, devicePrivateKey } = setup();
  const msg = RapidPass.buildMessage({ ...credential, cls: 'fire' }, devicePrivateKey, 1, rp.now());
  const r = rp.verify(msg);
  assert.equal(r.reason, 'BAD_CREDENTIAL_SIGNATURE');
  assert.equal(r.alert, true);
});

test('rejects a message signed with a different device key', () => {
  const a = setup(), b = setup();
  const msg = RapidPass.buildMessage(a.credential, b.devicePrivateKey, 1, a.rp.now());
  assert.equal(a.rp.verify(msg).reason, 'BAD_MESSAGE_SIGNATURE');
});

test('dispatch status decides priority: returning gets none (E7)', () => {
  const { rp, inc, send } = setup();
  rp.setStatus(inc.id, 'H 8919', 'returning');
  assert.equal(send(1).reason, 'STATUS_NOT_PRIORITY');
  rp.setStatus(inc.id, 'H 8919', 'patient');
  assert.equal(send(2).ok, true);
});

test('closing the incident revokes its passes', () => {
  const { rp, inc, send } = setup();
  assert.equal(send(1).ok, true);
  rp.closeIncident(inc.id);
  assert.equal(send(2).reason, 'CREDENTIAL_REVOKED');
});

test('expired credentials and stale messages are rejected', () => {
  let t = 1_000_000;
  const rp = new RapidPass({ now: () => t });
  const inc = rp.createIncident();
  const { credential, devicePrivateKey } = rp.issuePass(inc.id, { plate: 'A 1', ttlMs: 60_000 });
  assert.equal(rp.verify(RapidPass.buildMessage(credential, devicePrivateKey, 1, t - 30_000)).reason, 'STALE_MESSAGE');
  t += 120_000;
  assert.equal(rp.verify(RapidPass.buildMessage(credential, devicePrivateKey, 2, t)).reason, 'CREDENTIAL_EXPIRED');
});

test('audit log is hash-chained and detects tampering', () => {
  const { rp, send } = setup();
  send(1); send(1);
  assert.equal(rp.audit.verifyChain().ok, true);
  rp.audit.entries[1].data.plate = 'X 0';
  assert.deepEqual(rp.audit.verifyChain(), { ok: false, brokenAt: 2 });
});

test('a second pass for the same vehicle on one incident is refused', () => {
  const { rp, inc } = setup();
  assert.throws(() => rp.issuePass(inc.id, { plate: 'H 8919' }), /already has a pass/);
});

test('export and import keep the signing key, passes, counters and audit chain', () => {
  const { rp, inc, credential, devicePrivateKey } = setup();
  rp.verify(RapidPass.buildMessage(credential, devicePrivateKey, 1, rp.now()));
  const copy = RapidPass.import(JSON.parse(JSON.stringify(rp.export())));
  assert.equal(copy.authorityPublicKey, rp.authorityPublicKey);
  assert.equal(copy.audit.verifyChain().ok, true);
  assert.equal(copy.verify(RapidPass.buildMessage(credential, devicePrivateKey, 1, copy.now())).reason, 'REPLAY', 'counter state was kept');
  assert.equal(copy.verify(RapidPass.buildMessage(credential, devicePrivateKey, 2, copy.now())).ok, true);
  assert.equal(copy.simulate('H 8919', 'valid').ok, true);
});
