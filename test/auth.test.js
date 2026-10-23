import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Auth, hashPassword, checkPassword, can } from '../src/auth.js';

const PW = 'correct-horse-battery';

test('passwords are salted scrypt hashes', async () => {
  const a = await hashPassword(PW), b = await hashPassword(PW);
  assert.notEqual(a, b);
  assert.match(a, /^scrypt\$/);
  assert.equal(await checkPassword(PW, a), true);
  assert.equal(await checkPassword('wrong-password', a), false);
});

test('tokens are signed, expire, and cannot be altered', async () => {
  let t = 1_000_000;
  const auth = new Auth({ now: () => t, ttlMs: 60_000 });
  await auth.addUser('amy', PW, 'dispatcher');
  const { token } = await auth.login('amy', PW);
  assert.deepEqual(auth.verifyToken(token), { sub: 'amy', role: 'dispatcher' });
  const [p, m] = token.split('.');
  const forged = Buffer.from(JSON.stringify({ sub: 'amy', role: 'admin', exp: t + 1e6 })).toString('base64url');
  assert.equal(auth.verifyToken(forged + '.' + m), null, 'edited payload fails the signature');
  assert.equal(auth.verifyToken(p + '.' + m.slice(0, -2) + 'AA'), null);
  t += 61_000;
  assert.equal(auth.verifyToken(token), null, 'expired');
});

test('a token from another server secret is rejected', async () => {
  const a = new Auth(), b = new Auth();
  await a.addUser('amy', PW, 'admin'); await b.addUser('amy', PW, 'admin');
  assert.equal(b.verifyToken((await a.login('amy', PW)).token), null);
});

test('user creation rules', async () => {
  const auth = new Auth();
  await assert.rejects(() => auth.addUser('x', PW, 'admin'), /username/);
  await assert.rejects(() => auth.addUser('amy', 'short', 'admin'), /password/);
  await assert.rejects(() => auth.addUser('amy', PW, 'root'), /role/);
  await auth.addUser('amy', PW, 'viewer');
  await assert.rejects(() => auth.addUser('amy', PW, 'viewer'), /exists/);
});

test('permissions by role', () => {
  assert.equal(can('edge', 'verify'), true); assert.equal(can('edge', 'read'), false);
  assert.equal(can('viewer', 'write'), false); assert.equal(can('dispatcher', 'write'), true);
  assert.equal(can('dispatcher', 'admin'), false); assert.equal(can('admin', 'admin'), true);
  assert.equal(can('nobody', 'read'), false);
});

test('lockout expires after a minute', async () => {
  let t = 5_000_000;
  const auth = new Auth({ now: () => t });
  await auth.addUser('amy', PW, 'viewer');
  for (let i = 0; i < 5; i++) await assert.rejects(() => auth.login('amy', 'bad' + i, 'ip'), /wrong/);
  await assert.rejects(() => auth.login('amy', PW, 'ip'), /too many/);
  t += 61_000;
  assert.ok((await auth.login('amy', PW, 'ip')).token);
});
