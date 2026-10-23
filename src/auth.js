import { scrypt, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';
import { promisify } from 'node:util';

const scryptP = promisify(scrypt);

/** What each role may do. Edge units can only verify; viewers can only read. */
export const PERMS = {
  viewer: ['read'],
  edge: ['verify'],
  operator: ['read', 'verify', 'simulate'],
  dispatcher: ['read', 'verify', 'simulate', 'write'],
  admin: ['read', 'verify', 'simulate', 'write', 'admin'],
};
export const can = (role, perm) => (PERMS[role] || []).includes(perm);

export class AuthError extends Error {
  constructor(message, status = 401) { super(message); this.status = status; }
}

export async function hashPassword(pw) {
  const salt = randomBytes(16);
  const key = await scryptP(pw, salt, 32);
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}
export async function checkPassword(pw, stored) {
  const [alg, s, k] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const key = await scryptP(pw, Buffer.from(s, 'base64'), 32);
  const want = Buffer.from(k, 'base64');
  return key.length === want.length && timingSafeEqual(key, want);
}

const b64u = b => Buffer.from(b).toString('base64url');
const MAX_FAILS = 5, LOCK_MS = 60_000;

/** Users, password login, signed expiring tokens, and a login throttle. */
export class Auth {
  constructor({ users = [], secret, now = () => Date.now(), ttlMs = 8 * 3600_000 } = {}) {
    this.users = new Map(users.map(u => [u.username, u]));
    this.secret = secret ? Buffer.from(secret, 'base64') : randomBytes(32);
    this.now = now; this.ttlMs = ttlMs; this.fails = new Map();
  }

  async addUser(username, password, role) {
    if (!/^[a-z0-9_.-]{3,32}$/i.test(username || '')) throw new AuthError('username must be 3 to 32 letters, digits, dot, dash or underscore', 400);
    if (!PERMS[role]) throw new AuthError('role must be one of ' + Object.keys(PERMS).join(', '), 400);
    if (typeof password !== 'string' || password.length < 10) throw new AuthError('password must be at least 10 characters', 400);
    if (this.users.has(username)) throw new AuthError('user already exists', 409);
    this.users.set(username, { username, role, hash: await hashPassword(password), created: new Date(this.now()).toISOString() });
    return { username, role };
  }

  removeUser(username) {
    const u = this.users.get(username);
    if (!u) throw new AuthError('user not found', 404);
    if (u.role === 'admin' && [...this.users.values()].filter(x => x.role === 'admin').length === 1) throw new AuthError('cannot remove the last admin', 409);
    this.users.delete(username);
  }

  list() { return [...this.users.values()].map(({ username, role, created }) => ({ username, role, created })); }

  async login(username, password, ip = '') {
    const key = ip + '|' + username, f = this.fails.get(key);
    if (f && f.until > this.now()) throw new AuthError('too many failed attempts; try again in a minute', 429);
    const u = this.users.get(username);
    // Always run the hash so an unknown user takes as long as a wrong password.
    const ok = await checkPassword(String(password ?? ''), u ? u.hash : 'scrypt$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    if (!u || !ok) {
      const expired = f && f.until && f.until <= this.now(); // a lock that has run out starts a fresh count
      const n = (expired ? 0 : f?.n || 0) + 1;
      this.fails.set(key, { n, until: n >= MAX_FAILS ? this.now() + LOCK_MS : 0 });
      throw new AuthError('wrong username or password');
    }
    this.fails.delete(key);
    return this.issue(u);
  }

  issue(u) {
    const exp = this.now() + this.ttlMs;
    const payload = b64u(JSON.stringify({ sub: u.username, role: u.role, exp }));
    return { token: payload + '.' + this.#mac(payload), role: u.role, username: u.username, exp };
  }

  /** Returns { sub, role } for a valid, unexpired token whose user still exists; otherwise null. */
  verifyToken(token) {
    const [payload, mac] = String(token || '').split('.');
    if (!payload || !mac) return null;
    const want = Buffer.from(this.#mac(payload)), got = Buffer.from(mac);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
    let p; try { p = JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch { return null; }
    if (!p.exp || p.exp < this.now()) return null;
    const u = this.users.get(p.sub);
    return u ? { sub: u.username, role: u.role } : null; // role comes from the user record, so demotion applies at once
  }

  #mac(payload) { return createHmac('sha256', this.secret).update(payload).digest('base64url'); }

  export() { return { secret: this.secret.toString('base64'), users: [...this.users.values()] }; }
}
