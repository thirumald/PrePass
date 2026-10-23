// Users, password login, signed expiring tokens and a login throttle, using WebCrypto only.
import { b64, unb64 } from './engine.js';

export const PERMS = {
  viewer: ['read'], edge: ['verify'], operator: ['read', 'verify', 'simulate'],
  dispatcher: ['read', 'verify', 'simulate', 'write'], admin: ['read', 'verify', 'simulate', 'write', 'admin'],
};
export const can = (role, perm) => (PERMS[role] || []).includes(perm);
export class AuthError extends Error { constructor(message, status = 401) { super(message); this.status = status; } }

const enc = new TextEncoder();
const ITER = 100_000; // the most Workers allows for PBKDF2
const b64u = u => b64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => unb64(s.replace(/-/g, '+').replace(/_/g, '/'));
const MAX_FAILS = 5, LOCK_MS = 60_000;

async function derive(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
function same(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
export async function hashPassword(pw) { const salt = crypto.getRandomValues(new Uint8Array(16)); return `pbkdf2$${ITER}$${b64(salt)}$${b64(await derive(pw, salt, ITER))}`; }
export async function checkPassword(pw, stored) {
  const [alg, it, s, k] = String(stored).split('$'); if (alg !== 'pbkdf2') return false;
  return same(await derive(pw, unb64(s), +it), unb64(k));
}
const DUMMY = 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

export class Auth {
  /** storage: Durable Object storage. secretB64: HMAC key for tokens. */
  constructor(storage, secretB64, { now = () => Date.now(), ttlMs = 8 * 3600_000 } = {}) { this.s = storage; this.secretB64 = secretB64; this.now = now; this.ttlMs = ttlMs; this.users = new Map(); this.fails = new Map(); }
  async init() { for (const [, u] of await this.s.list({ prefix: 'user:' })) this.users.set(u.username, u); }
  #key(usage) { return crypto.subtle.importKey('raw', unb64(this.secretB64), { name: 'HMAC', hash: 'SHA-256' }, false, [usage]); }

  async addUser(username, password, role) {
    if (!/^[a-z0-9_.-]{3,32}$/i.test(username || '')) throw new AuthError('username must be 3 to 32 letters, digits, dot, dash or underscore', 400);
    if (!PERMS[role]) throw new AuthError('role must be one of ' + Object.keys(PERMS).join(', '), 400);
    if (typeof password !== 'string' || password.length < 10) throw new AuthError('password must be at least 10 characters', 400);
    if (this.users.has(username)) throw new AuthError('user already exists', 409);
    const u = { username, role, hash: await hashPassword(password), created: new Date(this.now()).toISOString() };
    this.users.set(username, u); await this.s.put('user:' + username, u); return { username, role };
  }
  async removeUser(username) {
    const u = this.users.get(username); if (!u) throw new AuthError('user not found', 404);
    if (u.role === 'admin' && [...this.users.values()].filter(x => x.role === 'admin').length === 1) throw new AuthError('cannot remove the last admin', 409);
    this.users.delete(username); await this.s.delete('user:' + username);
  }
  list() { return [...this.users.values()].map(({ username, role, created }) => ({ username, role, created })); }

  async login(username, password, ip = '') {
    const key = ip + '|' + username, f = this.fails.get(key);
    if (f && f.until > this.now()) throw new AuthError('too many failed attempts; try again in a minute', 429);
    const u = this.users.get(username);
    const ok = await checkPassword(String(password ?? ''), u ? u.hash : DUMMY); // an unknown user costs the same time as a wrong password
    if (!u || !ok) {
      const expired = f && f.until && f.until <= this.now(), n = (expired ? 0 : f?.n || 0) + 1;
      this.fails.set(key, { n, until: n >= MAX_FAILS ? this.now() + LOCK_MS : 0 });
      throw new AuthError('wrong username or password');
    }
    this.fails.delete(key); return this.issue(u);
  }
  async issue(u) {
    const exp = this.now() + this.ttlMs, payload = b64u(enc.encode(JSON.stringify({ sub: u.username, role: u.role, exp })));
    const mac = b64u(await crypto.subtle.sign('HMAC', await this.#key('sign'), enc.encode(payload)));
    return { token: payload + '.' + mac, role: u.role, username: u.username, exp };
  }
  /** { sub, role } for a valid, unexpired token whose user still exists, else null. Role comes from the live user record. */
  async verifyToken(token) {
    const [payload, mac] = String(token || '').split('.'); if (!payload || !mac) return null;
    let ok = false; try { ok = await crypto.subtle.verify('HMAC', await this.#key('verify'), unb64u(mac), enc.encode(payload)); } catch {}
    if (!ok) return null;
    let p; try { p = JSON.parse(new TextDecoder().decode(unb64u(payload))); } catch { return null; }
    if (!p.exp || p.exp < this.now()) return null;
    const u = this.users.get(p.sub); return u ? { sub: u.username, role: u.role } : null;
  }
}
