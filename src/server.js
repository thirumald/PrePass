import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { RapidPass, RapidPassError } from './rapidpass.js';
import { Auth, AuthError, can } from './auth.js';
import { Store } from './store.js';

const PAGES = [fileURLToPath(new URL('../index.html', import.meta.url)), fileURLToPath(new URL('../public/index.html', import.meta.url))];
const TOMTOM_ALLOWED = /^(traffic|routing|search)\//;
const MAX_BODY = 1e6;

/**
 * HTTP API for RapidPass.
 * Every /api route except health and login needs a bearer token; each route also needs a permission
 * that the caller's role grants (see PERMS in auth.js).
 */
export function createApp({ rp = new RapidPass(), auth = new Auth(), store = null, env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const persist = () => { if (store) store.save(() => ({ rp: rp.export(), auth: auth.export() })); };
  const origins = (env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const cache = new Map();

  const routes = [
    // [method, pattern, permission (null = public), handler, mutates]
    ['GET', /^\/api\/health$/, null, () => ({ ok: true, authorityPublicKey: rp.authorityPublicKey, simulate: env.ENABLE_SIMULATE !== '0', tomtomProxy: !!env.TOMTOM_KEY })],
    ['POST', /^\/api\/login$/, null, async ({ body, ip }) => { const r = await auth.login(String(body.username ?? ''), body.password, ip); rp.audit.append('LOGIN', { actor: r.username, ip }); return r; }, true],
    ['GET', /^\/api\/me$/, 'any', ({ user }) => ({ username: user.sub, role: user.role })],
    ['GET', /^\/api\/incidents$/, 'read', () => rp.list()],
    ['POST', /^\/api\/incidents$/, 'write', ({ body, user }) => rp.createIncident(body, user.sub), true],
    ['POST', /^\/api\/incidents\/([^/]+)\/vehicles$/, 'write', ({ params, body, user }) => { const o = rp.issuePass(params[0], body, user.sub); return { credential: o.credential }; }, true],
    ['POST', /^\/api\/incidents\/([^/]+)\/status$/, 'write', ({ params, body, user }) => rp.setStatus(params[0], body.plate, body.status, user.sub), true],
    ['POST', /^\/api\/incidents\/([^/]+)\/close$/, 'write', ({ params, user }) => rp.closeIncident(params[0], user.sub), true],
    ['POST', /^\/api\/verify$/, 'verify', ({ body }) => rp.verify(body.message, body.site), true],
    ['POST', /^\/api\/simulate$/, 'simulate', ({ body, user }) => {
      if (env.ENABLE_SIMULATE === '0') throw new RapidPassError('simulation is disabled on this server', 403);
      return rp.simulate(body.plate, body.mode, body.site || 'S1 EB', user.sub);
    }, true],
    ['GET', /^\/api\/audit$/, 'read', () => ({ chain: rp.audit.verifyChain(), entries: rp.audit.entries.slice(-200).reverse() })],
    ['GET', /^\/api\/users$/, 'admin', () => auth.list()],
    ['POST', /^\/api\/users$/, 'admin', async ({ body, user }) => { const u = await auth.addUser(body.username, body.password, body.role); rp.audit.append('USER_ADDED', { username: u.username, role: u.role, actor: user.sub }); return u; }, true],
    ['DELETE', /^\/api\/users\/([^/]+)$/, 'admin', ({ params, user }) => { auth.removeUser(params[0]); rp.audit.append('USER_REMOVED', { username: params[0], actor: user.sub }); return { ok: true }; }, true],
    ['GET', /^\/api\/tomtom\/(.+)$/, 'read', ({ params, query }) => tomtom(params[0], query)],
  ];

  /** Server-side TomTom proxy: the key stays in the environment and never reaches the browser. */
  async function tomtom(path, query) {
    if (!env.TOMTOM_KEY) throw new RapidPassError('TomTom proxy is not configured (set TOMTOM_KEY)', 503);
    if (!TOMTOM_ALLOWED.test(path) || path.includes('..')) throw new RapidPassError('path not allowed', 400);
    const q = new URLSearchParams(query); q.delete('key'); q.set('key', env.TOMTOM_KEY);
    const url = `https://api.tomtom.com/${path}?${q}`, hit = cache.get(url);
    if (hit && hit.exp > Date.now()) return { __raw: true, ...hit.v };
    const r = await fetchImpl(url);
    const v = { status: r.status, type: r.headers.get('content-type') || 'application/json', body: Buffer.from(await r.arrayBuffer()) };
    if (r.ok) { if (cache.size > 200) cache.delete(cache.keys().next().value); cache.set(url, { exp: Date.now() + 60_000, v }); }
    return { __raw: true, ...v };
  }

  const headers = (req, extra = {}) => {
    const h = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', ...extra };
    const o = req.headers.origin;
    if (o && origins.includes(o)) { h['access-control-allow-origin'] = o; h['vary'] = 'Origin'; h['access-control-allow-headers'] = 'authorization,content-type'; h['access-control-allow-methods'] = 'GET,POST,DELETE,OPTIONS'; }
    return h;
  };

  return createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const send = (status, body, extra = {}) => res.writeHead(status, headers(req, { 'cache-control': 'no-store', ...extra })).end(body);
    const json = (status, obj) => send(status, JSON.stringify(obj), { 'content-type': 'application/json' });
    try {
      if (req.method === 'OPTIONS') return send(204, '');
      if (req.method === 'GET' && url.pathname === '/') {
        for (const f of PAGES) { try { return send(200, await readFile(f), { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' }); } catch {} }
        return json(404, { error: 'no page' });
      }
      for (const [method, re, perm, handler, mutates] of routes) {
        const m = url.pathname.match(re);
        if (req.method !== method || !m) continue;
        let user = null;
        if (perm) {
          const h = req.headers.authorization || '';
          user = auth.verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');
          if (!user) throw new AuthError('login required');
          if (perm !== 'any' && !can(user.role, perm)) throw new AuthError(`role "${user.role}" may not do this (needs ${perm})`, 403);
        }
        const body = method === 'POST' ? await readJson(req) : {};
        const out = await handler({ params: m.slice(1).map(decodeURIComponent), body, query: url.searchParams, user, ip: req.socket.remoteAddress || '' });
        if (mutates) persist();
        if (out && out.__raw) return send(out.status, out.body, { 'content-type': out.type });
        return json(200, out);
      }
      json(404, { error: 'not found' });
    } catch (e) {
      const status = e.status ?? (e instanceof SyntaxError ? 400 : 500);
      if (status === 500) console.error(e);
      json(status, { error: status === 500 ? 'internal error' : e.message });
    }
  });
}

async function readJson(req) {
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (raw.length > MAX_BODY) throw new RapidPassError('body too large', 413); }
  return raw ? JSON.parse(raw) : {};
}

/** Load saved state (or start fresh), make sure an admin exists, and return a ready app. */
export async function bootstrap(env = process.env) {
  const store = new Store(env.DATA_FILE || 'var/rapidpass.json');
  const saved = await store.load();
  const rp = saved ? RapidPass.import(saved.rp) : new RapidPass();
  const auth = new Auth({ secret: saved?.auth?.secret, users: saved?.auth?.users || [] });
  let notice = '';
  if (!auth.users.size) {
    const password = env.ADMIN_PASSWORD || randomBytes(12).toString('base64url');
    await auth.addUser(env.ADMIN_USER || 'admin', password, 'admin');
    notice = `Created admin user "${env.ADMIN_USER || 'admin'}"` + (env.ADMIN_PASSWORD ? '.' : ` with one-time password: ${password}`);
    store.save(() => ({ rp: rp.export(), auth: auth.export() }), 0);
  }
  return { app: createApp({ rp, auth, store, env }), store, notice };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { app, store, notice } = await bootstrap();
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => { console.log(`RapidPass listening on http://localhost:${port}`); if (notice) console.log(notice); });
  const stop = async () => { await store.flush(); process.exit(0); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
