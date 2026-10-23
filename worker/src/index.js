// RapidPass API on Cloudflare Workers. Same routes and JSON as the Node server (src/server.js), so the page's Server mode works with either.
// One Durable Object holds all state, which makes counters and revocations strongly consistent.
import { Engine, EngineError } from './engine.js';
import { Auth, AuthError, can } from './auth.js';

const TOMTOM_ALLOWED = /^(traffic|routing|search)\//;
const MAX_BODY = 1_000_000;

export class RapidPassDO {
  constructor(state, env) {
    this.env = env; this.cache = new Map(); this.fatal = null;
    this.state = state;
    state.blockConcurrencyWhile(async () => {
      try {
        this.engine = new Engine(state.storage); await this.engine.init();
        this.auth = new Auth(state.storage, this.engine.tokenSecret); await this.auth.init();
        if (!this.auth.users.size && env.ADMIN_PASSWORD) { // first start: create the admin from the ADMIN_PASSWORD secret
          await this.auth.addUser(env.ADMIN_USER || 'admin', env.ADMIN_PASSWORD, 'admin');
          await this.engine.log('USER_ADDED', { username: env.ADMIN_USER || 'admin', role: 'admin', actor: 'bootstrap' });
        }
      } catch (e) { this.fatal = e; } // never throw here: that would restart the object in a loop
    });
  }

  json(status, obj) { return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }); }

  async fetch(request) {
    try {
      if (this.fatal) return this.json(this.fatal.status || 503, { error: this.fatal.message });
      const url = new URL(request.url), method = request.method, path = url.pathname, env = this.env, ip = request.headers.get('cf-connecting-ip') || '';
      const { engine, auth } = this;
      if (method === 'GET' && path === '/api/health') return this.json(200, { ok: true, authorityPublicKey: engine.authorityPublicKey, simulate: env.ENABLE_SIMULATE !== '0', tomtomProxy: !!env.TOMTOM_KEY, setupNeeded: !auth.users.size });
      if (method === 'POST' && path === '/api/login') {
        const b = await this.body(request); const r = await auth.login(String(b.username ?? ''), b.password, ip);
        await engine.log('LOGIN', { actor: r.username, ip }); return this.json(200, r);
      }
      const h = request.headers.get('authorization') || '';
      const user = await auth.verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');
      if (!user) throw new AuthError('login required');
      const need = (perm) => { if (!can(user.role, perm)) throw new AuthError(`role "${user.role}" may not do this (needs ${perm})`, 403); };
      let m;
      if (method === 'GET' && path === '/api/me') return this.json(200, { username: user.sub, role: user.role });
      if (method === 'GET' && path === '/api/incidents') { need('read'); return this.json(200, engine.list()); }
      if (method === 'POST' && path === '/api/incidents') { need('write'); return this.json(200, await engine.createIncident(await this.body(request), user.sub)); }
      if (method === 'POST' && (m = path.match(/^\/api\/incidents\/([^/]+)\/vehicles$/))) { need('write'); return this.json(200, await engine.issuePass(decodeURIComponent(m[1]), await this.body(request), user.sub)); }
      if (method === 'POST' && (m = path.match(/^\/api\/incidents\/([^/]+)\/status$/))) { need('write'); const b = await this.body(request); return this.json(200, await engine.setStatus(decodeURIComponent(m[1]), b.plate, b.status, user.sub)); }
      if (method === 'POST' && (m = path.match(/^\/api\/incidents\/([^/]+)\/close$/))) { need('write'); return this.json(200, await engine.closeIncident(decodeURIComponent(m[1]), user.sub)); }
      if (method === 'POST' && path === '/api/verify') { need('verify'); const b = await this.body(request); return this.json(200, await engine.verify(b.message, b.site)); }
      if (method === 'POST' && path === '/api/simulate') {
        need('simulate'); if (env.ENABLE_SIMULATE === '0') throw new EngineError('simulation is disabled on this server', 403);
        const b = await this.body(request); return this.json(200, await engine.simulate(b.plate, b.mode, b.site || 'S1 EB'));
      }
      if (method === 'GET' && path === '/api/audit') {
        need('read'); const chain = url.searchParams.get('verify') ? await engine.verifyChain() : { ok: true, length: engine.auditLen };
        return this.json(200, { chain: { ok: chain.ok, length: chain.length, brokenAt: chain.brokenAt }, entries: await engine.auditPage() });
      }
      if (method === 'GET' && path === '/api/users') { need('admin'); return this.json(200, auth.list()); }
      if (method === 'POST' && path === '/api/users') { need('admin'); const b = await this.body(request); const u = await auth.addUser(b.username, b.password, b.role); await engine.log('USER_ADDED', { username: u.username, role: u.role, actor: user.sub }); return this.json(200, u); }
      if (method === 'DELETE' && (m = path.match(/^\/api\/users\/([^/]+)$/))) { need('admin'); const name = decodeURIComponent(m[1]); await auth.removeUser(name); await engine.log('USER_REMOVED', { username: name, actor: user.sub }); return this.json(200, { ok: true }); }
      if (method === 'GET' && (m = path.match(/^\/api\/tomtom\/(.+)$/))) { need('read'); return await this.tomtom(decodeURIComponent(m[1]), url.searchParams); }
      return this.json(404, { error: 'not found' });
    } catch (e) {
      const status = e.status ?? (e instanceof SyntaxError ? 400 : 500);
      if (status === 500) console.error(e);
      return this.json(status, { error: status === 500 ? 'internal error' : e.message });
    }
  }

  async body(request) {
    const text = await request.text(); if (text.length > MAX_BODY) throw new EngineError('body too large', 413);
    return text ? JSON.parse(text) : {};
  }

  /** Server-side TomTom proxy: the key stays in a Worker secret. */
  async tomtom(path, query) {
    if (!this.env.TOMTOM_KEY) throw new EngineError('TomTom proxy is not configured (set the TOMTOM_KEY secret)', 503);
    if (!TOMTOM_ALLOWED.test(path) || path.includes('..')) throw new EngineError('path not allowed', 400);
    const q = new URLSearchParams(query); q.delete('key'); q.set('key', this.env.TOMTOM_KEY);
    const url = `https://api.tomtom.com/${path}?${q}`, hit = this.cache.get(url);
    if (hit && hit.exp > Date.now()) return new Response(hit.body, { status: hit.status, headers: { 'content-type': hit.type, 'cache-control': 'no-store' } });
    const r = await fetch(url), body = await r.arrayBuffer(), type = r.headers.get('content-type') || 'application/json';
    if (r.ok) { if (this.cache.size > 100) this.cache.delete(this.cache.keys().next().value); this.cache.set(url, { exp: Date.now() + 60_000, status: r.status, type, body }); }
    return new Response(body, { status: r.status, headers: { 'content-type': type, 'cache-control': 'no-store' } });
  }
}

/** Add CORS (only for configured origins) and basic security headers. */
function withHeaders(res, request, env) {
  const out = new Response(res.body, res);
  out.headers.set('x-content-type-options', 'nosniff'); out.headers.set('referrer-policy', 'no-referrer');
  const origin = request.headers.get('origin'), allowed = (env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  if (origin && allowed.includes(origin)) {
    out.headers.set('access-control-allow-origin', origin); out.headers.set('vary', 'Origin');
    out.headers.set('access-control-allow-headers', 'authorization,content-type'); out.headers.set('access-control-allow-methods', 'GET,POST,DELETE,OPTIONS');
  }
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return withHeaders(new Response(null, { status: 204 }), request, env);
    if (url.pathname === '/') return withHeaders(new Response(JSON.stringify({ service: 'rapidpass-api', docs: 'https://github.com/thirumald/RapidPass' }), { headers: { 'content-type': 'application/json' } }), request, env);
    if (!url.pathname.startsWith('/api/')) return withHeaders(new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'content-type': 'application/json' } }), request, env);
    const stub = env.RP.get(env.RP.idFromName('main'));
    return withHeaders(await stub.fetch(request), request, env);
  },
};
