// RapidPass engine for Cloudflare Workers: WebCrypto only (no Node APIs), state in Durable Object storage.
// Same rules as src/rapidpass.js: signed passes, dispatch status decides priority, counters stop replays,
// every decision lands in a hash-chained audit log.

const enc = new TextEncoder();
export const b64 = u => { let s = ''; for (const x of new Uint8Array(u)) s += String.fromCharCode(x); return btoa(s); };
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const canon = v => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);
const ED = { name: 'Ed25519' };
export const sha256 = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))].map(x => x.toString(16).padStart(2, '0')).join('');
const newPair = async () => { const k = await crypto.subtle.generateKey(ED, true, ['sign', 'verify']); return { priv: b64(await crypto.subtle.exportKey('pkcs8', k.privateKey)), pub: b64(await crypto.subtle.exportKey('spki', k.publicKey)) }; };
const privKey = b => crypto.subtle.importKey('pkcs8', unb64(b), ED, false, ['sign']);
const pubKey = b => crypto.subtle.importKey('spki', unb64(b), ED, false, ['verify']);
const sign = async (obj, privB64) => b64(await crypto.subtle.sign(ED, await privKey(privB64), enc.encode(canon(obj))));
const check = async (obj, sig, pubB64) => { try { return await crypto.subtle.verify(ED, await pubKey(pubB64), unb64(sig), enc.encode(canon(obj))); } catch { return false; } };

export class EngineError extends Error { constructor(message, status = 400) { super(message); this.status = status; } }

const PRIORITY = new Set(['enroute', 'patient']);
const STATUSES = ['enroute', 'patient', 'returning', 'available'];
const MAX_SKEW_MS = 5000, DEFAULT_TTL_MS = 2 * 3600_000;
const pad = n => String(n).padStart(8, '0');

export class Engine {
  /** storage: Durable Object storage (get, put, list). now: injectable clock for tests. */
  constructor(storage, { now = () => Date.now() } = {}) { this.s = storage; this.now = now; this.incidents = new Map(); this.auditLen = 0; this.auditHead = 'GENESIS'; }

  async init() {
    let meta = await this.s.get('meta');
    if (!meta) { const a = await newPair(); meta = { seq: 0, authorityPriv: a.priv, authorityPub: a.pub, tokenSecret: b64(crypto.getRandomValues(new Uint8Array(32))) }; await this.s.put('meta', meta); }
    this.meta = meta;
    for (const [, inc] of await this.s.list({ prefix: 'inc:' })) this.incidents.set(inc.id, inc);
    const chain = await this.verifyChain(); // refuse to serve a tampered log
    if (!chain.ok) throw new EngineError('audit chain broken at entry ' + chain.brokenAt + '; refusing to serve', 503);
    this.auditLen = chain.length; this.auditHead = chain.head;
  }

  get authorityPublicKey() { return this.meta.authorityPub; }
  get tokenSecret() { return this.meta.tokenSecret; }

  async log(type, data) {
    const body = { seq: this.auditLen + 1, ts: new Date(this.now()).toISOString(), type, data };
    const entry = { ...body, prev: this.auditHead, hash: await sha256(this.auditHead + canon(body)) };
    await this.s.put('audit:' + pad(entry.seq), entry);
    this.auditLen = entry.seq; this.auditHead = entry.hash; return entry;
  }
  /** Re-read the whole log from storage and check every link. */
  async verifyChain() {
    let prev = 'GENESIS', n = 0;
    for (const [, e] of await this.s.list({ prefix: 'audit:' })) {
      const { prev: p, hash, ...body } = e;
      if (p !== prev || await sha256(prev + canon(body)) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash; n = e.seq;
    }
    return { ok: true, length: n, head: prev };
  }
  async auditPage(limit = 200) { return [...(await this.s.list({ prefix: 'audit:', reverse: true, limit })).values()]; }

  view(i) { return { id: i.id, type: i.type, location: i.location, active: i.active, openedAt: i.openedAt, vehicles: Object.values(i.vehicles).map(v => ({ plate: v.plate, agency: v.agency, cls: v.cls, status: v.status, kid: v.credential.kid, exp: v.credential.exp, revoked: !!v.revoked })) }; }
  list() { return [...this.incidents.values()].map(i => this.view(i)); }
  #active(id) { const i = this.incidents.get(id); if (!i) throw new EngineError('incident not found', 404); if (!i.active) throw new EngineError('incident is closed', 409); return i; }
  #save(i) { return this.s.put('inc:' + i.id, i); }

  async createIncident({ type = 'medical', location = '' } = {}, actor) {
    const seq = ++this.meta.seq; await this.s.put('meta', this.meta);
    const i = { id: 'INC-' + (2400 + seq), type, location, active: true, openedAt: new Date(this.now()).toISOString(), vehicles: {} };
    this.incidents.set(i.id, i); await this.#save(i); await this.log('INCIDENT_OPENED', { id: i.id, type, location, actor }); return this.view(i);
  }

  async issuePass(incId, { plate, agency = 'unknown', cls = 'ambulance', ttlMs = DEFAULT_TTL_MS } = {}, actor) {
    const i = this.#active(incId); if (!plate) throw new EngineError('plate is required'); if (i.vehicles[plate]) throw new EngineError('vehicle already has a pass on this incident', 409);
    const dev = await newPair(), t = this.now();
    const c = { v: 1, kid: `${incId}:${plate}`, plate, agency, cls, incident: incId, devicePub: dev.pub, nbf: t, exp: t + ttlMs };
    const credential = { ...c, sig: await sign(c, this.meta.authorityPriv) };
    i.vehicles[plate] = { plate, agency, cls, status: 'enroute', credential, devicePriv: dev.priv, lastCtr: 0, revoked: false };
    await this.#save(i); await this.log('PASS_ISSUED', { incident: incId, plate, agency, cls, kid: c.kid, exp: c.exp, actor }); return { credential };
  }

  async setStatus(incId, plate, status, actor) {
    if (!STATUSES.includes(status)) throw new EngineError('status must be one of ' + STATUSES.join(', '));
    const i = this.#active(incId), v = i.vehicles[plate]; if (!v) throw new EngineError('vehicle not on this incident', 404);
    v.status = status; await this.#save(i); await this.log('STATUS_CHANGED', { incident: incId, plate, status, actor }); return this.view(i);
  }

  async closeIncident(incId, actor) {
    const i = this.#active(incId); i.active = false; for (const v of Object.values(i.vehicles)) v.revoked = true;
    await this.#save(i); await this.log('INCIDENT_CLOSED', { id: incId, revoked: Object.keys(i.vehicles).length, actor }); return this.view(i);
  }

  async #decide(m) {
    if (!m || !m.cred || typeof m.ctr !== 'number' || typeof m.ts !== 'number') return { ok: false, reason: 'MALFORMED', alert: false };
    const { sig: cs, ...cred } = m.cred;
    if (!await check(cred, cs, this.meta.authorityPub)) return { ok: false, reason: 'BAD_CREDENTIAL_SIGNATURE', alert: true };
    const t = this.now();
    if (t < cred.nbf || t > cred.exp) return { ok: false, reason: 'CREDENTIAL_EXPIRED', alert: false };
    const inc = this.incidents.get(cred.incident), v = inc && inc.vehicles[cred.plate];
    if (v && v.revoked) return { ok: false, reason: 'CREDENTIAL_REVOKED', alert: false };
    if (!inc || !inc.active || !v) return { ok: false, reason: 'NOT_DISPATCHED', alert: false };
    if (!PRIORITY.has(v.status)) return { ok: false, reason: 'STATUS_NOT_PRIORITY', alert: false };
    const body = { plate: m.plate, incident: m.incident, ctr: m.ctr, ts: m.ts };
    if (m.plate !== cred.plate || m.incident !== cred.incident || !await check(body, m.sig, cred.devicePub)) return { ok: false, reason: 'BAD_MESSAGE_SIGNATURE', alert: true };
    if (Math.abs(t - m.ts) > MAX_SKEW_MS) return { ok: false, reason: 'STALE_MESSAGE', alert: false };
    if (m.ctr <= v.lastCtr) return { ok: false, reason: 'REPLAY', alert: true };
    v.lastCtr = m.ctr; await this.#save(inc); // counter is persisted before we answer, so a replay can never slip through
    return { ok: true, reason: 'OK', alert: false };
  }
  async verify(m, site = 'unit') { const r = await this.#decide(m); await this.log(r.ok ? 'VERIFY_ACCEPTED' : 'VERIFY_REJECTED', { site, plate: m && m.plate || null, reason: r.reason, alert: r.alert }); return r; }

  async #message(cred, privB64, ctr) { const body = { plate: cred.plate, incident: cred.incident, ctr, ts: this.now() }; return { cred, ...body, sig: await sign(body, privB64) }; }
  /** Demo only: act as a vehicle. mode is valid, replay, forged or wrongkey. */
  async simulate(plate, mode, site = 'unit') {
    let v = null; for (const i of this.incidents.values()) if (i.vehicles[plate]) v = i.vehicles[plate];
    if (!v) throw new EngineError('unknown plate; issue a pass first', 404);
    this.sim ||= new Map(); const s = this.sim.get(plate) || { ctr: 0, last: null }; this.sim.set(plate, s); s.ctr = Math.max(s.ctr, v.lastCtr);
    let msg;
    if (mode === 'valid') { msg = await this.#message(v.credential, v.devicePriv, ++s.ctr); s.last = msg; }
    else if (mode === 'replay') { if (!s.last) throw new EngineError('send a valid message first, then replay it', 409); msg = s.last; }
    else if (mode === 'forged') msg = await this.#message({ ...v.credential, cls: 'fire' }, v.devicePriv, ++s.ctr);
    else if (mode === 'wrongkey') msg = await this.#message(v.credential, (await newPair()).priv, ++s.ctr);
    else throw new EngineError('mode must be valid, replay, forged or wrongkey');
    return { mode, ...await this.verify(msg, site) };
  }
}
