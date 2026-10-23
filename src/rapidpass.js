import { createPrivateKey } from 'node:crypto';
import { newKeyPair, signObj, verifyObj, pubFromB64 } from './crypto.js';
import { AuditLog } from './audit.js';

const PRIORITY = new Set(['enroute', 'patient']);
const STATUSES = new Set(['enroute', 'patient', 'returning', 'available']);
const MAX_SKEW_MS = 5000;
const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000;

/**
 * Issues signed priority credentials for an active dispatch incident and verifies
 * the messages vehicles send to roadside units. Dispatch status decides priority:
 * a valid credential alone is not enough (returning to station gets none).
 */
export class RapidPass {
  constructor({ now = () => Date.now() } = {}) {
    this.now = now;
    this.authority = newKeyPair();
    this.audit = new AuditLog();
    this.incidents = new Map();
    this.revoked = new Set();
    this.seq = 0;
  }

  get authorityPublicKey() { return this.authority.publicB64; }

  createIncident({ type = 'medical', location = '' } = {}) {
    const id = 'INC-' + String(++this.seq + 2400);
    const inc = { id, type, location, active: true, openedAt: new Date(this.now()).toISOString(), vehicles: new Map() };
    this.incidents.set(id, inc);
    this.audit.append('INCIDENT_OPENED', { id, type, location });
    return this.view(inc);
  }

  /** Issue a pass to a vehicle. The device key stays with the vehicle; the server keeps it only for demo simulation. */
  issuePass(incidentId, { plate, agency = 'unknown', cls = 'ambulance', ttlMs = DEFAULT_TTL_MS }) {
    const inc = this.#active(incidentId);
    if (!plate) throw new RapidPassError('plate is required', 400);
    if (inc.vehicles.has(plate)) throw new RapidPassError('vehicle already has a pass on this incident', 409);
    const device = newKeyPair();
    const t = this.now();
    const cred = { v: 1, kid: `${incidentId}:${plate}`, plate, agency, cls, incident: incidentId, devicePub: device.publicB64, nbf: t, exp: t + ttlMs };
    const credential = { ...cred, sig: signObj(cred, this.authority.privateKey) };
    inc.vehicles.set(plate, { plate, agency, cls, status: 'enroute', credential, device, lastCtr: 0 });
    this.audit.append('PASS_ISSUED', { incident: incidentId, plate, agency, cls, kid: cred.kid, exp: cred.exp });
    return { credential, devicePrivateKey: device.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') };
  }

  setStatus(incidentId, plate, status) {
    if (!STATUSES.has(status)) throw new RapidPassError('status must be one of ' + [...STATUSES].join(', '), 400);
    const v = this.#vehicle(this.#active(incidentId), plate);
    v.status = status;
    this.audit.append('STATUS_CHANGED', { incident: incidentId, plate, status });
    return this.view(this.incidents.get(incidentId));
  }

  /** Closing an incident revokes every pass issued on it. */
  closeIncident(incidentId) {
    const inc = this.#active(incidentId);
    inc.active = false;
    for (const v of inc.vehicles.values()) this.revoked.add(v.credential.kid);
    this.audit.append('INCIDENT_CLOSED', { id: incidentId, revoked: inc.vehicles.size });
    return this.view(inc);
  }

  revoke(kid) {
    this.revoked.add(kid);
    this.audit.append('PASS_REVOKED', { kid });
  }

  /** Message a vehicle device would send: credential plus a counter-stamped signature. */
  static buildMessage(credential, devicePrivateKeyB64, ctr, ts) {
    const body = { plate: credential.plate, incident: credential.incident, ctr, ts };
    const key = RapidPass.privateKeyFromB64(devicePrivateKeyB64);
    return { cred: credential, ...body, sig: signObj(body, key) };
  }
  static privateKeyFromB64(b64) {
    return createPrivateKey({ key: Buffer.from(b64, 'base64'), type: 'pkcs8', format: 'der' });
  }

  /** Edge verification. Returns { ok, reason, alert }. Every decision is audited. */
  verify(msg, site = 'unknown') {
    const r = this.#decide(msg);
    this.audit.append(r.ok ? 'VERIFY_ACCEPTED' : 'VERIFY_REJECTED', { site, plate: msg?.plate ?? null, reason: r.reason, alert: r.alert });
    return r;
  }

  #decide(msg) {
    if (!msg || !msg.cred || typeof msg.ctr !== 'number' || typeof msg.ts !== 'number') return { ok: false, reason: 'MALFORMED', alert: false };
    const { sig: credSig, ...cred } = msg.cred;
    if (!verifyObj(cred, credSig, this.authority.publicKey)) return { ok: false, reason: 'BAD_CREDENTIAL_SIGNATURE', alert: true };
    const t = this.now();
    if (t < cred.nbf || t > cred.exp) return { ok: false, reason: 'CREDENTIAL_EXPIRED', alert: false };
    if (this.revoked.has(cred.kid)) return { ok: false, reason: 'CREDENTIAL_REVOKED', alert: false };
    const inc = this.incidents.get(cred.incident);
    const v = inc?.vehicles.get(cred.plate);
    if (!inc || !inc.active || !v) return { ok: false, reason: 'NOT_DISPATCHED', alert: false };
    if (!PRIORITY.has(v.status)) return { ok: false, reason: 'STATUS_NOT_PRIORITY', alert: false };
    const body = { plate: msg.plate, incident: msg.incident, ctr: msg.ctr, ts: msg.ts };
    if (msg.plate !== cred.plate || msg.incident !== cred.incident || !verifyObj(body, msg.sig, pubFromB64(cred.devicePub))) {
      return { ok: false, reason: 'BAD_MESSAGE_SIGNATURE', alert: true };
    }
    if (Math.abs(t - msg.ts) > MAX_SKEW_MS) return { ok: false, reason: 'STALE_MESSAGE', alert: false };
    if (msg.ctr <= v.lastCtr) return { ok: false, reason: 'REPLAY', alert: true };
    v.lastCtr = msg.ctr;
    return { ok: true, reason: 'OK', alert: false };
  }

  #active(id) {
    const inc = this.incidents.get(id);
    if (!inc) throw new RapidPassError('incident not found', 404);
    if (!inc.active) throw new RapidPassError('incident is closed', 409);
    return inc;
  }
  #vehicle(inc, plate) {
    const v = inc.vehicles.get(plate);
    if (!v) throw new RapidPassError('vehicle not on this incident', 404);
    return v;
  }

  view(inc) {
    return {
      id: inc.id, type: inc.type, location: inc.location, active: inc.active, openedAt: inc.openedAt,
      vehicles: [...inc.vehicles.values()].map(v => ({ plate: v.plate, agency: v.agency, cls: v.cls, status: v.status, kid: v.credential.kid, exp: v.credential.exp, revoked: this.revoked.has(v.credential.kid) })),
    };
  }
  list() { return [...this.incidents.values()].map(i => this.view(i)); }
}

export class RapidPassError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
