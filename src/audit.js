import { canon, sha256 } from './crypto.js';

/** Append-only log where each entry commits to the previous one, so edits are detectable. */
export class AuditLog {
  constructor(entries = []) { this.entries = entries; }

  append(type, data) {
    const prev = this.entries.length ? this.entries[this.entries.length - 1].hash : 'GENESIS';
    const body = { seq: this.entries.length + 1, ts: new Date().toISOString(), type, data };
    const entry = { ...body, prev, hash: sha256(prev + canon(body)) };
    this.entries.push(entry);
    return entry;
  }

  verifyChain() {
    let prev = 'GENESIS';
    for (const e of this.entries) {
      const { prev: p, hash, ...body } = e;
      if (p !== prev || sha256(prev + canon(body)) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash;
    }
    return { ok: true, length: this.entries.length };
  }
}
