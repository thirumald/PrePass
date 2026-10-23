import { generateKeyPairSync, createHash, sign, verify, createPublicKey, createPrivateKey } from 'node:crypto';

/** Deterministic JSON so signatures do not depend on key order. */
export function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    // undefined values are skipped, as JSON.stringify does, so a hash survives a save and reload
    return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

export function newKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicB64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
}

export const pubFromB64 = b64 => createPublicKey({ key: Buffer.from(b64, 'base64'), type: 'spki', format: 'der' });
export const signObj = (obj, privateKey) => sign(null, Buffer.from(canon(obj)), privateKey).toString('base64');
export function verifyObj(obj, sigB64, publicKey) {
  try { return verify(null, Buffer.from(canon(obj)), publicKey, Buffer.from(sigB64, 'base64')); } catch { return false; }
}
export const sha256 = s => createHash('sha256').update(s).digest('hex');

export const privToB64 = k => k.export({ type: 'pkcs8', format: 'der' }).toString('base64');
/** Rebuild a key pair from a stored PKCS8 private key. */
export function keyPairFromPrivB64(b64) {
  const privateKey = createPrivateKey({ key: Buffer.from(b64, 'base64'), type: 'pkcs8', format: 'der' });
  const publicKey = createPublicKey(privateKey);
  return { publicKey, privateKey, publicB64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
}
