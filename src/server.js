import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { RapidPass, RapidPassError } from './rapidpass.js';
import { newKeyPair } from './crypto.js';

const PAGE = fileURLToPath(new URL('../public/index.html', import.meta.url));

export function createApp(rp = new RapidPass()) {
  // Demo-only: the vehicle-side secrets and last message per plate, so the UI can simulate a vehicle.
  const sim = new Map();

  const routes = [
    ['GET', /^\/api\/health$/, () => ({ ok: true, authorityPublicKey: rp.authorityPublicKey })],
    ['GET', /^\/api\/incidents$/, () => rp.list()],
    ['POST', /^\/api\/incidents$/, ({ body }) => rp.createIncident(body)],
    ['POST', /^\/api\/incidents\/([^/]+)\/vehicles$/, ({ params, body }) => {
      const out = rp.issuePass(params[0], body);
      sim.set(out.credential.plate, { credential: out.credential, key: out.devicePrivateKey, ctr: 0, last: null });
      return { credential: out.credential };
    }],
    ['POST', /^\/api\/incidents\/([^/]+)\/status$/, ({ params, body }) => rp.setStatus(params[0], body.plate, body.status)],
    ['POST', /^\/api\/incidents\/([^/]+)\/close$/, ({ params }) => rp.closeIncident(params[0])],
    ['POST', /^\/api\/verify$/, ({ body }) => rp.verify(body.message, body.site)],
    ['POST', /^\/api\/simulate$/, ({ body }) => simulate(rp, sim, body)],
    ['GET', /^\/api\/audit$/, () => ({ chain: rp.audit.verifyChain(), entries: rp.audit.entries.slice(-200).reverse() })],
  ];

  return createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    try {
      if (req.method === 'GET' && url.pathname === '/') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(await readFile(PAGE));
        return;
      }
      for (const [method, re, handler] of routes) {
        const m = url.pathname.match(re);
        if (req.method === method && m) {
          const body = method === 'POST' ? await readJson(req) : {};
          const out = handler({ params: m.slice(1).map(decodeURIComponent), body });
          res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out));
          return;
        }
      }
      res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'not found' }));
    } catch (e) {
      const status = e instanceof RapidPassError ? e.status : e instanceof SyntaxError ? 400 : 500;
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: e.message }));
    }
  });
}

function simulate(rp, sim, { plate, mode = 'valid', site = 'S1 EB' }) {
  const s = sim.get(plate);
  if (!s) throw new RapidPassError('unknown plate; issue a pass first', 404);
  let msg;
  if (mode === 'valid') {
    msg = RapidPass.buildMessage(s.credential, s.key, ++s.ctr, Date.now());
    s.last = msg;
  } else if (mode === 'replay') {
    if (!s.last) throw new RapidPassError('send a valid message first, then replay it', 409);
    msg = s.last;
  } else if (mode === 'forged') {
    msg = RapidPass.buildMessage({ ...s.credential, cls: 'fire' }, s.key, ++s.ctr, Date.now());
  } else if (mode === 'wrongkey') {
    msg = RapidPass.buildMessage(s.credential, attackerKey(sim), ++s.ctr, Date.now());
  } else throw new RapidPassError('mode must be valid, replay, forged or wrongkey', 400);
  return { mode, ...rp.verify(msg, site) };
}

function attackerKey(sim) {
  if (!sim.has('__attacker')) sim.set('__attacker', { key: newKeyPair().privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') });
  return sim.get('__attacker').key;
}

async function readJson(req) {
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (raw.length > 1e6) throw new RapidPassError('body too large', 413); }
  return raw ? JSON.parse(raw) : {};
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT) || 3000;
  createApp().listen(port, () => console.log(`RapidPass listening on http://localhost:${port}`));
}
