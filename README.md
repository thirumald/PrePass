# RapidPass

Priority-pass service for emergency vehicles, built to feed the smart speed breaker platform. A speed breaker lowers only when two independent signals agree, and RapidPass is the credential signal: it proves a vehicle is on an active dispatch, and it rejects clones, replays and vehicles that are not on a priority call.

## How it works

- **Dispatch opens an incident** and issues each responding vehicle a pass: an Ed25519-signed credential bound to a device key, valid for a time window.
- **The vehicle sends the roadside unit** the credential plus a message signed with its device key, carrying a one-time counter and timestamp.
- **The edge verifier** (`POST /api/verify`) checks, in order: credential signature, validity window, revocation, active incident and priority status, message signature, clock skew, then counter. A counter that does not increase is a replay.
- **Dispatch status decides priority.** Only `enroute` and `patient` are accepted; `returning` and `available` are not, even with a valid credential.
- **Closing an incident revokes its passes.**
- **Every decision is audited** in a hash-chained log, so edited entries are detectable (`GET /api/audit`).

Rejections with a forged credential, a wrong device key or a replay set `alert: true` so the caller can notify police.

## Operations console (GitHub Pages)

`index.html` is one self-contained page with everything in it:

- **Live, Units, Incidents, Analytics, Alarms, Settings**: the operations console and its speed-breaker simulator, now with 28 scripted scenarios covering 31 of the 37 use cases (queues, broken-down vehicles, pedestrians, cyclists, replay and platform attacks, flood, sand and heat, night, stuck flush, sensor disagreement, event, evacuation and maintenance modes).
- **Map**: a 3D Abu Dhabi map (MapLibre and OpenFreeMap) with hospitals, civil defence stations, traffic jams, closures and roadworks, 3D delay towers, OpenStreetMap speed bumps, and all 37 use cases placed as data points. Each use-case popup shows the risk, the solution, real data found near the point, and a button that opens the matching scripted scenario in Live. The corridor planner routes between a station and a hospital, counts the speed bumps on the way, and can run a RapidPass corridor: a vehicle drives the route and the pass engine verifies it at every bump.
- **Drone docks** (in the Map view): docking stations on traffic-signal poles, where drones land, recharge and launch again. Dock sites are picked from real OpenStreetMap signal poles so they cover hospitals, civil defence stations and today's jams and closures. You can send a drone to an incident and compare its arrival time with a ground crew's routed time, and tick "Drone escort" on a corridor run so a drone confirms each speed-bump zone is clear before the pass engine lowers it (the sightings are simulated). Privacy rules are enforced before launch: an allowed purpose is required, faces and plates must be blurred on board, flights into airport no-fly buffers are refused, and footage retention is set (the app itself stores no video or personal data). Every flight, including refused ones, goes in a public flight register and the Passes audit log.
- **Passes**: the signed-pass system running in the browser with WebCrypto: open an incident, issue a pass, simulate valid, replayed, forged or wrong-key messages, and read the hash-chained audit log.

Traffic data: a real TomTom snapshot (2026-10-23) is embedded. With a TomTom key the Map switches to live incidents, a live traffic-flow layer, per-hospital speeds and traffic-aware routing. A public demo key is built in; paste your own in the Map panel to override it, or open `#key=YOUR_KEY` once.

Speed bumps come from OpenStreetMap through the Overpass API and may be incomplete. Use-case markers sit at illustrative sites. It needs a browser with Ed25519 in WebCrypto (current Chrome, Edge, Firefox, or Safari 17+).

To publish: Settings, Pages, Source "GitHub Actions". `.github/workflows/deploy.yml` publishes `index.html` on every push to `main`. The site is at https://thirumald.github.io/RapidPass/.

## Backend (Node server)

`src/server.js` is the persistent, login-protected API behind the Passes view. No dependencies, Node 20 or later.

- **Persistence:** one JSON file (`DATA_FILE`), written atomically. It holds the signing key, incidents, passes, revocations, users and the audit log. On start the audit chain is verified and the server refuses to run if it was edited.
- **Logins:** passwords are salted scrypt hashes. Tokens are HMAC-signed and expire after 8 hours. Five wrong attempts lock a user and address for a minute. Removing or demoting a user takes effect immediately.
- **Roles:** `viewer` reads; `edge` (roadside units) only verifies; `operator` reads, verifies and simulates; `dispatcher` also opens incidents, issues passes and closes incidents; `admin` also manages users. Every change is recorded in the audit log with the user's name.
- **First start:** an admin account is created from `ADMIN_USER` and `ADMIN_PASSWORD`. If no password is set, a random one is printed once.
- **Browser access:** set `CORS_ORIGIN` to the site that calls the API (for GitHub Pages, `https://thirumald.github.io`). The API must be served over https.
- **TomTom proxy:** with `TOMTOM_KEY` set, `GET /api/tomtom/traffic|routing|search/...` forwards to TomTom with the key added on the server and a one-minute cache.

```
cp .env.example .env     # then export the variables, or set them in your host
npm start                # http://localhost:3000, serves index.html too
npm test                 # 41 tests: Node server and Workers version
```

### API

| Method | Path | Needs |
|---|---|---|
| POST | `/api/login` | nothing; returns a token |
| GET | `/api/health` | nothing |
| GET | `/api/me` | any login |
| GET | `/api/incidents`, `/api/audit` | read |
| POST | `/api/incidents`, `/api/incidents/:id/vehicles`, `/status`, `/close` | write |
| POST | `/api/verify` | verify |
| POST | `/api/simulate` | simulate (switch off with `ENABLE_SIMULATE=0`) |
| GET, POST, DELETE | `/api/users` | admin |
| GET | `/api/tomtom/*` | read |

Send `Authorization: Bearer <token>`.

### Deploy

**Free option: Cloudflare Workers** (`worker/`). The same API and JSON as the Node server, so the Passes view works with either. It stores everything in one Durable Object (SQLite-backed, available on the free plan), which keeps counters and revocations consistent. It uses only WebCrypto, so it runs on Workers without Node. It was run on the real Workers runtime (`wrangler dev --local`) and through the page, and its 13 tests also run in `npm test`.

1. Create a free Cloudflare account.
2. Create an API token from the "Edit Cloudflare Workers" template, and note your account id.
3. In this repo, Settings, Secrets and variables, Actions, add `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and `RP_ADMIN_PASSWORD` (the first admin's password, at least 10 characters).
4. Actions, "Deploy API to Cloudflare Workers", Run workflow. It tests, then deploys.
5. The API is at `https://rapidpass-api.<your-subdomain>.workers.dev`. Paste that into the Passes view and sign in as `admin`.

To deploy by hand instead: `cd worker && npx wrangler deploy && npx wrangler secret put ADMIN_PASSWORD`. Set `CORS_ORIGIN` in `worker/wrangler.toml` if the page is not on `thirumald.github.io`, and `ENABLE_SIMULATE` to `"0"` for production. An optional `TOMTOM_KEY` secret turns on the server-side proxy.

**Other hosts:** the repo also has a `Dockerfile` and a Render blueprint for the Node server (`src/server.js`). Render's free tier has no persistent disk, so use the Workers version if you want free storage.

## Limits

On Workers, login throttling lives in the object's memory, so it resets when Cloudflare restarts the object, and PBKDF2 is capped at 100,000 rounds. Free-plan request and storage limits apply. The signing key lives in the data file (or Durable Object storage); production would hold it in an HSM or secret manager and rotate certificates. Device keys are also stored so the demo simulator can act as a vehicle; real vehicles would keep theirs. There is no password reset or multi-factor login, and login throttling is in memory, so it resets on restart. Tests run in the Tests workflow on every push.
