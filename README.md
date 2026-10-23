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

## Abu Dhabi map (GitHub Pages)

`map.html` is a static 3D map of Abu Dhabi built with MapLibre and OpenFreeMap. It shows hospitals, civil defence stations, traffic jams, closures and roadworks, with 3D delay towers, plus OpenStreetMap speed bumps and a corridor planner that counts the bumps on a route and estimates the time a RapidPass corridor could save.

- **Without a key** it shows a real snapshot in `data/snapshot.json`, captured from TomTom on 2026-10-23, clearly labelled as a snapshot.
- **With a TomTom key** (pasted in the page, stored only in the browser) it switches to live incidents, a live traffic-flow layer, per-hospital speeds and traffic-aware routing, refreshing every 2 minutes.
- Speed bumps come from OpenStreetMap through the Overpass API and may be incomplete.

`passes.html` is a static copy of the pass system that runs in the browser with WebCrypto, so GitHub Pages can serve it. In the repo go to Settings, Pages, and set Source to "GitHub Actions". The workflow in `.github/workflows/deploy.yml` publishes `index.html`, `map.html`, `passes.html` and `data/` on every push to `main`. The Operations Console is at https://thirumald.github.io/RapidPass/, the Abu Dhabi map at https://thirumald.github.io/RapidPass/map.html and the pass demo at https://thirumald.github.io/RapidPass/passes.html. It needs a browser with Ed25519 in WebCrypto (current Chrome, Edge, Firefox, or Safari 17+).

## Run the Node server

Needs Node 20 or later. No dependencies.

```
npm start     # http://localhost:3000
npm test
```

The page at `/` walks through open incident, issue pass, then simulate a vehicle (valid, replay, forged, wrong key).

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/incidents` | Open an incident `{type, location}` |
| GET | `/api/incidents` | List incidents and vehicles |
| POST | `/api/incidents/:id/vehicles` | Issue a pass `{plate, agency, cls}` |
| POST | `/api/incidents/:id/status` | Set status `{plate, status}` |
| POST | `/api/incidents/:id/close` | Close incident and revoke passes |
| POST | `/api/verify` | Edge check `{message, site}` |
| POST | `/api/simulate` | Demo only: act as a vehicle `{plate, mode}` |
| GET | `/api/audit` | Audit log and chain check |

## Limits

This is a working prototype, not a deployed system. State is in memory and lost on restart. The server keeps device keys so `/api/simulate` can act as a vehicle; a real deployment would keep them on the vehicle only. There is no authentication on the API and no persistence. The authority key is generated at start-up; production would use an HSM-held key with rotating certificates.
