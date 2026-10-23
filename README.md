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

## Live demo (GitHub Pages)

`index.html` in the repo root is a static copy that runs the whole system in the browser with WebCrypto, so GitHub Pages can serve it. In the repo go to Settings, Pages, set Source to "Deploy from a branch", branch `main`, folder `/ (root)`. The site is then at https://thirumald.github.io/RapidPass/. It needs a browser with Ed25519 in WebCrypto (current Chrome, Edge, Firefox, or Safari 17+).

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
