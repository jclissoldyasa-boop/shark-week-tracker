# Shark Week Tracker

Private period and cycle tracker focused on cycle tracking and health optimisation (not pregnancy).
Web app + Android app, one account, data synced between devices and end-to-end encrypted.

**Live:** https://shark-week.shark-week-server.workers.dev — landing page at `/`, the app at `/app`,
Android APK at `/download/SharkWeek.apk` (also attached to every GitHub release).

- `app.html` — the whole app (single page, no external scripts or fonts), served at `/app`
- `landing.html` — the promo page at `/` (no scripts); screenshots in `web/img/`
- `legal/` — Privacy Policy and Terms (filled in from `site.json`)
- `server/` — Cloudflare Worker + D1 database (accounts, encrypted sync, security headers)
- `android/` — WebView shell (reminders, privacy screen, file export); `./build.sh` → `SharkWeek.apk`
- `site.json` — app name, public host, operator name, contact email, state

## Features
Today ring (cycle day, phase, next period, fertile window), quick "period started/ended", daily log
(flow, 20 symptoms, pain 0–10, mood, energy, stress, sleep, BBT, cervical mucus, ovulation tests, sex drive,
exercise, water/alcohol/caffeine, meds, notes), calendar with predictions and an "edit period days" mode,
Insights (cycle & period length charts, symptom-by-cycle-day heatmap, energy/sleep/stress/pain by cycle day,
BBT chart with three-over-six ovulation detection, plain-English pattern notes), phase-based health tips,
"worth a chat with your GP" flags (healthdirect/Jean Hailes thresholds), printable doctor summary,
JSON/CSV export, account deletion, devices list, Android reminders (optionally discreet).

## Updates
`./release.sh "What changed"` builds a new APK (version code = minutes since 1970), deploys the site/API,
publishes the APK and `/version.json`, pushes to GitHub and creates a release.
- **Android app:** checks `/version.json` on start, on resume (every 6 h) and from *Me → Check for updates*.
  A newer version code shows an *Update* banner that downloads the APK; Android installs it over the old one
  (same signing key).
- **Web app:** each build carries a hash of the page; a different hash in `/version.json` shows *Reload*.

## Encryption (zero-knowledge)
1. On the device: `PBKDF2-SHA256(password, salt, 600k)` → HKDF → **login key** (sent) and **wrap key** (never sent).
2. A random 64-byte data key (AES-256-GCM key + HMAC key) is generated at signup, encrypted with the wrap key
   and with a key from the 125-bit **recovery code**; only those encrypted copies are stored.
3. Each day's log / settings is a document: JSON padded to 256 bytes, AES-256-GCM, with the document id as
   associated data. Document ids are HMACs of `day:YYYY-MM-DD`, so the server can't see which dates exist.
4. Server stores `HMAC(AUTH_PEPPER, login key)`. Lose password **and** recovery code = data unrecoverable (by design).

## Row-level security
D1 is SQLite, which has no built-in RLS, so it is enforced in one place: `rowsFor(env, userId)` in
`server/src/worker.js` is the only code that touches a user's rows, and the user id comes from the verified
session. `test/rls.test.mjs` (also run before every deploy) fails if any SQL on `users/docs/sessions` isn't
pinned to a user; `test/api.test.mjs` attacks cross-account reads/writes against a running server.
On top of that, the data is ciphertext, so even a bypass would leak nothing readable.

## Australian compliance notes
- Privacy Act 1988 / APPs: express consent for sensitive (health) info at signup (APP 3), policy covering
  APP 1/5/6/8/11/12/13, OAIC complaints, Notifiable Data Breaches; consent re-asked when `TERMS_VERSION` changes.
- Data minimisation: email only; no analytics, ads, trackers, third-party scripts or fonts.
- Storage: D1 created with `--location oc` (Oceania). Cloudflare is disclosed as an overseas recipient (APP 8).
- TGA: positioned as general wellbeing — no contraception/diagnosis claims; disclaimers in app and Terms.
- Accessibility (WCAG 2.1 AA aims): labelled controls, 44px targets, colour never the only cue, light/dark,
  table view for every chart. Age: 16+.
- Security: CSP with script hashes only, HSTS, no framing, same-origin checks, rate limits, 90-day idle
  session expiry, devices list + sign out others; Android FLAG_SECURE and no backups.

## Run locally
```
cd server && npm install
echo "AUTH_PEPPER=$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))')" > .dev.vars
npm run dev            # http://127.0.0.1:8787
node test/api.test.mjs # in another terminal
```

## Deploy
The Cloudflare login for this project lives in `server/.cf-home` (gitignored), separate from any other
wrangler login on the machine. To log in again: `cd server && XDG_CONFIG_HOME=$PWD/.cf-home npx wrangler login`.

### First time on a new account
```
cd server
npx wrangler d1 create shark-week --location oc     # put the database_id into wrangler.jsonc
node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))' | npx wrangler secret put AUTH_PEPPER
npm run deploy                                      # builds, RLS check, migrations, deploy
```
Then set `host` in `site.json` to the deployed address, `npm run deploy` again, and `cd ../android && ./build.sh`.
**Never change or lose `AUTH_PEPPER`** (everyone would be locked out) **or `android/sharkweek.keystore`**.
