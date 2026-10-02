// Shark Week Tracker: accounts and encrypted sync API, plus the web app's pages (./public) with security headers.
//
// Zero-knowledge design: the password never leaves the device. The device derives two keys from it —
// a login key (sent here, stored only as an HMAC with a server-side pepper) and a wrapping key (never
// sent) that encrypts the user's random data key. Health data arrives already encrypted with that data
// key, so this server and its database only ever hold ciphertext.
//
// Row-level security: D1 (SQLite) has no database-enforced RLS, so it is enforced here instead. Every
// read or write of a user's rows goes through rowsFor(), which binds the user id taken from the
// verified session — never from anything the client sends. test/rls.test.mjs fails the build if any
// SQL touching user rows lacks the `user_id = ?` / `id = ?` guard, and test/api.test.mjs tries
// cross-account reads and writes against a running server.

import { CSP, ASSET_LINKS } from "./site.generated.js";

const TERMS_VERSION = "2026-10-03"; // bump when the Terms or Privacy Policy change materially; the app re-asks consent
const SESSION_IDLE = 90 * 864e5;    // sign out a device after 90 days unused
const MAX_BODY = 2_000_000;         // bytes per request
const MAX_DOC = 64_000;             // chars per encrypted document (one day of logs is ~1 KB)
const MAX_BATCH = 200;              // documents per upload
const MAX_DOCS = 40_000;            // ~100 years of daily logs
const PAGE = 500;                   // documents per download page
const MIN_ITER = 300_000;           // device-side PBKDF2 iterations we accept (the app uses 600k, per OWASP 2023+)
const DOC_ID = /^[A-Za-z0-9_-]{22}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESET_TTL = 3600e3;           // email reset links last an hour

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
};
const API_CSP = "default-src 'none'; frame-ancestors 'none'";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/.well-known/assetlinks.json") return json(ASSET_LINKS); // lets the Android app share saved passwords with this site
    if (!url.pathname.startsWith("/api/")) return page(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: SECURITY_HEADERS }); // no CORS: same-site only
    try {
      // Browsers send Origin on cross-site POSTs; refuse those (defence in depth — auth is a bearer token, not a cookie).
      const origin = req.headers.get("Origin");
      if (req.method !== "GET" && origin && origin !== url.origin) throw new HttpError(403, "Not allowed.");
      return await route(req, env, url);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e && e.stack || e); // never logs request bodies
      return json({ error: "Something went wrong. Try again." }, 500);
    }
  },

  // Daily clean-up, matching the retention periods in the Privacy Policy.
  async scheduled(_event, env) {
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE last_seen < ?").bind(now - SESSION_IDLE),
      env.DB.prepare("DELETE FROM attempts WHERE first < ?").bind(now - 864e5),
      env.DB.prepare("DELETE FROM reset_tokens WHERE created < ?").bind(now - RESET_TTL),
    ]);
  },
};

async function page(req, env) {
  const res = await env.ASSETS.fetch(req);
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  const path = new URL(req.url).pathname;
  if (path.endsWith(".apk")) {
    out.headers.set("Content-Type", "application/vnd.android.package-archive");
    out.headers.set("Content-Disposition", 'attachment; filename="SharkWeek.apk"');
    out.headers.set("Cache-Control", "no-cache");
  }
  if (path === "/version.json") out.headers.set("Cache-Control", "no-store");
  if ((out.headers.get("Content-Type") || "").includes("text/html")) {
    out.headers.set("Content-Security-Policy", CSP);
    out.headers.set("Cache-Control", "no-cache");
  }
  return out;
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  if (+(req.headers.get("Content-Length") || 0) > MAX_BODY) throw new HttpError(413, "That request is too large.");
  if (!env.AUTH_PEPPER || env.AUTH_PEPPER.length < 32) throw new Error("AUTH_PEPPER secret is missing");

  if (p === "/api/config" && m === "GET") return json({ terms: TERMS_VERSION, emailReset: hasEmail(env) });
  if (p === "/api/prelogin" && m === "POST") return prelogin(req, env);
  if (p === "/api/signup" && m === "POST") return signup(req, env);
  if (p === "/api/login" && m === "POST") return login(req, env);
  if (p === "/api/recover/key" && m === "POST") return recoverKey(req, env);
  if (p === "/api/recover/reset" && m === "POST") return recoverReset(req, env);
  if (p === "/api/reset/email" && m === "POST") return emailReset(req, env, url);
  if (p === "/api/reset/email/confirm" && m === "POST") return emailResetConfirm(req, env);
  const pm = p.match(/^\/api\/partner\/([A-Za-z0-9_-]{22})$/);
  if (pm && m === "GET") return partnerGet(req, env, pm[1]);
  if (p === "/api/reset/email/peek" && m === "POST") return json({ email: (await resetToken(env, req, (await readJson(req)).token)).email });

  const user = await auth(req, env);
  const rows = rowsFor(env, user.id);
  if (p === "/api/me" && m === "GET") return json(await rows.me());
  if (p === "/api/consent" && m === "POST") { await rows.consent(); return json({ ok: true }); }
  if (p === "/api/logout" && m === "POST") { await rows.endSession(user.tokenHash); return json({ ok: true }); }
  if (p === "/api/sessions" && m === "GET") return json({ sessions: await rows.sessions(user.tokenHash) });
  if (p === "/api/sessions/others" && m === "DELETE") { await rows.endOtherSessions(user.tokenHash); return json({ ok: true }); }
  if (p === "/api/password" && m === "POST") return changePassword(req, env, user, rows);
  if (p === "/api/password/device" && m === "POST") return devicePassword(req, env, user, rows);
  if (p === "/api/keyproof" && m === "POST") { await rows.setKeyProofIfMissing(await proofHash(env, keyProof((await readJson(req)).keyProof))); return json({ ok: true }); }
  if (p === "/api/recovery" && m === "POST") return newRecovery(req, env, user, rows);
  if (p === "/api/account" && m === "DELETE") return deleteAccount(req, env, user, rows);
  if (pm && m === "PUT") { const d = String((await readJson(req, 40000)).data || ""); if (!B64.test(d) || d.length > 30000) throw new HttpError(400, "Bad data."); await rows.putPartner(pm[1], d); return json({ ok: true }); }
  if (pm && m === "DELETE") { await rows.deletePartner(pm[1]); return json({ ok: true }); }
  if (p === "/api/docs" && m === "GET") return json(await rows.docsSince(+url.searchParams.get("since") || 0, url.searchParams.get("after") || ""));
  if (p === "/api/docs" && m === "POST") return putDocs(req, rows);
  throw new HttpError(404, "Not found.");
}

// ---------- Row-level security ----------
//
// The ONLY place that reads or writes a user's rows. `uid` comes from auth() (a verified session).
// Every statement below is pinned to it; keep it that way (test/rls.test.mjs checks).

function rowsFor(env, uid) {
  const db = env.DB;
  if (typeof uid !== "string" || !uid) throw new Error("rowsFor needs a verified user id");
  return {
    async me() {
      const u = await db.prepare("SELECT email, created, terms_version FROM users WHERE id = ?").bind(uid).first();
      const n = await db.prepare("SELECT COUNT(*) AS n FROM docs WHERE user_id = ?").bind(uid).first("n");
      return { email: u.email, created: u.created, consentCurrent: u.terms_version === TERMS_VERSION, terms: TERMS_VERSION, docs: n };
    },
    consent: () => db.prepare("UPDATE users SET terms_version = ?, consented = ? WHERE id = ?").bind(TERMS_VERSION, Date.now(), uid).run(),
    secrets: () => db.prepare("SELECT email, kdf_salt, kdf_iter, auth_hash, wrapped_key, key_proof FROM users WHERE id = ?").bind(uid).first(),
    setKeyProofIfMissing: h => db.prepare("UPDATE users SET key_proof = ? WHERE id = ? AND key_proof IS NULL").bind(h, uid).run(),
    /** Email reset without a recovery code: the old data key is gone, so the old (unreadable) logs go too. */
    restartWithNewKey: (k, rec, proof) => db.batch([
      db.prepare("DELETE FROM docs WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM reset_tokens WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM partner_shares WHERE user_id = ?").bind(uid),
      db.prepare("UPDATE users SET kdf_salt = ?, kdf_iter = ?, auth_hash = ?, wrapped_key = ?, rec_hash = ?, wrapped_rec = ?, key_proof = ? WHERE id = ?")
        .bind(k.salt, k.iter, k.authHash, k.wrapped, rec.hash, rec.wrapped, proof, uid),
    ]),
    async sessions(current) {
      const { results } = await db.prepare("SELECT token_hash, created, last_seen, device FROM sessions WHERE user_id = ? ORDER BY last_seen DESC").bind(uid).all();
      return results.map(r => ({ id: r.token_hash.slice(0, 8), created: r.created, lastSeen: r.last_seen, device: r.device, current: r.token_hash === current }));
    },
    endSession: tokenHash => db.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash = ?").bind(uid, tokenHash).run(),
    endOtherSessions: keep => db.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?").bind(uid, keep).run(),
    setPassword: (k, keep) => db.batch([
      db.prepare("UPDATE users SET kdf_salt = ?, kdf_iter = ?, auth_hash = ?, wrapped_key = ? WHERE id = ?").bind(k.salt, k.iter, k.authHash, k.wrapped, uid),
      db.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?").bind(uid, keep),
    ]),
    setRecovery: (recHash, wrappedRec) => db.prepare("UPDATE users SET rec_hash = ?, wrapped_rec = ? WHERE id = ?").bind(recHash, wrappedRec, uid).run(),
    deleteEverything: () => db.batch([
      db.prepare("DELETE FROM docs WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM reset_tokens WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM partner_shares WHERE user_id = ?").bind(uid),
      db.prepare("DELETE FROM users WHERE id = ?").bind(uid),
    ]),
    async docsSince(since, after) {
      if (after && !DOC_ID.test(after)) throw new HttpError(400, "Bad cursor.");
      const { results } = await db.prepare(
        "SELECT doc_id, data, updated FROM docs WHERE user_id = ? AND (updated > ? OR (updated = ? AND doc_id > ?)) ORDER BY updated, doc_id LIMIT ?"
      ).bind(uid, since, since, after, PAGE).all();
      const last = results[results.length - 1];
      return {
        docs: results.map(r => ({ id: r.doc_id, data: r.data, updated: r.updated })),
        more: results.length === PAGE,
        since: last ? last.updated : since,
        after: last ? last.doc_id : after,
      };
    },
    async putPartner(id, data) {
      const r = await db.prepare(
        "INSERT INTO partner_shares (id, user_id, data, updated) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT (id) DO UPDATE SET data = excluded.data, updated = excluded.updated WHERE partner_shares.user_id = ?"
      ).bind(id, uid, data, Date.now(), uid).run();
      if (!r.meta.changes) throw new HttpError(403, "Not allowed.");
      const n = await db.prepare("SELECT COUNT(*) AS n FROM partner_shares WHERE user_id = ?").bind(uid).first("n");
      if (n > 3) await db.prepare("DELETE FROM partner_shares WHERE user_id = ? AND id NOT IN (SELECT id FROM partner_shares WHERE user_id = ? ORDER BY updated DESC LIMIT 3)").bind(uid, uid).run();
    },
    deletePartner: id => db.prepare("DELETE FROM partner_shares WHERE user_id = ? AND id = ?").bind(uid, id).run(),
    countDocs: () => db.prepare("SELECT COUNT(*) AS n FROM docs WHERE user_id = ?").bind(uid).first("n"),
    putDocs(docs, now) {
      return db.batch(docs.map(d => db.prepare(
        "INSERT INTO docs (user_id, doc_id, data, updated) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT (user_id, doc_id) DO UPDATE SET data = excluded.data, updated = excluded.updated WHERE docs.user_id = ?"
      ).bind(uid, d.id, d.data, now, uid)));
    },
  };
}

// Account lookups by email happen before there is a session (sign-in, recovery); they return only
// what that step needs and are rate limited per email and per connection.
const byEmail = (env, email, cols) => env.DB.prepare(`SELECT ${cols} FROM users WHERE email = ?`).bind(email).first();

// ---------- accounts ----------

/** Returns the salt the device needs to derive its keys. Unknown emails get a stable fake salt, so this can't be used to find accounts. */
async function prelogin(req, env) {
  const email = checkEmail((await readJson(req)).email);
  await limit(env, "pre:" + ip(req), 60, 15 * 60e3, "Too many tries from this connection. Wait 15 minutes and try again.");
  const u = await byEmail(env, email, "kdf_salt, kdf_iter");
  if (u) return json({ salt: u.kdf_salt, iter: u.kdf_iter });
  return json({ salt: (await hmac(env.AUTH_PEPPER, "fake-salt:" + email)).slice(0, 22), iter: 600_000 });
}

async function signup(req, env) {
  const b = await readJson(req);
  const email = checkEmail(b.email);
  if (b.acceptTerms !== true || b.healthConsent !== true) throw new HttpError(400, "Please agree to the Terms, Privacy Policy and the collection of health information.");
  if (b.age16 !== true) throw new HttpError(400, "You need to be 16 or older to create an account.");
  const k = keyMaterial(b);
  const rec = recMaterial(b);
  const proof = await proofHash(env, keyProof(b.keyProof));
  await limit(env, "signup:" + ip(req), 10, 3600e3, "Too many new accounts from this connection. Try again later.");
  if (await byEmail(env, email, "1")) throw new HttpError(409, "There's already an account with that email. Sign in instead.");
  const id = crypto.randomUUID(), now = Date.now();
  await env.DB.prepare(
    "INSERT INTO users (id, email, kdf_salt, kdf_iter, auth_hash, wrapped_key, rec_hash, wrapped_rec, created, terms_version, consented, key_proof) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, email, k.salt, k.iter, await authHash(env, k.auth), k.wrapped, await authHash(env, rec.auth), rec.wrapped, now, TERMS_VERSION, now, proof).run();
  return json({ token: await newSession(env, req, id), email });
}

async function login(req, env) {
  const b = await readJson(req);
  const email = checkEmail(b.email), key = String(b.auth || "");
  await limit(env, "loginip:" + ip(req), 30, 15 * 60e3, "Too many sign-in attempts from this connection. Wait 15 minutes and try again.");
  await limit(env, "login:" + email, 10, 15 * 60e3, "Too many tries. Wait 15 minutes and try again.");
  const u = await byEmail(env, email, "id, auth_hash, wrapped_key");
  const ok = safeEqual(await authHash(env, key), u ? u.auth_hash : "x".repeat(64));
  if (!u || !ok) throw new HttpError(401, "Email or password isn't right.");
  await env.DB.prepare("DELETE FROM attempts WHERE key = ?").bind("login:" + email).run();
  return json({ token: await newSession(env, req, u.id), email, wrapped: u.wrapped_key });
}

/** Step 1 of a forgotten password: prove the recovery code, get the data key encrypted under it. */
async function recoverKey(req, env) {
  const b = await readJson(req);
  const email = checkEmail(b.email);
  const u = await checkRecovery(env, req, email, b.recAuth);
  return json({ wrappedRec: u.wrapped_rec, salt: u.kdf_salt });
}

/** Step 2: set a new password (and a new recovery code). All devices are signed out. */
async function recoverReset(req, env) {
  const b = await readJson(req, 16000);
  const email = checkEmail(b.email);
  const u = await checkRecovery(env, req, email, b.recAuth);
  const k = keyMaterial(b), rec = recMaterial(b.next || {});
  const rows = rowsFor(env, u.id);
  await rows.setPassword({ ...k, authHash: await authHash(env, k.auth) }, "");
  await rows.setRecovery(await authHash(env, rec.auth), rec.wrapped);
  await env.DB.prepare("DELETE FROM attempts WHERE key = ?").bind("rec:" + email).run();
  return json({ token: await newSession(env, req, u.id), email });
}

async function checkRecovery(env, req, email, recAuth) {
  await limit(env, "recip:" + ip(req), 20, 3600e3, "Too many tries from this connection. Wait an hour and try again.");
  await limit(env, "rec:" + email, 10, 3600e3, "Too many tries. Wait an hour and try again.");
  const u = await byEmail(env, email, "id, rec_hash, wrapped_rec, kdf_salt");
  const ok = safeEqual(await authHash(env, String(recAuth || "")), u ? u.rec_hash : "x".repeat(64));
  if (!u || !ok) throw new HttpError(401, "Email or recovery code isn't right.");
  return u;
}

/** Change password: the device re-encrypts the same data key under the new password. Other devices are signed out. */
async function changePassword(req, env, user, rows) {
  const b = await readJson(req);
  await checkCurrent(env, user, rows, b.current);
  const k = keyMaterial(b);
  await rows.setPassword({ ...k, authHash: await authHash(env, k.auth) }, user.tokenHash);
  return json({ ok: true });
}

/**
 * Forgot your password but still signed in on a device: that device still holds the data key, so it
 * re-encrypts it under a new password. It must prove it holds the key (keyProof), so a stolen session
 * token alone can't take over the account. Other devices are signed out.
 */
async function devicePassword(req, env, user, rows) {
  const b = await readJson(req);
  await limit(env, "devpw:" + user.id, 5, 3600e3, "Too many tries. Wait an hour and try again.");
  const s = await rows.secrets();
  if (!s.key_proof || !safeEqual(await proofHash(env, keyProof(b.keyProof)), s.key_proof)) throw new HttpError(403, "This device can't confirm your encryption key. Sign in again, or use your recovery code.");
  const k = keyMaterial(b);
  await rows.setPassword({ ...k, authHash: await authHash(env, k.auth) }, user.tokenHash);
  return json({ ok: true });
}

/** The partner's page fetches the encrypted forecast by its secret id (no account needed). */
async function partnerGet(req, env, id) {
  await limit(env, "partner:" + ip(req), 120, 15 * 60e3, "Too many requests. Try again shortly.");
  const r = await env.DB.prepare("SELECT data, updated FROM partner_shares WHERE id = ?").bind(id).first();
  if (!r) throw new HttpError(404, "This forecast has been switched off.");
  return json(r);
}

// ---------- email reset (needs the EMAIL binding: a verified sending domain on Workers Paid) ----------

const hasEmail = env => !!(env.EMAIL && env.EMAIL_FROM);

/** Emails a one-hour reset link. Always answers the same way, so it can't be used to find accounts. */
async function emailReset(req, env, url) {
  if (!hasEmail(env)) throw new HttpError(503, "Email reset isn't available yet.");
  const email = checkEmail((await readJson(req)).email);
  await limit(env, "mailip:" + ip(req), 10, 3600e3, "Too many reset emails from this connection. Try again in an hour.");
  await limit(env, "mail:" + email, 3, 3600e3, "We've already sent a few reset emails. Check your inbox (and spam), or try again in an hour.");
  const u = await byEmail(env, email, "id");
  if (u) {
    const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare("INSERT INTO reset_tokens (token_hash, user_id, created) VALUES (?, ?, ?)").bind(await sha256(token), u.id, Date.now()).run();
    const link = `${url.origin}/app#reset=${token}`; // a #fragment never reaches server logs
    await env.EMAIL.send({
      to: email, from: env.EMAIL_FROM, subject: "Reset your Shark Week Tracker password",
      text: `Someone (hopefully you) asked to reset the password for this Shark Week Tracker account.\n\nReset it here (link works for 1 hour):\n${link}\n\nIf you still have your recovery code, use "Forgot password?" with the code instead — it keeps your logs. Resetting from this email starts your account fresh, because your old logs are encrypted with your old password.\n\nDidn't ask for this? Ignore this email; nothing changes.`,
      html: `<p>Someone (hopefully you) asked to reset the password for this Shark Week Tracker account.</p><p><a href="${link}">Reset your password</a> (link works for 1 hour).</p><p>If you still have your <b>recovery code</b>, use <i>Forgot password?</i> with the code instead — it keeps your logs. Resetting from this email starts your account fresh, because your old logs are encrypted with your old password.</p><p>Didn't ask for this? Ignore this email; nothing changes.</p>`,
    });
  }
  return json({ ok: true });
}

/** Checks an email reset link; returns its account. */
async function resetToken(env, req, token) {
  token = String(token || "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new HttpError(400, "That reset link isn't valid.");
  await limit(env, "resetip:" + ip(req), 20, 3600e3, "Too many tries from this connection. Wait an hour and try again.");
  const row = await env.DB.prepare("SELECT r.user_id, r.created, u.email FROM reset_tokens r JOIN users u ON u.id = r.user_id WHERE r.token_hash = ?").bind(await sha256(token)).first();
  if (!row || Date.now() - row.created > RESET_TTL) throw new HttpError(400, "That reset link has expired or was already used. Ask for a new one.");
  return row;
}

/** Sets a brand-new password and data key from an email link. Old logs (unreadable without the old key) are deleted. */
async function emailResetConfirm(req, env) {
  const b = await readJson(req, 16000);
  const row = await resetToken(env, req, b.token);
  const k = keyMaterial(b), rec = recMaterial(b), proof = await proofHash(env, keyProof(b.keyProof));
  await rowsFor(env, row.user_id).restartWithNewKey({ ...k, authHash: await authHash(env, k.auth) }, { hash: await authHash(env, rec.auth), wrapped: rec.wrapped }, proof);
  return json({ token: await newSession(env, req, row.user_id), email: row.email });
}

async function newRecovery(req, env, user, rows) {
  const b = await readJson(req);
  await checkCurrent(env, user, rows, b.current);
  const rec = recMaterial(b);
  await rows.setRecovery(await authHash(env, rec.auth), rec.wrapped);
  return json({ ok: true });
}

async function deleteAccount(req, env, user, rows) {
  await checkCurrent(env, user, rows, (await readJson(req)).current);
  await rows.deleteEverything();
  return json({ ok: true });
}

/** Re-checks the password (as its login key) before sensitive changes. */
async function checkCurrent(env, user, rows, key) {
  const k = "current:" + user.id;
  await limit(env, k, 10, 15 * 60e3, "Too many tries. Wait 15 minutes and try again.");
  const s = await rows.secrets();
  if (!safeEqual(await authHash(env, String(key || "")), s.auth_hash)) throw new HttpError(403, "Your current password isn't right.");
  await env.DB.prepare("DELETE FROM attempts WHERE key = ?").bind(k).run();
}

async function putDocs(req, rows) {
  const b = await readJson(req, MAX_BODY);
  const docs = Array.isArray(b.docs) ? b.docs : null;
  if (!docs || !docs.length || docs.length > MAX_BATCH) throw new HttpError(400, "Bad upload.");
  const seen = new Set();
  for (const d of docs) {
    if (!d || !DOC_ID.test(d.id) || typeof d.data !== "string" || !B64.test(d.data) || d.data.length > MAX_DOC || seen.has(d.id)) throw new HttpError(400, "Bad upload.");
    seen.add(d.id);
  }
  if ((await rows.countDocs()) + docs.length > MAX_DOCS) throw new HttpError(413, "Storage limit reached.");
  const now = Date.now();
  await rows.putDocs(docs, now);
  return json({ ok: true, updated: now });
}

function keyMaterial(b) {
  const salt = String(b.salt || ""), iter = +b.iter, auth = String(b.auth || ""), wrapped = String(b.wrapped || "");
  if (!B64.test(salt) || salt.length < 22 || salt.length > 64) throw new HttpError(400, "Bad key data.");
  if (!Number.isInteger(iter) || iter < MIN_ITER || iter > 10_000_000) throw new HttpError(400, "Bad key data.");
  if (!B64.test(auth) || auth.length !== 43) throw new HttpError(400, "Bad key data.");
  if (!B64.test(wrapped) || wrapped.length < 40 || wrapped.length > 400) throw new HttpError(400, "Bad key data.");
  return { salt, iter, auth, wrapped };
}

function keyProof(v) {
  const s = String(v || "");
  if (!B64.test(s) || s.length !== 43) throw new HttpError(400, "Bad key data.");
  return s;
}
const proofHash = (env, kp) => hmac(env.AUTH_PEPPER, "proof:" + kp);

function recMaterial(b) {
  const auth = String(b.recAuth || ""), wrapped = String(b.wrappedRec || "");
  if (!B64.test(auth) || auth.length !== 43 || !B64.test(wrapped) || wrapped.length < 40 || wrapped.length > 400) throw new HttpError(400, "Bad recovery data.");
  return { auth, wrapped };
}

function checkEmail(s) {
  const email = String(s || "").trim().toLowerCase();
  if (email.length > 254 || !EMAIL.test(email)) throw new HttpError(400, "Enter a valid email address.");
  return email;
}

async function auth(req, env) {
  const m = (req.headers.get("Authorization") || "").match(/^Bearer ([A-Za-z0-9_-]{43})$/);
  if (!m) throw new HttpError(401, "Sign in to continue.");
  const tokenHash = await sha256(m[1]);
  const row = await env.DB.prepare("SELECT user_id, last_seen FROM sessions WHERE token_hash = ?").bind(tokenHash).first();
  const now = Date.now();
  if (!row || now - row.last_seen > SESSION_IDLE) throw new HttpError(401, "Sign in to continue.");
  if (now - row.last_seen > 3600e3) await env.DB.prepare("UPDATE sessions SET last_seen = ? WHERE token_hash = ?").bind(now, tokenHash).run();
  return { id: row.user_id, tokenHash };
}

async function newSession(env, req, userId) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, created, last_seen, device) VALUES (?, ?, ?, ?, ?)")
    .bind(await sha256(token), userId, now, now, deviceLabel(req)).run();
  return token;
}

function deviceLabel(req) {
  const ua = req.headers.get("User-Agent") || "";
  const app = /SharkWeekApp/.test(ua) ? " app" : "";
  for (const [re, name] of [[/Android/, "Android"], [/iPhone|iPad/, "iPhone/iPad"], [/Windows/, "Windows"], [/Mac OS/, "Mac"], [/CrOS/, "Chromebook"], [/Linux/, "Linux"]]) {
    if (re.test(ua)) return name + app;
  }
  return "Unknown device";
}

/** Fixed-window rate limit. One atomic statement, so parallel requests can't slip past the count. */
async function limit(env, key, max, windowMs, message) {
  const count = await env.DB.prepare(
    "INSERT INTO attempts (key, count, first) VALUES (?1, 1, ?2) ON CONFLICT (key) DO UPDATE SET " +
    "count = CASE WHEN ?2 - first >= ?3 THEN 1 ELSE count + 1 END, " +
    "first = CASE WHEN ?2 - first >= ?3 THEN ?2 ELSE first END RETURNING count"
  ).bind(key, Date.now(), windowMs).first("count");
  if (count > max) throw new HttpError(429, message);
}

const ip = req => req.headers.get("CF-Connecting-IP") || "local";

// ---------- crypto helpers ----------

/** The device's login key is already a 600k-round PBKDF2 output; a keyed hash with a secret pepper means a stolen database alone is useless. */
const authHash = (env, key) => hmac(env.AUTH_PEPPER, "auth:" + key);

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg))));
}

async function sha256(s) {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

const b64url = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function readJson(req, max = 8000) {
  const text = await req.text();
  if (text.length > max) throw new HttpError(413, "That's too much data in one go.");
  try { return JSON.parse(text) || {}; } catch { throw new HttpError(400, "Bad request."); }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: {
    "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Security-Policy": API_CSP, ...SECURITY_HEADERS,
  } });
}
