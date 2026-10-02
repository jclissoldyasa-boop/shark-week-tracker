// End-to-end API + security tests against a running server (default: local `wrangler dev`).
//   BASE=https://… node test/api.test.mjs   to run against a deployment (uses throwaway accounts, deletes them after).
// Implements the same device-side crypto as app.html, so it also proves the server never needs the password.
import assert from "node:assert/strict";
const BASE = process.env.BASE || "http://127.0.0.1:8787";
const { subtle } = globalThis.crypto;
const te = new TextEncoder();
const b64 = u8 => Buffer.from(u8).toString("base64url");
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const ITER = 600000;

async function pbkdf2(pw, salt, iter) {
  const k = await subtle.importKey("raw", te.encode(pw.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: te.encode(salt), iterations: iter }, k, 256));
}
async function hkdf(ikm, info, salt = "") {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: te.encode(salt), info: te.encode(info) }, k, 256));
}
async function pwKeys(pw, salt, iter) { const m = await pbkdf2(pw, salt, iter); return { auth: b64(await hkdf(m, "sharkweek-auth-v1")), wrap: await hkdf(m, "sharkweek-wrap-v1") }; }
async function recKeys(code, email) { const c = te.encode(code); return { auth: b64(await hkdf(c, "sharkweek-rec-auth-v1", email)), wrap: await hkdf(c, "sharkweek-rec-wrap-v1", email) }; }
const proofOf = async raw => b64(await hkdf(raw, "sharkweek-keyproof-v1"));
async function wrap(key, raw) {
  const iv = rand(12), k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return b64(Buffer.concat([iv, new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode("sharkweek-key-v1") }, k, raw))]));
}
async function unwrap(key, s) {
  const u = Buffer.from(s, "base64url"), k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12), additionalData: te.encode("sharkweek-key-v1") }, k, u.subarray(12)));
}

async function call(path, { method = "GET", body, token, headers = {} } = {}) {
  const r = await fetch(BASE + path, { method, headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}), ...headers }, body: body && method !== "GET" ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => null), headers: r.headers };
}

let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ✓", name); }

async function newUser(tag) {
  const email = `test-${tag}-${Date.now()}-${b64(rand(4))}@example.com`, password = "correct horse battery " + tag;
  const raw = rand(64), salt = b64(rand(16)), k = await pwKeys(password, salt, ITER);
  const code = "ABCDEFGHJKLMNPQRSTUVWXYZ2".split("").sort(() => Math.random() - .5).join("");
  const rk = await recKeys(code, email);
  const r = await call("/api/signup", { method: "POST", body: { email, salt, iter: ITER, auth: k.auth, wrapped: await wrap(k.wrap, raw), recAuth: rk.auth, wrappedRec: await wrap(rk.wrap, raw), keyProof: await proofOf(raw), acceptTerms: true, healthConsent: true, age16: true } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { email, password, raw, salt, auth: k.auth, code, token: r.body.token };
}
const docId = () => b64(rand(16)).slice(0, 22);
const ct = () => b64(rand(300));

console.log(`Testing ${BASE}`);
const A = await newUser("a"), B = await newUser("b");

await test("pages have security headers and a hash-only script policy", async () => {
  const r = await fetch(BASE + "/");
  assert.equal(r.status, 200);
  const csp = r.headers.get("content-security-policy");
  assert.match(csp, /script-src 'sha256-/); assert.doesNotMatch(csp, /unsafe-inline'[^;]*script|script-src[^;]*unsafe/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(r.headers.get("strict-transport-security"), /max-age=63072000/);
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal(r.headers.get("referrer-policy"), "no-referrer");
  for (const p of ["/privacy", "/terms"]) { const x = await fetch(BASE + p); assert.equal(x.status, 200); assert.match(await x.text(), /Australia/); }
});

await test("signup rejects missing consent, weak key data and duplicates", async () => {
  const k = await pwKeys("whatever whatever", "saltsaltsaltsaltsaltsa", ITER);
  const base = { email: `x-${Date.now()}@example.com`, salt: "saltsaltsaltsaltsaltsa", iter: ITER, auth: k.auth, wrapped: ct(), recAuth: k.auth, wrappedRec: ct(), keyProof: k.auth, acceptTerms: true, healthConsent: true, age16: true };
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, keyProof: undefined } })).status, 400);
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, healthConsent: false } })).status, 400);
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, age16: false } })).status, 400);
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, iter: 1000 } })).status, 400);
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, auth: "short" } })).status, 400);
  assert.equal((await call("/api/signup", { method: "POST", body: { ...base, email: A.email } })).status, 409);
});

await test("prelogin doesn't reveal whether an account exists", async () => {
  const e = `nobody-${Date.now()}@example.com`;
  const r1 = await call("/api/prelogin", { method: "POST", body: { email: e } }), r2 = await call("/api/prelogin", { method: "POST", body: { email: e } });
  assert.equal(r1.status, 200); assert.equal(r1.body.salt, r2.body.salt); assert.equal(r1.body.iter, ITER);
  const real = await call("/api/prelogin", { method: "POST", body: { email: A.email } });
  assert.equal(real.body.salt, A.salt); assert.equal(real.body.salt.length, r1.body.salt.length);
});

await test("login needs the right key; returns the wrapped data key, which only the password unlocks", async () => {
  const bad = await pwKeys("wrong password!!", A.salt, ITER);
  const r1 = await call("/api/login", { method: "POST", body: { email: A.email, auth: bad.auth } });
  assert.equal(r1.status, 401);
  const unknown = await call("/api/login", { method: "POST", body: { email: "nobody@example.com", auth: bad.auth } });
  assert.equal(unknown.status, 401); assert.equal(unknown.body.error, r1.body.error);
  const k = await pwKeys(A.password, A.salt, ITER);
  const r = await call("/api/login", { method: "POST", body: { email: A.email.toUpperCase(), auth: k.auth } });
  assert.equal(r.status, 200);
  assert.deepEqual(await unwrap(k.wrap, r.body.wrapped), A.raw);
  await assert.rejects(unwrap(bad.wrap, r.body.wrapped));
  A.token2 = r.body.token;
});

await test("API refuses requests without a valid session", async () => {
  for (const [p, m] of [["/api/docs", "GET"], ["/api/me", "GET"], ["/api/sessions", "GET"], ["/api/docs", "POST"], ["/api/account", "DELETE"]]) {
    assert.equal((await call(p, { method: m, body: {} })).status, 401, p);
    assert.equal((await call(p, { method: m, body: {}, token: "A".repeat(43) })).status, 401, p);
  }
});

const aDoc = docId(), aData = ct();
await test("RLS: a user's documents are invisible and untouchable to other users", async () => {
  assert.equal((await call("/api/docs", { method: "POST", token: A.token, body: { docs: [{ id: aDoc, data: aData }] } })).status, 200);
  const mine = await call("/api/docs?since=0", { token: A.token });
  assert.deepEqual(mine.body.docs.map(d => [d.id, d.data]), [[aDoc, aData]]);
  const theirs = await call("/api/docs?since=0", { token: B.token });
  assert.equal(theirs.body.docs.length, 0);
  // B writes the same document id: it becomes B's own row and A's stays untouched.
  assert.equal((await call("/api/docs", { method: "POST", token: B.token, body: { docs: [{ id: aDoc, data: ct() }] } })).status, 200);
  const again = await call("/api/docs?since=0", { token: A.token });
  assert.equal(again.body.docs[0].data, aData);
  // Sessions list only shows your own devices.
  const s = await call("/api/sessions", { token: B.token });
  assert.equal(s.body.sessions.length, 1);
  // A user id or email in the body is ignored.
  const sneaky = await call("/api/docs?since=0&user_id=x", { token: B.token, headers: { "X-User": A.email } });
  assert.ok(sneaky.body.docs.every(d => d.data !== aData));
});

await test("upload validation", async () => {
  const bad = [[{ id: "../../etc", data: ct() }], [{ id: docId(), data: "not base64!" }], [{ id: docId(), data: "A".repeat(70000) }], [], Array.from({ length: 201 }, () => ({ id: docId(), data: ct() }))];
  for (const docs of bad) assert.equal((await call("/api/docs", { method: "POST", token: A.token, body: { docs } })).status, 400);
  const d = docId();
  assert.equal((await call("/api/docs", { method: "POST", token: A.token, body: { docs: [{ id: d, data: ct() }, { id: d, data: ct() }] } })).status, 400);
});

await test("sync pages through changes in order", async () => {
  const docs = Array.from({ length: 150 }, () => ({ id: docId(), data: ct() }));
  await call("/api/docs", { method: "POST", token: A.token, body: { docs } });
  let since = 0, after = "", got = [];
  for (;;) { const r = await call(`/api/docs?since=${since}&after=${after}`, { token: A.token }); got.push(...r.body.docs); since = r.body.since; after = r.body.after; if (!r.body.more) break; }
  assert.equal(got.length, 151);
  const r = await call(`/api/docs?since=${since}&after=${after}`, { token: A.token });
  assert.equal(r.body.docs.length, 0);
});

await test("cross-site requests are refused", async () => {
  const r = await call("/api/docs", { method: "POST", token: A.token, headers: { Origin: "https://evil.example" }, body: { docs: [{ id: docId(), data: ct() }] } });
  assert.equal(r.status, 403);
});

await test("change password: needs current password, re-wraps key, signs out other devices", async () => {
  const wrongCur = (await pwKeys("nope nope nope", A.salt, ITER)).auth;
  const salt = b64(rand(16)), nk = await pwKeys("new password for A!", salt, ITER), wrapped = await wrap(nk.wrap, A.raw);
  assert.equal((await call("/api/password", { method: "POST", token: A.token, body: { current: wrongCur, salt, iter: ITER, auth: nk.auth, wrapped } })).status, 403);
  assert.equal((await call("/api/password", { method: "POST", token: A.token, body: { current: A.auth, salt, iter: ITER, auth: nk.auth, wrapped } })).status, 200);
  assert.equal((await call("/api/me", { token: A.token })).status, 200);
  assert.equal((await call("/api/me", { token: A.token2 })).status, 401);
  assert.equal((await call("/api/login", { method: "POST", body: { email: A.email, auth: A.auth } })).status, 401);
  const r = await call("/api/login", { method: "POST", body: { email: A.email, auth: nk.auth } });
  assert.equal(r.status, 200); assert.deepEqual(await unwrap(nk.wrap, r.body.wrapped), A.raw);
  Object.assign(A, { salt, auth: nk.auth, password: "new password for A!" });
});

await test("recovery code resets the password and keeps the data readable", async () => {
  const wrongRec = await recKeys("ZZZZZZZZZZZZZZZZZZZZZZZZZ", B.email);
  assert.equal((await call("/api/recover/key", { method: "POST", body: { email: B.email, recAuth: wrongRec.auth } })).status, 401);
  const rk = await recKeys(B.code, B.email);
  const r1 = await call("/api/recover/key", { method: "POST", body: { email: B.email, recAuth: rk.auth } });
  assert.equal(r1.status, 200);
  const raw = await unwrap(rk.wrap, r1.body.wrappedRec);
  assert.deepEqual(raw, B.raw);
  const salt = b64(rand(16)), nk = await pwKeys("brand new B password", salt, ITER), nrk = await recKeys("NEWCODENEWCODENEWCODENEWC", B.email);
  const r2 = await call("/api/recover/reset", { method: "POST", body: { email: B.email, recAuth: rk.auth, salt, iter: ITER, auth: nk.auth, wrapped: await wrap(nk.wrap, raw), next: { recAuth: nrk.auth, wrappedRec: await wrap(nrk.wrap, raw) } } });
  assert.equal(r2.status, 200);
  assert.equal((await call("/api/me", { token: B.token })).status, 401, "old sessions end");
  assert.equal((await call("/api/recover/key", { method: "POST", body: { email: B.email, recAuth: rk.auth } })).status, 401, "old code stops working");
  B.token = r2.body.token; B.auth = nk.auth;
});

await test("forgot password on a signed-in device: needs the data key, not just a session", async () => {
  const salt = b64(rand(16)), nk = await pwKeys("device reset password", salt, ITER), wrapped = await wrap(nk.wrap, A.raw);
  const second = (await call("/api/login", { method: "POST", body: { email: A.email, auth: A.auth } })).body.token;
  // A stolen session token without the key can't do it.
  assert.equal((await call("/api/password/device", { method: "POST", token: A.token, body: { keyProof: await proofOf(rand(64)), salt, iter: ITER, auth: nk.auth, wrapped } })).status, 403);
  assert.equal((await call("/api/password/device", { method: "POST", token: A.token, body: { salt, iter: ITER, auth: nk.auth, wrapped } })).status, 400);
  // The device that holds the key can, without the old password.
  assert.equal((await call("/api/password/device", { method: "POST", token: A.token, body: { keyProof: await proofOf(A.raw), salt, iter: ITER, auth: nk.auth, wrapped } })).status, 200);
  assert.equal((await call("/api/me", { token: second })).status, 401, "other devices signed out");
  const r = await call("/api/login", { method: "POST", body: { email: A.email, auth: nk.auth } });
  assert.equal(r.status, 200); assert.deepEqual(await unwrap(nk.wrap, r.body.wrapped), A.raw, "same data key, data kept");
  assert.equal((await call("/api/docs?since=0", { token: A.token })).body.docs.length, 151);
  Object.assign(A, { salt, auth: nk.auth });
});

await test("email reset endpoints validate links", async () => {
  const cfg = (await call("/api/config")).body;
  const r = await call("/api/reset/email", { method: "POST", body: { email: A.email } });
  assert.equal(r.status, cfg.emailReset ? 200 : 503);
  for (const p of ["/api/reset/email/peek", "/api/reset/email/confirm"]) {
    assert.equal((await call(p, { method: "POST", body: { token: "bad" } })).status, 400);
    assert.equal((await call(p, { method: "POST", body: { token: b64(rand(32)) } })).status, 400);
  }
});

await test("partner forecast: public by secret id, only its owner can change it", async () => {
  const id = docId(), data = ct();
  assert.equal((await call(`/api/partner/${id}`, { method: "PUT", body: { data } })).status, 401);
  assert.equal((await call(`/api/partner/${id}`, { method: "PUT", token: A.token, body: { data } })).status, 200);
  const pub = await call(`/api/partner/${id}`);
  assert.equal(pub.status, 200); assert.equal(pub.body.data, data);
  assert.equal((await call(`/api/partner/${id}`, { method: "PUT", token: B.token, body: { data: ct() } })).status, 403, "someone else can't overwrite it");
  await call(`/api/partner/${id}`, { method: "DELETE", token: B.token });
  assert.equal((await call(`/api/partner/${id}`)).body.data, data, "or delete it");
  assert.equal((await call(`/api/partner/${docId()}`)).status, 404);
  assert.equal((await call(`/api/partner/${id}`, { method: "PUT", token: A.token, body: { data: "not base64!" } })).status, 400);
  assert.equal((await call(`/api/partner/${id}`, { method: "DELETE", token: A.token })).status, 200);
  assert.equal((await call(`/api/partner/${id}`)).status, 404);
});

await test("delete account removes everything and only that account", async () => {
  assert.equal((await call("/api/account", { method: "DELETE", token: A.token, body: { current: "x".repeat(43) } })).status, 403);
  assert.equal((await call("/api/account", { method: "DELETE", token: A.token, body: { current: A.auth } })).status, 200);
  assert.equal((await call("/api/me", { token: A.token })).status, 401);
  assert.equal((await call("/api/login", { method: "POST", body: { email: A.email, auth: A.auth } })).status, 401);
  const b = await call("/api/docs?since=0", { token: B.token });
  assert.equal(b.status, 200); assert.equal(b.body.docs.length, 1);
  assert.equal((await call("/api/account", { method: "DELETE", token: B.token, body: { current: B.auth } })).status, 200);
});

await test("sign-in attempts are rate limited", async () => {
  const C = await newUser("c");
  let last;
  for (let i = 0; i < 11; i++) last = await call("/api/login", { method: "POST", body: { email: C.email, auth: "x".repeat(43) } });
  assert.equal(last.status, 429);
  await call("/api/account", { method: "DELETE", token: C.token, body: { current: C.auth } });
});

console.log(`\n${passed} tests passed.`);
