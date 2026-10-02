// Assembles the web app for the server (./public) and the Android app (../android/assets):
// the app page, the legal pages (filled in from ../site.json), web-app files, and a
// Content-Security-Policy that only allows the exact inline scripts in these pages (by SHA-256 hash).
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const read = f => fs.readFileSync(path.join(root, f), "utf8");
const site = JSON.parse(read("site.json"));
const TERMS_VERSION = read("server/src/worker.js").match(/const TERMS_VERSION = "([^"]+)"/)[1];
const date = new Date(TERMS_VERSION + "T12:00:00").toLocaleDateString("en-AU", { day: "numeric", month: "long", year: "numeric" });
const style = `<style>\n${read("legal/_style.css")}</style>`;
const fill = html => html.replace("<!--STYLE-->", style).replace(/\{\{(\w+)\}\}/g, (_, k) => {
  const v = { NAME: site.name, OPERATOR: site.operator, CONTACT: site.contact, STATE: site.state, DATE: date, TERMS_VERSION, REPO: site.repo, HOST: site.host }[k];
  if (v == null) throw new Error("No value for {{" + k + "}}");
  return v.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
});
// The app page carries a short hash of itself so it can tell when a newer version has been deployed.
let app = read("app.html");
const BUILD = crypto.createHash("sha256").update(app).digest("hex").slice(0, 12);
app = app.replace('"__BUILD__"', JSON.stringify(BUILD));
const legal = { "privacy.html": fill(read("legal/privacy.html")), "terms.html": fill(read("legal/terms.html")) };
const landing = fill(read("landing.html"));
const webPages = { "index.html": landing, "app.html": app, "partner.html": read("partner.html"), ...legal }; // site: landing at /, app at /app, partner forecast at /partner
const apkPages = { "index.html": app, ...legal };                         // APK: the bundled app

const hashes = new Set();
for (const html of Object.values(webPages)) {
  for (const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) hashes.add(`'sha256-${crypto.createHash("sha256").update(m[1]).digest("base64")}'`);
  if (/<script[^>]*src=/.test(html)) throw new Error("External scripts aren't allowed by the CSP");
  if (/\son[a-z]+=/i.test(html.replace(/<script>[\s\S]*?<\/script>/g, ""))) throw new Error("Inline event handlers are blocked by the CSP");
}
const csp = [
  "default-src 'self'",
  `script-src ${[...hashes].join(" ")}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'none'",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// Android signing key (generated once — KEEP IT: Android only installs updates signed with the same key).
const ks = path.join(root, "android/sharkweek.keystore");
if (!fs.existsSync(ks)) {
  execFileSync("keytool", ["-genkeypair", "-keystore", ks, "-alias", "sharkweek", "-keyalg", "RSA", "-keysize", "3072", "-validity", "10000",
    "-storepass", "sharkweek", "-keypass", "sharkweek", "-dname", "CN=Shark Week Tracker"], { stdio: "ignore" });
}
const fp = execFileSync("keytool", ["-list", "-v", "-keystore", ks, "-alias", "sharkweek", "-storepass", "sharkweek"]).toString().match(/SHA256: ([0-9A-F:]+)/)[1];
const assetLinks = [{
  relation: ["delegate_permission/common.get_login_creds", "delegate_permission/common.handle_all_urls"],
  target: { namespace: "android_app", package_name: "au.sharkweek", sha256_cert_fingerprints: [fp] },
}];

const pub = path.join(root, "server/public"), apk = path.join(root, "android/assets");
for (const [out, pages] of [[pub, webPages], [apk, apkPages]]) {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  for (const [name, html] of Object.entries(pages)) fs.writeFileSync(path.join(out, name), html);
}
fs.cpSync(path.join(root, "web"), pub, { recursive: true });
// QR code for "Share Shark Week": scanning it opens the landing page (download + web app).
const QRCode = (await import("qrcode")).default;
fs.writeFileSync(path.join(pub, "qr.svg"), await QRCode.toString(`https://${site.host}/`, { type: "svg", margin: 2, errorCorrectionLevel: "M", color: { dark: "#07162A", light: "#FFFFFF" } }));

// The latest Android build (from android/build.sh) is published at /download/SharkWeek.apk, and
// /version.json tells installed apps and open web pages whether they're out of date.
const version = { web: BUILD };
const rel = path.join(root, "android/release.json"), apkFile = path.join(root, "android/SharkWeek.apk");
if (fs.existsSync(rel) && fs.existsSync(apkFile)) {
  fs.mkdirSync(path.join(pub, "download"), { recursive: true });
  fs.copyFileSync(apkFile, path.join(pub, "download/SharkWeek.apk"));
  const r = JSON.parse(fs.readFileSync(rel, "utf8"));
  version.android = { code: r.code, name: r.name, notes: r.notes || "", url: "/download/SharkWeek.apk", size: fs.statSync(apkFile).size };
}
fs.writeFileSync(path.join(pub, "version.json"), JSON.stringify(version));
fs.writeFileSync(path.join(apk, "csp.txt"), csp);
fs.writeFileSync(path.join(root, "server/src/site.generated.js"),
  `// Generated by build.mjs — do not edit.\nexport const CSP = ${JSON.stringify(csp)};\nexport const ASSET_LINKS = ${JSON.stringify(assetLinks)};\n`);
fs.mkdirSync(path.join(root, "android/gen/au/sharkweek"), { recursive: true });
fs.writeFileSync(path.join(root, "android/gen/au/sharkweek/Site.java"),
  `// Generated by server/build.mjs from site.json — do not edit.\npackage au.sharkweek;\nfinal class Site { static final String HOST = ${JSON.stringify(site.host)}; }\n`);
console.log(`Built web ${BUILD}${version.android ? ` + APK ${version.android.name}` : " (no APK yet)"} with ${hashes.size} script hash(es) for ${site.host}.`);
