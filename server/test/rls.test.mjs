// Static row-level-security check: every SQL statement that touches a user's rows must be pinned to one
// user. Statements on docs/sessions need `user_id = ?`; statements on users need `id = ?` or `email = ?`
// (the pre-session lookups, which are rate limited). Inserts are allowed. Fails loudly otherwise.
import fs from "node:fs";
const src = fs.readFileSync(new URL("../src/worker.js", import.meta.url), "utf8");
const sql = [...src.matchAll(/(["`])((?:SELECT|INSERT|UPDATE|DELETE)\b[^"`]*)\1(?:\s*\+\s*\n?\s*(["`])([^"`]*)\3)?/g)].map(m => m[2] + (m[4] || ""));
let bad = 0, checked = 0;
for (const q of sql) {
  const table = (q.match(/\b(?:FROM|INTO|UPDATE)\s+(\w+)/) || [])[1];
  if (!["docs", "sessions", "users"].includes(table)) continue;
  checked++;
  if (/^INSERT/.test(q) && !/ON CONFLICT[\s\S]*DO UPDATE/.test(q)) continue;
  let ok;
  if (table === "users") ok = /WHERE (id|email) = \?/.test(q);
  else ok = /user_id = \?/.test(q) || /WHERE token_hash = \?/.test(q) || /WHERE last_seen < \?/.test(q);
  if (/ON CONFLICT[\s\S]*DO UPDATE/.test(q)) ok = /DO UPDATE[\s\S]*WHERE docs\.user_id = \?/.test(q);
  if (!ok) { bad++; console.error("NOT SCOPED TO A USER:", q); }
}
// Sessions by token hash: the token is a 256-bit secret, so looking it up is itself the access check.
// "last_seen < ?" is the daily clean-up job, which deletes idle sessions of every user by design.
if (checked < 15) { console.error(`Only found ${checked} statements — the checker is out of date.`); process.exit(1); }
if (bad) process.exit(1);
console.log(`RLS check: ${checked} statements on user tables, all scoped.`);
