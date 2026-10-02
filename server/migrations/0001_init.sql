-- Shark Week Tracker. The server never sees health data: docs.data is AES-256-GCM ciphertext made on
-- the user's device with a key the server never receives (see README "Encryption").
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  kdf_salt TEXT NOT NULL,        -- public salt for the device-side PBKDF2 of the password
  kdf_iter INTEGER NOT NULL,
  auth_hash TEXT NOT NULL,       -- HMAC(pepper, login key derived on the device); never the password
  wrapped_key TEXT NOT NULL,     -- the data key, encrypted with a key derived from the password
  rec_hash TEXT NOT NULL,        -- same, for the recovery code
  wrapped_rec TEXT NOT NULL,
  created INTEGER NOT NULL,
  terms_version TEXT NOT NULL,
  consented INTEGER NOT NULL     -- when they gave express consent to store sensitive (health) information
);
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  device TEXT NOT NULL           -- coarse label like "Android" or "Windows", so people can spot unknown devices
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE docs (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  doc_id TEXT NOT NULL,          -- opaque (keyed hash made on the device), so dates aren't visible
  data TEXT NOT NULL,            -- base64url(iv || ciphertext)
  updated INTEGER NOT NULL,
  PRIMARY KEY (user_id, doc_id)
);
CREATE INDEX docs_user_updated ON docs(user_id, updated);
CREATE TABLE attempts (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  first INTEGER NOT NULL
);
