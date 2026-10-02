-- Proof that a device holds the data key (HMAC(pepper, key-derived value)); lets a signed-in device
-- reset a forgotten password without a stolen session token being enough on its own.
ALTER TABLE users ADD COLUMN key_proof TEXT;
-- One-hour email reset links. Only a hash of the token is stored.
CREATE TABLE reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL
);
CREATE INDEX reset_tokens_user ON reset_tokens(user_id);
