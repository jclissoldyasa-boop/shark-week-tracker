-- Partner heads-up: an encrypted forecast the user's device uploads. The key is only in the share link's
-- #fragment, so the server (and anyone without the link) sees ciphertext only.
CREATE TABLE partner_shares (
  id TEXT PRIMARY KEY,           -- random 22-char id from the share link
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  data TEXT NOT NULL,
  updated INTEGER NOT NULL
);
CREATE INDEX partner_shares_user ON partner_shares(user_id);
