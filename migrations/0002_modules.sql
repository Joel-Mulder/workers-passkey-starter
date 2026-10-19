-- workers-passkey-starter: tables and columns for the optional modules (src/auth/modules/*). Run it when you enable
-- any module; the core never reads these. Additive only: 0001's tables keep their shape, so nothing is rebuilt.

-- E-mail verification: only a VERIFIED address is ever stored on the user row (an unverified address waits in
-- email_verifications), so nobody can claim someone else's address by typing it.
ALTER TABLE users ADD COLUMN email TEXT;                  -- lowercase, verified
ALTER TABLE users ADD COLUMN email_verified_at INTEGER;
CREATE UNIQUE INDEX users_email ON users (email) WHERE email IS NOT NULL;

-- Approval + admin. users.status (0001) stays 'active' | 'suspended'; an account waiting for approval or rejected is
-- 'suspended' with approval 'pending' / 'rejected', so the core already refuses it everywhere.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'));
ALTER TABLE users ADD COLUMN approval TEXT NOT NULL DEFAULT 'approved' CHECK (approval IN ('approved', 'pending', 'rejected'));
CREATE INDEX users_waiting ON users (created_at) WHERE approval != 'approved';

CREATE TABLE email_verifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,                       -- the address to verify (not yet on the user row)
  token_hash TEXT NOT NULL UNIQUE,           -- SHA-256 of the token in the link
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX email_verifications_user ON email_verifications (user_id);

-- Recovery links that were mailed remember the address, so it is told once the link has been used.
ALTER TABLE recovery_tokens ADD COLUMN mailed_to TEXT;

-- Personal invites: one address, single use, 7 days by default.
CREATE TABLE invites (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_by TEXT,                           -- the admin's user id (no FK: invites outlive accounts)
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  used_by TEXT,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL
);

-- Shareable signup links: a number of uses until a date. used_count only ever goes up (a deleted account never
-- gives its place back).
CREATE TABLE signup_links (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  max_uses INTEGER NOT NULL CHECK (max_uses > 0),
  used_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL
);
