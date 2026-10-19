-- workers-passkey-starter: the auth tables. Nothing else.
-- Conventions: timestamps are INTEGER milliseconds since the epoch (UTC), booleans are 0/1, ids are TEXT (UUID v4
-- unless stated). Your own tables can reference users(id).
--
-- If your app already has a users table, see README.md ("Existing users table"): the auth code needs the columns
-- below (id, username, name, status, access_version, created_at, updated_at); add the missing ones to yours instead.

CREATE TABLE users (
  id TEXT PRIMARY KEY,                       -- also the WebAuthn user handle (UTF-8 bytes of this string)
  username TEXT NOT NULL UNIQUE,             -- lowercase, ^[a-z0-9][a-z0-9_.-]{2,31}$
  name TEXT NOT NULL,                        -- display name
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  access_version INTEGER NOT NULL DEFAULT 1, -- bump to end every session of this user at once
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,        -- base64url
  public_key TEXT NOT NULL,                  -- base64url COSE key
  counter INTEGER NOT NULL DEFAULT 0,        -- only ever moves forward (synced passkeys stay at 0)
  transports TEXT,                           -- comma-separated
  device_type TEXT,                          -- singleDevice | multiDevice
  backed_up INTEGER NOT NULL DEFAULT 0,
  aaguid TEXT,
  name TEXT NOT NULL DEFAULT 'Passkey',
  rp_id TEXT NOT NULL,                       -- the RP ID it was registered for
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX passkeys_user ON passkeys (user_id);

-- Sign in with Google / Apple. Accounts are matched on (provider, subject) only, never on e-mail address.
CREATE TABLE oauth_identities (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('google', 'apple')),
  subject TEXT NOT NULL,
  email TEXT,                                -- as the provider reported it; display only
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  UNIQUE (provider, subject)
);
CREATE INDEX oauth_identities_user ON oauth_identities (user_id);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,                       -- SHA-256 (hex) of the cookie token; the token itself is never stored
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access_version INTEGER NOT NULL,           -- must equal users.access_version, or the session is dead
  auth_method TEXT NOT NULL,                 -- passkey | google | apple
  authenticated_at INTEGER NOT NULL,         -- last full sign-in or step-up (fresh-auth checks use this)
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- Short-lived ceremony state: WebAuthn challenges, OAuth state/PKCE/nonce, signup drafts. Single use, with a TTL.
CREATE TABLE auth_flows (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  data TEXT NOT NULL,                        -- JSON
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX auth_flows_expires ON auth_flows (expires_at);

-- Fixed-window rate-limit counters. Keys hold an HMAC of the client IP, never the IP itself.
CREATE TABLE rate_counters (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);
CREATE INDEX rate_counters_expires ON rate_counters (expires_at);

-- Optional (AuthOptions.audit, on by default): one row per account change, written in the same batch as the change.
-- With audit: false you can drop this table.
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  actor_id TEXT,
  action TEXT NOT NULL,                      -- account-created | passkey-added | passkey-removed | identity-linked | …
  target_user_id TEXT,
  details TEXT,                              -- JSON, ids only
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_log_target ON audit_log (target_user_id, created_at);
