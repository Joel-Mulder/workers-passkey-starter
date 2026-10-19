// Account creation: with a passkey (username + display name, then the passkey) or after Google/Apple (pick a
// username). One atomic D1 batch per account; retry-safe because the user id is fixed per signup flow.
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import type { AuthConfig } from './config';
import { uuid } from './crypto';
import { createFlow, peekFlow } from './flows';
import { MSG as PK_MSG, passkeyInsertStmt, registrationOptions, verifyRegistration, type NewPasskey } from './passkeys';
import { auditStmts, fail, getUser, type Fail, type Result, type UserRow } from './users';
import { validateProfile, type Profile } from './validation';
import type { AuthBindings, Provider } from './types';

type Env = Pick<AuthBindings, 'DB' | 'APP_ORIGIN' | 'PASSKEY_RP_ID'>;

export const MSG = {
  usernameTaken: 'This username is already taken. Choose another one.',
  flowExpired: 'Creating your account took too long. Please start again.',
  flowUsed: 'This account has already been created. Sign in instead.',
};

export type Credential =
  | { kind: 'passkey'; passkey: NewPasskey }
  | { kind: 'oauth'; provider: Provider; subject: string; email: string | null; emailVerified: boolean };

export interface Registered { user: UserRow; idempotent: boolean }

async function usernameFree(db: D1Database, username: string): Promise<Fail | null> {
  return (await db.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first()) ? fail(409, 'username_taken', MSG.usernameTaken) : null;
}

/**
 * Create the user, its first credential and the audit row in ONE batch. Retry-safe: when the same flow already
 * created this user with this credential, the existing user comes back with `idempotent: true`.
 */
export async function registerAccount(env: Env, cfg: Pick<AuthConfig, 'audit'>, input: { userId: string; profile: Profile; credential: Credential }, at = Date.now()): Promise<Result<Registered>> {
  const db = env.DB;
  const uid = input.userId;
  const cred = input.credential;
  const exists = { sql: 'EXISTS (SELECT 1 FROM users WHERE id = ? AND created_at = ?)', params: [uid, at] };
  const stmts = [
    db.prepare("INSERT INTO users (id, username, name, status, access_version, created_at, updated_at) VALUES (?, ?, ?, 'active', 1, ?, ?)")
      .bind(uid, input.profile.username, input.profile.name, at, at),
    cred.kind === 'passkey'
      ? passkeyInsertStmt(db, uid, cred.passkey, at, exists)
      : db.prepare(`INSERT INTO oauth_identities (id, user_id, provider, subject, email, email_verified, created_at, last_used_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${exists.sql}`)
        .bind(uuid(), uid, cred.provider, cred.subject, cred.email, cred.emailVerified ? 1 : 0, at, at, ...exists.params),
    ...auditStmts(db, cfg, { actorId: uid, action: 'account-created', targetUserId: uid, details: { method: cred.kind === 'passkey' ? 'passkey' : cred.provider } }, at, exists.sql, exists.params),
  ];
  try {
    await db.batch(stmts);
  } catch (e) {
    const text = String(e);
    if (!text.includes('UNIQUE')) throw e;
    // A retry of a registration that already succeeded?
    const owned = cred.kind === 'passkey'
      ? await db.prepare('SELECT 1 FROM passkeys WHERE credential_id = ? AND user_id = ?').bind(cred.passkey.credentialId, uid).first()
      : await db.prepare('SELECT 1 FROM oauth_identities WHERE provider = ? AND subject = ? AND user_id = ?').bind(cred.provider, cred.subject, uid).first();
    if (owned) return { ok: true, user: (await getUser(db, uid))!, idempotent: true };
    if (text.includes('users.username')) return fail(409, 'username_taken', MSG.usernameTaken);
    if (text.includes('users.id')) return fail(409, 'flow_used', MSG.flowUsed);
    return fail(409, 'credential_taken', PK_MSG.duplicate);
  }
  return { ok: true, user: (await getUser(db, uid))!, idempotent: false };
}

// ───────────── Passkey signup ─────────────

interface PasskeySignupFlow { method: 'passkey'; challenge: string; userId: string; profile: Profile }

/** Validate the form, check the username is free and return creation options (the account is created at verify). */
export async function startPasskeySignup(env: Env, cfg: Pick<AuthConfig, 'appName'>, body: { name?: unknown; username?: unknown }, at = Date.now()):
  Promise<Result<{ flowId: string; options: PublicKeyCredentialCreationOptionsJSON; profile: Profile }>> {
  const p = validateProfile(body);
  if (!p.ok) return p;
  const taken = await usernameFree(env.DB, p.value.username);
  if (taken) return taken;
  const userId = uuid();
  const options = await registrationOptions(env, cfg, { userId, username: p.value.username, name: p.value.name });
  const flowId = await createFlow<PasskeySignupFlow>(env.DB, 'signup', { method: 'passkey', challenge: options.challenge, userId, profile: p.value }, { at });
  return { ok: true, flowId, options, profile: p.value };
}

export async function peekPasskeySignup(db: D1Database, flowId: unknown, at = Date.now()) {
  const f = await peekFlow<PasskeySignupFlow>(db, flowId, 'signup', at);
  return f && f.data.method === 'passkey' ? f : null;
}

export async function finishPasskeySignup(env: Env, cfg: Pick<AuthConfig, 'audit'>, flowId: unknown, response: unknown, at = Date.now()): Promise<Result<Registered>> {
  const flow = await peekPasskeySignup(env.DB, flowId, at);
  if (!flow) return fail(400, 'flow_expired', MSG.flowExpired);
  const v = await verifyRegistration(env, response, flow.data.challenge);
  if (!v.ok) return v;
  return registerAccount(env, cfg, { userId: flow.data.userId, profile: flow.data.profile, credential: { kind: 'passkey', passkey: v.passkey } }, at);
}

// ───────────── Google / Apple signup (verified identity → pick a username) ─────────────

export interface OAuthIdentity { provider: Provider; subject: string; email: string | null; emailVerified: boolean; name: string | null }
export interface OAuthSignupFlow { method: 'oauth'; userId: string; identity: OAuthIdentity }

export async function startOAuthSignup(db: D1Database, identity: OAuthIdentity, at = Date.now()): Promise<string> {
  return createFlow<OAuthSignupFlow>(db, 'signup', { method: 'oauth', userId: uuid(), identity }, { at });
}

export async function getOAuthSignup(db: D1Database, flowId: unknown, at = Date.now()) {
  const f = await peekFlow<OAuthSignupFlow>(db, flowId, 'signup', at);
  return f && f.data.method === 'oauth' ? f : null;
}

export async function completeOAuthSignup(env: Env, cfg: Pick<AuthConfig, 'audit'>, flowId: unknown, body: { name?: unknown; username?: unknown }, at = Date.now()): Promise<Result<Registered>> {
  const flow = await getOAuthSignup(env.DB, flowId, at);
  if (!flow) return fail(400, 'flow_expired', MSG.flowExpired);
  const { identity, userId } = flow.data;
  const p = validateProfile(body);
  if (!p.ok) return p;
  // A retry after success: this flow's user already exists with this identity.
  const owned = await env.DB.prepare('SELECT 1 FROM oauth_identities WHERE provider = ? AND subject = ? AND user_id = ?').bind(identity.provider, identity.subject, userId).first();
  if (owned) return { ok: true, user: (await getUser(env.DB, userId))!, idempotent: true };
  const taken = await usernameFree(env.DB, p.value.username);
  if (taken) return taken;
  return registerAccount(env, cfg, {
    userId, profile: p.value,
    credential: { kind: 'oauth', provider: identity.provider, subject: identity.subject, email: identity.email, emailVerified: identity.emailVerified },
  }, at);
}
