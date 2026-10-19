// WebAuthn ceremonies with @simplewebauthn/server: registration, usernameless (discoverable) login, step-up, and
// managing a user's passkeys. Challenges live in auth_flows (single use, 10 minutes).
import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON, type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { AuthConfig } from './config';
import { b64url, fromB64url, uuid } from './crypto';
import { createFlow, takeFlow } from './flows';
import { changeAndRotateStmts } from './session';
import { auditStmts, blockedFail, fail, getUser, isBlocked, type Fail, type Result, type UserRow } from './users';
import type { AuthBindings } from './types';

/** Indirection so tests can stub the crypto (vi.spyOn(webauthn, 'verifyAuthenticationResponse')). */
export const webauthn = { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse };

/** ES256 and RS256 (Windows Hello still uses RS256). */
const ALGORITHMS = [-7, -257];
const TIMEOUT = 120_000;

export const MSG = {
  flowExpired: 'This took too long. Please try again.',
  invalid: 'The passkey couldn’t be verified. Please try again.',
  unknown: 'This passkey isn’t known (any more). Use another passkey or create an account.',
  noPasskey: 'You don’t have a passkey here yet. Confirm with Google or Apple instead.',
  notYours: 'This passkey doesn’t belong to your account.',
  lastMethod: 'You can’t remove your last way to sign in. Add another passkey or link Google or Apple first.',
  notFound: 'This passkey doesn’t exist (any more).',
  name: 'Give the passkey a name of 1 to 60 characters.',
  duplicate: 'This passkey is already linked to an account.',
};

export interface PasskeyRow {
  id: string; user_id: string; credential_id: string; public_key: string; counter: number; transports: string | null;
  device_type: string | null; backed_up: number; aaguid: string | null; name: string; rp_id: string; created_at: number; last_used_at: number | null;
}

export interface NewPasskey {
  credentialId: string; publicKey: string; counter: number; transports: string[];
  deviceType: string; backedUp: boolean; aaguid: string; name: string; rpId: string;
}

type Env = Pick<AuthBindings, 'DB' | 'APP_ORIGIN' | 'PASSKEY_RP_ID'>;

/** WebAuthn user handle = UTF-8 bytes of users.id (a UUID; never the username or e-mail). */
export const userHandle = (userId: string) => new Uint8Array(new TextEncoder().encode(userId));
export const userHandleB64 = (userId: string) => b64url(userHandle(userId));

/** Default passkey names by AAGUID (display only; users can rename). */
const PROVIDERS: Record<string, string> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '771b48fd-d3d4-4f74-9232-fc157ab0507a': 'Edge on Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass',
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': 'Keeper',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
};
export const passkeyProvider = (aaguid: string | null | undefined): string | null => (aaguid ? PROVIDERS[aaguid.toLowerCase()] ?? null : null);

function isCredentialJson(r: unknown): r is { id: string; rawId: string; response: Record<string, unknown>; type: string } {
  const o = r as Record<string, unknown> | null;
  return !!o && typeof o === 'object' && typeof o.id === 'string' && o.id.length > 0 && o.id.length <= 1024
    && typeof o.response === 'object' && o.response !== null && o.type === 'public-key';
}

// ───────────── Registration ─────────────

export async function registrationOptions(
  env: Env, cfg: Pick<AuthConfig, 'appName'>, u: { userId: string; username: string; name: string; exclude?: Pick<PasskeyRow, 'credential_id' | 'transports' | 'rp_id'>[] },
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  return webauthn.generateRegistrationOptions({
    rpName: cfg.appName,
    rpID: env.PASSKEY_RP_ID,
    userName: u.username,
    userDisplayName: u.name,
    userID: userHandle(u.userId),
    attestationType: 'none',
    excludeCredentials: (u.exclude ?? []).filter(p => p.rp_id === env.PASSKEY_RP_ID)
      .map(p => ({ id: p.credential_id, transports: p.transports ? (p.transports.split(',') as never) : undefined })),
    // Discoverable credential (usernameless login) with user verification (biometrics or device PIN).
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    supportedAlgorithmIDs: ALGORITHMS,
    timeout: TIMEOUT,
  });
}

export async function verifyRegistration(env: Env, response: unknown, expectedChallenge: string): Promise<Result<{ passkey: NewPasskey }>> {
  if (!isCredentialJson(response)) return fail(400, 'passkey_invalid', MSG.invalid);
  try {
    const v = await webauthn.verifyRegistrationResponse({
      response: response as unknown as RegistrationResponseJSON,
      expectedChallenge,
      expectedOrigin: env.APP_ORIGIN,
      expectedRPID: env.PASSKEY_RP_ID,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGORITHMS,
    });
    if (!v.verified) return fail(400, 'passkey_invalid', MSG.invalid);
    const info = v.registrationInfo;
    const transports: string[] = info.credential.transports ?? (response as unknown as RegistrationResponseJSON).response.transports ?? [];
    return {
      ok: true,
      passkey: {
        credentialId: info.credential.id,
        publicKey: b64url(info.credential.publicKey),
        counter: info.credential.counter,
        transports: transports.filter(t => typeof t === 'string').slice(0, 8),
        deviceType: info.credentialDeviceType,
        backedUp: info.credentialBackedUp,
        aaguid: info.aaguid,
        name: passkeyProvider(info.aaguid) ?? 'Passkey',
        rpId: env.PASSKEY_RP_ID,
      },
    };
  } catch {
    return fail(400, 'passkey_invalid', MSG.invalid);
  }
}

/** INSERT for a verified passkey. With `where`, the row is only written when the SQL condition holds (batch chaining). */
export function passkeyInsertStmt(db: D1Database, userId: string, p: NewPasskey, at = Date.now(), where?: { sql: string; params: unknown[] }): D1PreparedStatement {
  const cols = 'id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, aaguid, name, rp_id, created_at, last_used_at';
  const vals = [uuid(), userId, p.credentialId, p.publicKey, p.counter, p.transports.join(',') || null, p.deviceType, p.backedUp ? 1 : 0, p.aaguid, p.name, p.rpId, at, at];
  if (!where) return db.prepare(`INSERT INTO passkeys (${cols}) VALUES (${vals.map(() => '?').join(', ')})`).bind(...vals);
  return db.prepare(`INSERT INTO passkeys (${cols}) SELECT ${vals.map(() => '?').join(', ')} WHERE ${where.sql}`).bind(...vals, ...where.params);
}

// ───────────── Login (usernameless) ─────────────

interface ChallengeFlow { challenge: string }

/** Discoverable login: empty allowCredentials, so the browser offers the user's passkeys; no username needed. */
export async function startLogin(env: Env): Promise<{ flowId: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  const options = await webauthn.generateAuthenticationOptions({ rpID: env.PASSKEY_RP_ID, allowCredentials: [], userVerification: 'required', timeout: TIMEOUT });
  const flowId = await createFlow<ChallengeFlow>(env.DB, 'passkey-login', { challenge: options.challenge });
  return { flowId, options };
}

/**
 * An unknown credential. `signalUnknown` says whether the client may call PublicKeyCredential.signalUnknownCredential,
 * which makes the password manager hide or delete that passkey. Only when it is provably ours and orphaned: the user
 * handle is one of our UUIDs and no such user exists. Never on a guess (another app may share the RP ID).
 */
export type UnknownCredential = Fail & { credentialId: string; rpId: string; signalUnknown: boolean };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The assertion's user handle as our user id, or null when absent or not UUID-shaped. */
export function userIdFromHandle(response: unknown): string | null {
  const h = (response as { response?: { userHandle?: unknown } } | null)?.response?.userHandle;
  if (typeof h !== 'string' || !h || h.length > 128 || !/^[A-Za-z0-9_-]+$/.test(h)) return null;
  try {
    const id = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(fromB64url(h));
    return UUID_RE.test(id) ? id.toLowerCase() : null;
  } catch {
    return null;
  }
}

async function unknownCredential(env: Env, credentialId: string, response: unknown): Promise<UnknownCredential> {
  const userId = userIdFromHandle(response);
  const signal = !!userId && !(await env.DB.prepare('SELECT 1 FROM users WHERE id = ?').bind(userId).first());
  return { ...fail(404, 'unknown_credential', MSG.unknown), credentialId, rpId: env.PASSKEY_RP_ID, signalUnknown: signal };
}

async function verifyAssertion(env: Env, pk: PasskeyRow, response: AuthenticationResponseJSON, challenge: string): Promise<{ newCounter: number; backedUp: boolean } | null> {
  try {
    const v = await webauthn.verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: env.APP_ORIGIN,
      expectedRPID: env.PASSKEY_RP_ID,
      credential: { id: pk.credential_id, publicKey: new Uint8Array(fromB64url(pk.public_key)), counter: pk.counter, transports: pk.transports ? (pk.transports.split(',') as never) : undefined },
      requireUserVerification: true,
    });
    if (!v.verified || v.authenticationInfo.rpID !== pk.rp_id) return null;
    return { newCounter: v.authenticationInfo.newCounter, backedUp: v.authenticationInfo.credentialBackedUp };
  } catch {
    return null;
  }
}

/**
 * Persist a verified assertion. The counter only moves forward: two assertions verified against the same stored
 * counter may finish in either order, and a lower one must not overwrite a higher one. Synced passkeys report 0.
 */
const counterUpdateStmt = (db: D1Database, id: string, v: { newCounter: number; backedUp: boolean }, at: number) =>
  db.prepare('UPDATE passkeys SET counter = MAX(counter, ?), backed_up = ?, last_used_at = ? WHERE id = ?').bind(v.newCounter, v.backedUp ? 1 : 0, at, id);

export interface LoginSuccess { user: UserRow; passkey: PasskeyRow; acceptedCredentialIds: string[] }

export async function finishLogin(env: Env, flowId: unknown, response: unknown, at = Date.now()): Promise<({ ok: true } & LoginSuccess) | Fail | UnknownCredential> {
  const flow = await takeFlow<ChallengeFlow>(env.DB, flowId, 'passkey-login', at);
  if (!flow) return fail(400, 'flow_expired', MSG.flowExpired);
  if (!isCredentialJson(response)) return fail(400, 'passkey_invalid', MSG.invalid);
  const pk = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ?').bind(response.id).first<PasskeyRow>();
  if (!pk) return unknownCredential(env, response.id, response);
  const user = await getUser(env.DB, pk.user_id);
  if (!user) return unknownCredential(env, response.id, response);
  if (isBlocked(user.status)) return blockedFail(user.id);
  const v = await verifyAssertion(env, pk, response as unknown as AuthenticationResponseJSON, flow.data.challenge);
  if (!v) return fail(400, 'passkey_invalid', MSG.invalid);
  await counterUpdateStmt(env.DB, pk.id, v, at).run();
  return { ok: true, user, passkey: pk, acceptedCredentialIds: await acceptedCredentialIds(env, user.id) };
}

/** The user's credential ids on this RP ID (for PublicKeyCredential.signalAllAcceptedCredentials). */
export async function acceptedCredentialIds(env: Env, userId: string): Promise<string[]> {
  const r = await env.DB.prepare('SELECT credential_id FROM passkeys WHERE user_id = ? AND rp_id = ?').bind(userId, env.PASSKEY_RP_ID).all<{ credential_id: string }>();
  return r.results.map(x => x.credential_id);
}

// ───────────── Step-up (fresh auth) ─────────────

export async function startReauth(env: Env, userId: string): Promise<Result<{ flowId: string; options: PublicKeyCredentialRequestOptionsJSON }>> {
  const rows = (await env.DB.prepare('SELECT credential_id, transports FROM passkeys WHERE user_id = ? AND rp_id = ?').bind(userId, env.PASSKEY_RP_ID).all<PasskeyRow>()).results;
  if (!rows.length) return fail(409, 'no_passkey', MSG.noPasskey);
  const options = await webauthn.generateAuthenticationOptions({
    rpID: env.PASSKEY_RP_ID, userVerification: 'required', timeout: TIMEOUT,
    allowCredentials: rows.map(p => ({ id: p.credential_id, transports: p.transports ? (p.transports.split(',') as never) : undefined })),
  });
  const flowId = await createFlow<ChallengeFlow>(env.DB, 'reauth', { challenge: options.challenge }, { userId });
  return { ok: true, flowId, options };
}

export async function finishReauth(env: Env, userId: string, flowId: unknown, response: unknown, at = Date.now()): Promise<Result> {
  const flow = await takeFlow<ChallengeFlow>(env.DB, flowId, 'reauth', at);
  if (!flow || flow.userId !== userId) return fail(400, 'flow_expired', MSG.flowExpired);
  if (!isCredentialJson(response)) return fail(400, 'passkey_invalid', MSG.invalid);
  const pk = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ?').bind(response.id).first<PasskeyRow>();
  if (!pk || pk.user_id !== userId) return fail(403, 'passkey_not_yours', MSG.notYours);
  const v = await verifyAssertion(env, pk, response as unknown as AuthenticationResponseJSON, flow.data.challenge);
  if (!v) return fail(400, 'passkey_invalid', MSG.invalid);
  await counterUpdateStmt(env.DB, pk.id, v, at).run();
  return { ok: true };
}

// ───────────── Add a passkey to a signed-in account ─────────────

export async function startAddPasskey(env: Env, cfg: Pick<AuthConfig, 'appName'>, user: Pick<UserRow, 'id' | 'username' | 'name'>): Promise<{ flowId: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  const exclude = (await env.DB.prepare('SELECT credential_id, transports, rp_id FROM passkeys WHERE user_id = ?').bind(user.id).all<PasskeyRow>()).results;
  const options = await registrationOptions(env, cfg, { userId: user.id, username: user.username, name: user.name, exclude });
  const flowId = await createFlow<ChallengeFlow>(env.DB, 'passkey-register', { challenge: options.challenge }, { userId: user.id });
  return { flowId, options };
}

export async function finishAddPasskey(env: Env, cfg: Pick<AuthConfig, 'audit'>, userId: string, flowId: unknown, response: unknown, at = Date.now()): Promise<Result<{ passkey: PasskeyView }>> {
  const flow = await takeFlow<ChallengeFlow>(env.DB, flowId, 'passkey-register', at);
  if (!flow || flow.userId !== userId) return fail(400, 'flow_expired', MSG.flowExpired);
  const v = await verifyRegistration(env, response, flow.data.challenge);
  if (!v.ok) return v;
  try {
    await env.DB.batch([
      passkeyInsertStmt(env.DB, userId, v.passkey, at),
      ...auditStmts(env.DB, cfg, { actorId: userId, action: 'passkey-added', targetUserId: userId, details: { credentialId: v.passkey.credentialId } }, at, 'changes() = 1'),
    ]);
  } catch (e) {
    if (String(e).includes('UNIQUE')) return fail(409, 'passkey_duplicate', MSG.duplicate);
    throw e;
  }
  const row = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ?').bind(v.passkey.credentialId).first<PasskeyRow>();
  return { ok: true, passkey: toView(row!) };
}

// ───────────── Management ─────────────

export interface PasskeyView { id: string; name: string; createdAt: number; lastUsedAt: number | null; deviceType: string | null; backedUp: boolean; provider: string | null }

export const toView = (r: PasskeyRow): PasskeyView => ({
  id: r.id, name: r.name, createdAt: r.created_at, lastUsedAt: r.last_used_at, deviceType: r.device_type, backedUp: r.backed_up === 1, provider: passkeyProvider(r.aaguid),
});

export async function listPasskeys(db: D1Database, userId: string): Promise<PasskeyView[]> {
  return (await db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at').bind(userId).all<PasskeyRow>()).results.map(toView);
}

export async function renamePasskey(db: D1Database, userId: string, id: string, name: unknown): Promise<Result> {
  const v = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ') : '';
  if (v.length < 1 || v.length > 60 || /[\u0000-\u001f\u007f]/.test(v)) return fail(422, 'invalid_name', MSG.name);
  const r = await db.prepare('UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?').bind(v, id, userId).run();
  return r.meta.changes === 1 ? { ok: true } : fail(404, 'not_found', MSG.notFound);
}

/**
 * Delete one of the user's own passkeys, never their last way to sign in (passkeys + linked identities). In the same
 * batch access_version advances, so every other session ends (the removed passkey may have been used elsewhere);
 * `keepSessionId` (this device) moves to the new version.
 */
export async function deletePasskey(db: D1Database, cfg: Pick<AuthConfig, 'audit'>, userId: string, id: string, at = Date.now(), keepSessionId: string | null = null): Promise<Result> {
  const res = await db.batch(changeAndRotateStmts(db,
    db.prepare(`DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2
      AND (SELECT COUNT(*) FROM passkeys WHERE user_id = ?2) + (SELECT COUNT(*) FROM oauth_identities WHERE user_id = ?2) > 1`).bind(id, userId),
    auditStmts(db, cfg, { actorId: userId, action: 'passkey-removed', targetUserId: userId, details: { passkeyId: id } }, at, 'changes() = 1'),
    userId, keepSessionId, at));
  if (res[0]?.meta.changes === 1) return { ok: true };
  const exists = await db.prepare('SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?').bind(id, userId).first();
  return exists ? fail(409, 'last_sign_in_method', MSG.lastMethod) : fail(404, 'not_found', MSG.notFound);
}
