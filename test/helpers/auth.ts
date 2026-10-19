// Test helpers: an in-memory D1 (node:sqlite), a config, users/passkeys, WebAuthn stubs and an HTTP client for the example app.
import { vi } from 'vitest';
import { createTestDb } from './d1';
import { resolveConfig, type AuthConfig } from '../../src/auth/config';
import { webauthn, type NewPasskey } from '../../src/auth/passkeys';
import { randomToken } from '../../src/auth/crypto';
import type { UserRow } from '../../src/auth/users';
import type { AuthBindings, AuthOptions } from '../../src/auth/types';

export const ORIGIN = 'http://localhost:8787';

export function makeEnv(overrides: Partial<AuthBindings> = {}): AuthBindings {
  return { DB: createTestDb(), APP_ENV: 'local', APP_ORIGIN: ORIGIN, PASSKEY_RP_ID: 'localhost', SESSION_SECRET: 'x'.repeat(40), ...overrides };
}

export const makeCfg = (o: Partial<AuthOptions> = {}): AuthConfig => resolveConfig({ appName: 'Test App', ...o });

let seq = 0;
export async function insertUser(db: D1Database, o: Partial<UserRow> = {}): Promise<UserRow> {
  seq++;
  const at = Date.now();
  const u: UserRow = { id: crypto.randomUUID(), username: `user${seq}`, name: `User ${seq}`, status: 'active', access_version: 1, created_at: at, updated_at: at, ...o };
  const cols = Object.keys(u);
  await db.prepare(`INSERT INTO users (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).bind(...Object.values(u)).run();
  return u;
}

export async function insertPasskey(db: D1Database, userId: string, o: { credentialId?: string; rpId?: string; counter?: number } = {}) {
  const id = crypto.randomUUID();
  const credentialId = o.credentialId ?? randomToken(16);
  await db.prepare('INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, rp_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, userId, credentialId, 'pQECAyYgASFYIA', o.counter ?? 0, o.rpId ?? 'localhost', Date.now()).run();
  return { id, credentialId };
}

export async function insertIdentity(db: D1Database, userId: string, o: { id?: string; provider?: 'google' | 'apple'; subject?: string } = {}) {
  const id = o.id ?? crypto.randomUUID();
  await db.prepare('INSERT INTO oauth_identities (id, user_id, provider, subject, created_at) VALUES (?, ?, ?, ?, 1)').bind(id, userId, o.provider ?? 'google', o.subject ?? `sub-${id}`).run();
  return id;
}

export function fakePasskey(o: Partial<NewPasskey> = {}): NewPasskey {
  return { credentialId: randomToken(16), publicKey: 'pQECAyYgASFYIA', counter: 0, transports: ['internal'], deviceType: 'multiDevice', backedUp: true, aaguid: '00000000-0000-0000-0000-000000000000', name: 'Passkey', rpId: 'localhost', ...o };
}

/** Make verifyRegistrationResponse succeed with the given credential id (iCloud Keychain AAGUID). */
export function mockRegistration(credentialId = randomToken(16)) {
  return vi.spyOn(webauthn, 'verifyRegistrationResponse').mockResolvedValue({
    verified: true,
    registrationInfo: {
      fmt: 'none', aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd', credentialType: 'public-key', attestationObject: new Uint8Array(),
      userVerified: true, credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: 'localhost',
      credential: { id: credentialId, publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ['internal'] },
    },
  } as never);
}

export function mockAuthentication(o: { rpID?: string; newCounter?: number; verified?: boolean } = {}) {
  return vi.spyOn(webauthn, 'verifyAuthenticationResponse').mockResolvedValue({
    verified: o.verified ?? true,
    authenticationInfo: { credentialID: 'x', newCounter: o.newCounter ?? 1, userVerified: true, credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: o.rpID ?? 'localhost' },
  } as never);
}

export const credentialResponse = (id: string, userHandle?: string) =>
  ({ id, rawId: id, type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', ...(userHandle ? { userHandle } : {}) }, clientExtensionResults: {} });

export const count = async (db: D1Database, sql: string, ...params: unknown[]) => (await db.prepare(sql).bind(...params).first<{ n: number }>())!.n;

/** Work handed to ctx.waitUntil by the requests made through client(); await settle() before checking its effects. */
const background: Promise<unknown>[] = [];
export const settle = async () => { while (background.length) await background.shift(); };

/** Requests against a Worker `fetch`: same-origin by default for writes; `cookie`, `ip` and `origin` per call. */
export function client(fetchFn: (req: Request, env: AuthBindings, ctx: ExecutionContext) => Response | Promise<Response>, env: AuthBindings) {
  return (path: string, init: RequestInit & { cookie?: string; ip?: string; origin?: string | null } = {}) => {
    const headers = new Headers(init.headers);
    if (init.method && init.method !== 'GET' && init.origin !== null) headers.set('origin', init.origin ?? ORIGIN);
    if (init.cookie) headers.set('cookie', init.cookie);
    if (init.ip) headers.set('CF-Connecting-IP', init.ip);
    const ctx = { waitUntil(p: Promise<unknown>) { background.push(p); }, passThroughOnException() {} } as unknown as ExecutionContext;
    return fetchFn(new Request(ORIGIN + path, { ...init, headers }), env, ctx);
  };
}

export const setCookieOf = (res: Response, name: string) => res.headers.getSetCookie().find(c => c.startsWith(name + '='));
export const cookiePair = (res: Response, name: string) => setCookieOf(res, name)?.split(';')[0];
