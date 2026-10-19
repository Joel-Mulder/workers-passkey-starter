// Helpers for the module tests: an app with the chosen modules, a memory mailer, and signup/session shortcuts.
import { vi } from 'vitest';
import { Hono } from 'hono';
import { createAuth, type AuthEnv, type AuthOptions } from '../../src/auth';
import { admin, emailVerification, invites, mail, memoryMailer, type AdminOptions, type EmailVerificationOptions } from '../../src/auth/modules';
import { insertSession } from '../../src/auth/session';
import { webauthn } from '../../src/auth/passkeys';
import type { AuthModule } from '../../src/auth/extensions';
import { client, cookiePair, insertPasskey, insertUser, makeCfg, makeEnv, ORIGIN, settle } from '../helpers/auth';
import type { UserRow } from '../../src/auth/users';

export interface Setup {
  mail?: boolean;
  email?: EmailVerificationOptions | false;
  admin?: AdminOptions | false;
  invites?: boolean;
  options?: Partial<AuthOptions>;
}

export function moduleApp(s: Setup = {}) {
  const outbox = memoryMailer();
  const modules: AuthModule[] = [];
  if (s.mail !== false) modules.push(mail({ mailer: () => outbox }));
  if (s.email) modules.push(emailVerification(s.email));
  if (s.admin) modules.push(admin(s.admin));
  if (s.invites) modules.push(invites());
  const auth = createAuth({ appName: 'Test App', ...s.options, modules });
  const app = new Hono<AuthEnv>();
  app.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
  app.route('/', auth.routes);
  const env = makeEnv();
  // client() passes a ctx whose waitUntil work settle() awaits.
  const req = client((r, e, ctx) => app.fetch(r, e, ctx), env);
  return { auth, app, env, req, outbox, cfg: auth.config, settle };
}

export const json = (body: unknown) => ({ method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

let credSeq = 0;
/** Passkey signup through the HTTP API (the WebAuthn check stubbed). Returns the verify response and its JSON. */
export async function signupPasskey(req: ReturnType<typeof moduleApp>['req'], body: Record<string, unknown>) {
  const credentialId = `cred-${++credSeq}`;
  const spy = vi.spyOn(webauthn, 'verifyRegistrationResponse').mockResolvedValue({
    verified: true,
    registrationInfo: {
      fmt: 'none', aaguid: '00000000-0000-0000-0000-000000000000', credentialType: 'public-key', attestationObject: new Uint8Array(), userVerified: true,
      credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: 'localhost', credential: { id: credentialId, publicKey: new Uint8Array([1]), counter: 0, transports: [] },
    },
  } as never);
  const opts = await req('/auth/api/signup/options', json(body));
  const optsJson = await opts.json() as { flowId?: string; error?: { code: string; message: string } };
  if (!opts.ok) { spy.mockRestore(); return { status: opts.status, json: optsJson as Record<string, unknown>, cookie: undefined as string | undefined, credentialId }; }
  const res = await req('/auth/api/signup/verify', json({ flowId: optsJson.flowId, response: { id: credentialId, rawId: credentialId, type: 'public-key', response: {} } }));
  spy.mockRestore();
  return { status: res.status, json: await res.json() as Record<string, unknown>, cookie: cookiePair(res, 'auth_session'), credentialId };
}

/** Start a passkey signup (options only); finish it later with finishSignup (for race tests). */
export async function startSignup(req: ReturnType<typeof moduleApp>['req'], body: Record<string, unknown>) {
  const res = await req('/auth/api/signup/options', json(body));
  return { status: res.status, json: await res.json() as { flowId: string; error?: { code: string } } };
}
export async function finishSignup(req: ReturnType<typeof moduleApp>['req'], flowId: string, credentialId: string) {
  const res = await req('/auth/api/signup/verify', json({ flowId, response: { id: credentialId, rawId: credentialId, type: 'public-key', response: {} } }));
  return { status: res.status, json: await res.json() as Record<string, unknown> };
}
/** Make every verifyRegistrationResponse succeed with the response's own credential id. */
export function acceptAnyRegistration() {
  return vi.spyOn(webauthn, 'verifyRegistrationResponse').mockImplementation(async ({ response }) => ({
    verified: true,
    registrationInfo: {
      fmt: 'none', aaguid: '00000000-0000-0000-0000-000000000000', credentialType: 'public-key', attestationObject: new Uint8Array(), userVerified: true,
      credentialDeviceType: 'multiDevice', credentialBackedUp: true, origin: ORIGIN, rpID: 'localhost', credential: { id: (response as { id: string }).id, publicKey: new Uint8Array([1]), counter: 0, transports: [] },
    },
  }) as never);
}

/** A fresh session cookie for `user` (signed in just now, so step-up passes). `ageMs` makes it older. */
export async function sessionCookie(db: D1Database, user: UserRow, ageMs = 0) {
  const s = await insertSession(db, makeCfg(), user, 'passkey', Date.now() - ageMs);
  return `auth_session=${s.token}`;
}

/** An active admin with a passkey and a confirmed address. */
export async function makeAdmin(db: D1Database, o: { email?: string | null } = {}) {
  const u = await insertUser(db);
  await db.prepare("UPDATE users SET role = 'admin', email = ?, email_verified_at = ? WHERE id = ?").bind(o.email === undefined ? `${u.username}@example.com` : o.email, Date.now(), u.id).run();
  await insertPasskey(db, u.id);
  return u;
}

export const linkIn = (text: string) => /(https?:\/\/\S+)/.exec(text)?.[1] ?? '';
export const pathOf = (url: string) => url.replace(ORIGIN, '');
export const user = (db: D1Database, username: string) => db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first<Record<string, unknown>>();
