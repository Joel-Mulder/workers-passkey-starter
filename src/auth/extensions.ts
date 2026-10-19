// Extension points for the optional modules (src/auth/modules/*). Core only calls these hooks; it never imports a
// module, so an app without modules bundles none of their code. Modules need migrations/0002_modules.sql.
import type { Hono } from 'hono';
import type { AuthConfig } from './config';
import type { OAuthIdentity } from './registration';
import type { Profile } from './validation';
import type { Fail, UserRow } from './users';
import type { AuthBindings, AuthContext, AuthEnv, AuthMethod } from './types';

/** Data the modules attach to a signup, stored with the signup flow and handed back at registration. */
export type ModuleData = Record<string, unknown>;

export interface SignupStage {
  c: AuthContext;
  cfg: AuthConfig;
  /** 'start': a Google/Apple signup is about to leave for the provider (only params are known). 'details': the form was filled in. */
  stage: 'start' | 'details';
  method: AuthMethod;
  /** Values of the modules' signupParams (e.g. an invite token), from the query or form. */
  params: Record<string, string>;
  /** Other form fields (e.g. email), 'details' only. */
  fields: Record<string, string>;
  profile?: Profile;
  identity?: OAuthIdentity;
  /** What earlier modules returned for this signup. */
  data: ModuleData;
}

export interface RegisterContext {
  c: AuthContext | null;
  env: Pick<AuthBindings, 'DB' | 'APP_ORIGIN' | 'PASSKEY_RP_ID'>;
  cfg: AuthConfig;
  userId: string;
  at: number;
  profile: Profile;
  method: AuthMethod;
  identity?: OAuthIdentity;
  params: Record<string, string>;
  /** Shared by all modules for this signup; register() may add to it for afterRegister(). */
  data: ModuleData;
  /** SQL condition (with params) that holds once the user row of this registration exists. Guard every statement with it. */
  exists: { sql: string; params: unknown[] };
}

export interface RegisterPart {
  /**
   * A quota statement that must change exactly one row for the account to be created (an invite or signup-link use).
   * It runs first in the batch; the user row is only inserted when it did. At most one module may return a gate.
   */
  gate?: D1PreparedStatement;
  /** The error to report when the gate changed nothing. */
  gateFailed?: () => Promise<Fail>;
  /** Extra statements for the same batch, after the user and credential rows. Guard them with ctx.exists. */
  stmts?: D1PreparedStatement[];
}

export interface AuthModule {
  name: string;
  /** Query/form keys carried from the start of a signup to the registration, e.g. ['invite', 'link']. */
  signupParams?: readonly string[];
  /** Validate a signup; return data to keep with it, or a Fail to refuse. */
  prepareSignup?(s: SignupStage): Promise<Fail | ModuleData | void>;
  /** Contribute to the atomic registration batch. */
  register?(r: RegisterContext): Promise<RegisterPart | void>;
  /** After the batch committed (new accounts only, not idempotent retries). Must not throw. */
  afterRegister?(r: RegisterContext & { user: UserRow }): Promise<void>;
  /** After a recovery link was used (the new passkey is in place). Must not throw. */
  afterRecovery?(x: { c: AuthContext; cfg: AuthConfig; user: UserRow; tokenId: string }): Promise<void>;
  /** Turn a UNIQUE/constraint error of the registration batch into a Fail (e.g. an e-mail address taken meanwhile). */
  mapError?(message: string): Fail | null;
  /** Why a blocked user can't sign in (e.g. waiting for approval). null = not this module's business. */
  blockedReason?(db: D1Database, userId: string): Promise<Fail | null>;
  /** Extra routes, registered after the core routes. */
  routes?(r: Hono<AuthEnv>, cfg: AuthConfig): void;
  /** HTML added to the built-in pages (already escaped: build it with the html`` helper). */
  html?: {
    login?(c: AuthContext, cfg: AuthConfig): string | Promise<string>;
    /** Inside the signup form (fields and hidden inputs). */
    signup?(c: AuthContext, cfg: AuthConfig, params: Record<string, string>): string | Promise<string>;
    /** Inside the username step after Google/Apple. */
    signupComplete?(c: AuthContext, cfg: AuthConfig, x: { params: Record<string, string>; identity: OAuthIdentity; fields: Record<string, string> }): string | Promise<string>;
    account?(c: AuthContext, cfg: AuthConfig, userId: string): Promise<string>;
    /** On the admin page (admin module). */
    admin?(c: AuthContext, cfg: AuthConfig): Promise<string>;
  };
}

/** The modules' signup params from a lookup (query or form), only non-empty strings of at most 128 characters. */
export function signupParamsOf(cfg: AuthConfig, get: (key: string) => unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of cfg.modules) for (const k of m.signupParams ?? []) {
    const v = get(k);
    if (typeof v === 'string' && v && v.length <= 128) out[k] = v;
  }
  return out;
}

const isFail = (v: unknown): v is Fail => !!v && typeof v === 'object' && (v as Fail).ok === false;

/** Run every module's prepareSignup in order; the first refusal wins. */
export async function prepareSignup(cfg: AuthConfig, s: Omit<SignupStage, 'cfg' | 'data'>, data: ModuleData = {}): Promise<Fail | ModuleData> {
  const merged: ModuleData = { ...data };
  for (const m of cfg.modules) {
    if (!m.prepareSignup) continue;
    const r = await m.prepareSignup({ ...s, cfg, data: merged });
    if (isFail(r)) return r;
    if (r) Object.assign(merged, r);
  }
  return merged;
}

/** Collect the modules' registration parts. */
export async function registerParts(cfg: AuthConfig, r: RegisterContext): Promise<RegisterPart[]> {
  const parts: RegisterPart[] = [];
  for (const m of cfg.modules) {
    const p = m.register ? await m.register(r) : undefined;
    if (p) parts.push(p);
  }
  if (parts.filter(p => p.gate).length > 1) throw new Error('At most one module may return a registration gate');
  return parts;
}

export async function afterRegister(cfg: AuthConfig, r: RegisterContext & { user: UserRow }, onError: (e: unknown) => void): Promise<void> {
  for (const m of cfg.modules) {
    if (!m.afterRegister) continue;
    try { await m.afterRegister(r); } catch (e) { onError(e); }
  }
}

export function mapRegistrationError(cfg: AuthConfig, message: string): Fail | null {
  for (const m of cfg.modules) {
    const f = m.mapError?.(message);
    if (f) return f;
  }
  return null;
}

/** A blocked user's Fail with the module's explanation (pending, rejected), or the Fail unchanged. */
export async function explainBlocked<F extends Fail>(db: D1Database, cfg: AuthConfig, f: F): Promise<F> {
  if (f.code !== 'account_suspended' || !f.userId) return f;
  for (const m of cfg.modules) {
    const r = await m.blockedReason?.(db, f.userId);
    if (r) return { ...f, ...r, userId: f.userId };
  }
  return f;
}

/** Concatenated module HTML for a page slot ('' without modules). */
export async function moduleHtml(cfg: AuthConfig, render: (m: AuthModule) => string | Promise<string> | undefined): Promise<string> {
  if (!cfg.modules.length) return '';
  return (await Promise.all(cfg.modules.map(m => render(m) ?? ''))).join('');
}
