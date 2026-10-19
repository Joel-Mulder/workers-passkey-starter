// Public types: the Worker bindings the auth code reads, the session it puts on the context, and the options of
// createAuth(). Your app's Hono env must include these (see README.md, "Integrate into an existing app").
import type { Context } from 'hono';

export interface AuthBindings {
  DB: D1Database;
  /** 'local' for `wrangler dev` over http (cookies without Secure, no HSTS). Anything else counts as deployed. */
  APP_ENV: string;
  /** Exact origin the browser sees, e.g. https://example.com (no trailing slash). WebAuthn checks it. */
  APP_ORIGIN: string;
  /** WebAuthn RP ID: APP_ORIGIN's host or a registrable parent of it (example.com for app.example.com). */
  PASSKEY_RP_ID: string;
  /** Secret, at least 32 random characters. Keys the HMAC of client IPs in rate-limit keys; rotating it signs nobody out. */
  SESSION_SECRET: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  /** Apple Services ID (not the App ID). */
  APPLE_CLIENT_ID?: string;
  APPLE_TEAM_ID?: string;
  APPLE_KEY_ID?: string;
  /** Contents of the .p8 key file (PEM, PKCS#8). */
  APPLE_PRIVATE_KEY?: string;
}

export type UserStatus = 'active' | 'suspended';
export type AuthMethod = 'passkey' | 'google' | 'apple';
export type Provider = 'google' | 'apple';

export interface SessionUser { id: string; username: string; name: string; status: UserStatus }

export interface SessionInfo {
  /** sessions.id: SHA-256 of the cookie token. */
  id: string;
  user: SessionUser;
  authMethod: AuthMethod;
  /** Last full sign-in or step-up (requireFreshAuth). */
  authenticatedAt: number;
  expiresAt: number;
}

export interface AuthVariables {
  /** Set by auth.session on every request: the signed-in user's session, or null. */
  session: SessionInfo | null;
  /** Per-response CSP nonce, set by auth.securityHeaders. Put it on your <script> tags. */
  nonce: string;
}

export type AuthEnv = { Bindings: AuthBindings; Variables: AuthVariables };
export type AuthContext = Context<AuthEnv>;

/** What allowSignup() is asked about. `identity` is set for Google/Apple signups. */
export interface SignupRequest {
  c: AuthContext;
  method: AuthMethod;
  /** Known once the user has filled in the form (passkey signup, or the username step after Google/Apple). */
  username?: string;
  name?: string;
  identity?: { provider: Provider; email: string | null; emailVerified: boolean };
}

export interface NewUserEvent {
  c: AuthContext;
  user: SessionUser;
  method: AuthMethod;
  identity?: { provider: Provider; email: string | null; emailVerified: boolean };
}

export type SecurityEventKind = 'signin-failed' | 'signin-blocked' | 'reauth-failed' | 'throttled' | 'origin-blocked';

/** No personal data: `source` is a short HMAC of the client IP, codes are fixed strings. */
export interface SecurityEvent { kind: SecurityEventKind; code: string; userId?: string | null; source?: string | null }

export interface PageInput {
  title: string;
  /** Trusted HTML (built with the escaping `html` helper in pages.ts). */
  body: string;
  status?: number;
  /** Module scripts to load (absolute paths); add the CSP nonce from c.get('nonce'). */
  scripts?: string[];
}

export interface AuthOptions {
  /** Shown in the browser's passkey sheet (WebAuthn RP name) and in page titles. */
  appName: string;
  /** Where the auth routes are mounted, e.g. '' (default) or '/app'. Must match app.route(basePath, auth.routes). */
  basePath?: string;
  /** Cookie names are `${cookiePrefix}_session`, `_oauth` and `_signup`. Default 'auth'. */
  cookiePrefix?: string;
  /** Where to go after sign-in when there is no returnTo. Default '/' under basePath. */
  afterSignInPath?: string;
  /** Session lifetime, sliding. Default 30 days. */
  sessionTtlMs?: number;
  /** Renew the sliding session at most this often. Default 1 day. */
  renewAfterMs?: number;
  /** How long a sign-in or step-up counts as fresh for requireFreshAuth. Default 5 minutes. */
  freshAuthMs?: number;
  /** Unauthenticated flow starts (passkey options, Google/Apple start, signup) per IP per window. Default 60 per 10 min. */
  flowStartsPerWindow?: number;
  flowStartWindowMs?: number;
  /** Write audit_log rows (same batch as each change). Default true. */
  audit?: boolean;
  /**
   * Who may create an account. Default: everyone. Return true to allow, false or a message (shown to the user) to
   * refuse. Asked when a signup starts and again right before the account is created.
   */
  allowSignup?: (req: SignupRequest) => boolean | string | Promise<boolean | string>;
  /** After an account was created (e.g. send a welcome or e-mail verification mail; c.executionCtx.waitUntil for slow work). */
  onUserCreated?: (e: NewUserEvent) => void | Promise<void>;
  /**
   * After a user deleted their own account (the users row is gone). Clean up your own data here unless your tables
   * reference users(id) with ON DELETE CASCADE. Must not throw.
   */
  onUserDeleted?: (e: { c: AuthContext; userId: string; username: string }) => void | Promise<void>;
  /** Failed sign-ins, throttling, blocked cross-origin writes. Default: one JSON line via console.warn. Must not throw. */
  onSecurityEvent?: (e: SecurityEvent, c: AuthContext) => void | Promise<void>;
  /** Wrap the built-in pages in your own layout. Default: a minimal unstyled HTML document. */
  renderPage?: (c: AuthContext, page: PageInput) => Response | Promise<Response>;
}
