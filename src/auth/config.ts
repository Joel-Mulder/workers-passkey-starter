// AuthOptions with defaults filled in. Every module takes the resolved config explicitly; nothing is global.
import type { AuthOptions, AuthContext, PageInput, SecurityEvent } from './types';

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

export interface AuthConfig {
  appName: string;
  basePath: string;
  cookies: { session: string; oauth: string; signup: string; path: string };
  afterSignInPath: string;
  sessionTtlMs: number;
  renewAfterMs: number;
  freshAuthMs: number;
  flowStartsPerWindow: number;
  flowStartWindowMs: number;
  audit: boolean;
  allowSignup: NonNullable<AuthOptions['allowSignup']>;
  onUserCreated: NonNullable<AuthOptions['onUserCreated']>;
  onSecurityEvent: NonNullable<AuthOptions['onSecurityEvent']>;
  renderPage: ((c: AuthContext, page: PageInput) => Response | Promise<Response>) | null;
  /** Absolute path under basePath, e.g. path('/auth/login') → '/app/auth/login'. */
  path: (p: string) => string;
}

const defaultSecurityEvent = (e: SecurityEvent) => { console.warn(JSON.stringify({ security: e })); };

export function resolveConfig(o: AuthOptions): AuthConfig {
  const basePath = (o.basePath ?? '').replace(/\/+$/, '');
  if (basePath && !/^\/[A-Za-z0-9._~\-/]*$/.test(basePath)) throw new Error('basePath must start with / and contain only path characters');
  const prefix = o.cookiePrefix ?? 'auth';
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(prefix)) throw new Error('cookiePrefix: letters, digits, _ and - only');
  const path = (p: string) => basePath + (p.startsWith('/') ? p : '/' + p);
  return {
    appName: o.appName,
    basePath,
    cookies: { session: `${prefix}_session`, oauth: `${prefix}_oauth`, signup: `${prefix}_signup`, path: basePath || '/' },
    afterSignInPath: path(o.afterSignInPath ?? '/'),
    sessionTtlMs: o.sessionTtlMs ?? 30 * DAY,
    renewAfterMs: o.renewAfterMs ?? DAY,
    freshAuthMs: o.freshAuthMs ?? 5 * MINUTE,
    flowStartsPerWindow: o.flowStartsPerWindow ?? 60,
    flowStartWindowMs: o.flowStartWindowMs ?? 10 * MINUTE,
    audit: o.audit ?? true,
    allowSignup: o.allowSignup ?? (() => true),
    onUserCreated: o.onUserCreated ?? (() => {}),
    onSecurityEvent: o.onSecurityEvent ?? defaultSecurityEvent,
    renderPage: o.renderPage ?? null,
    path,
  };
}
