// Entry point: createAuth(options) returns the router and the middleware to put in front of your app.
//
//   const auth = createAuth({ appName: 'My App' });
//   app.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
//   app.route('/', auth.routes);
//   app.get('/dashboard', auth.requireUser, c => c.text(`Hi ${c.get('session')!.user.name}`));
//
// See README.md for the full integration guide.
import { cleanupExpired } from './account';
import { resolveConfig, type AuthConfig } from './config';
import { authRoutes } from './routes';
import { bodyLimitGuard, originCheck, securityHeaders, type SecurityHeaderOptions } from './security';
import { requireFreshAuth, requireUser, revokeAllSessions, sessionMiddleware } from './session';
import type { AuthOptions } from './types';

export function createAuth(options: AuthOptions & { securityHeaders?: SecurityHeaderOptions; maxBodyBytes?: number }) {
  const cfg: AuthConfig = resolveConfig(options);
  return {
    config: cfg,
    /** Mount with app.route(config.basePath || '/', auth.routes). */
    routes: authRoutes(cfg),
    /** Resolves the session cookie into c.get('session'). Put it before anything that reads the session. */
    session: sessionMiddleware(cfg),
    /** CSRF: writes must come from APP_ORIGIN (Apple's callback excepted). */
    originCheck: originCheck(cfg),
    /** CSP with nonce, HSTS, Permissions-Policy for WebAuthn, … Optional if your app already sets its own. */
    securityHeaders: securityHeaders(options.securityHeaders),
    /** Request bodies of at most 256 KB by default, counted on the actual bytes. */
    bodyLimit: bodyLimitGuard(options.maxBodyBytes),
    /** Signed in, else redirect to the login page (pages) or 401 (paths containing /api/ or JSON requests). */
    requireUser: requireUser(cfg),
    /** Signed in or stepped up within maxAgeMs (default 5 minutes), else 403 reauth_required. */
    requireFreshAuth: (maxAgeMs?: number) => requireFreshAuth(cfg, maxAgeMs),
    /** End every session of a user (e.g. after suspending them). */
    revokeAllSessions,
    /** For a cron trigger: delete expired sessions, ceremony flows and rate counters. */
    cleanup: cleanupExpired,
  };
}

export type Auth = ReturnType<typeof createAuth>;
export type { AuthBindings, AuthEnv, AuthOptions, AuthVariables, SessionInfo, SessionUser, SignupRequest, NewUserEvent, SecurityEvent, PageInput } from './types';
export { html, escapeHtml, SafeHtml } from './pages';
