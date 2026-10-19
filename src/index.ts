// Example Worker: the auth kit plus two pages of "your app". Replace the example routes with your own.
import { Hono } from 'hono';
import { createAuth, html, type AuthEnv } from './auth';

export const auth = createAuth({
  appName: 'Example App',
  // Who may sign up. Default: everyone. Examples: an allow-list, an invite code you check yourself, a closed beta.
  // allowSignup: ({ username }) => username !== 'admin' || 'That username is reserved.',
  // onUserCreated: async ({ c, user }) => { /* send a welcome mail, create a profile row, … */ },
});

const app = new Hono<AuthEnv>();

// Order matters: headers wrap everything, the body limit and origin check run before any handler reads a body, and
// the session is resolved before routes that need it.
app.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
app.route(auth.config.basePath || '/', auth.routes);

app.get('/', c => {
  const s = c.get('session');
  const body = s
    ? html`<h1>Hello, ${s.user.name}</h1>
<p>You’re signed in with ${s.authMethod}.</p>
<p><a href="/private">A page only for signed-in users</a> · <a href="/auth/account">Sign-in methods</a></p>
<form method="post" action="/auth/logout"><button type="submit">Sign out</button></form>`
    : html`<h1>Example App</h1><p><a href="/auth/login">Sign in</a> or <a href="/auth/signup">create an account</a>.</p>`;
  return c.html(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Example App</title><link rel="stylesheet" href="/auth/auth.css"><main class="auth">${body}</main></html>`);
});

app.get('/private', auth.requireUser, c => c.text(`Only for signed-in users. You are ${c.get('session')!.user.username}.`));

// A sensitive action: needs a passkey (or Google/Apple) confirmation within the last 5 minutes.
app.post('/api/example/sensitive', auth.requireUser, auth.requireFreshAuth(), c => c.json({ ok: true }));

app.notFound(c => c.text('Not found', 404));
app.onError((err, c) => {
  console.error(JSON.stringify({ error: err.name, path: c.req.routePath }));
  return c.text('Something went wrong', 500);
});

export default {
  fetch: app.fetch,
  // Daily housekeeping (see "triggers" in wrangler.jsonc).
  scheduled: async (_event: ScheduledController, env: AuthEnv['Bindings'], ctx: ExecutionContext) => {
    ctx.waitUntil(auth.cleanup(env.DB));
  },
} satisfies ExportedHandler<AuthEnv['Bindings']>;
