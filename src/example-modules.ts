// Example Worker with every optional module on: mail (Resend, or the console locally), e-mail verification,
// approval + admin, invites and signup links. Deploy it instead of src/index.ts with
// `wrangler deploy src/example-modules.ts`, or copy the createAuth() call into your app. Needs migration 0002.
import { Hono } from 'hono';
import { createAuth, html, type AuthEnv } from './auth';
import { admin, consoleMailer, emailVerification, invites, mail, resendMailer } from './auth/modules';

type Env = AuthEnv['Bindings'] & { RESEND_API_KEY?: string; MAIL_FROM?: string };

export const auth = createAuth({
  appName: 'Example App',
  modules: [
    mail({
      // Resend when the key is set; otherwise mail is printed to the console (bodies only with APP_ENV=local).
      mailer: env => {
        const e = env as Env;
        return e.RESEND_API_KEY && e.MAIL_FROM ? resendMailer({ apiKey: e.RESEND_API_KEY, from: e.MAIL_FROM }) : consoleMailer(env);
      },
    }),
    emailVerification({ required: false }),
    admin({ signupMode: 'approval' }),
    invites(),
  ],
});

const app = new Hono<AuthEnv>();
app.use('*', auth.securityHeaders, auth.bodyLimit, auth.originCheck, auth.session);
app.route(auth.config.basePath || '/', auth.routes);

app.get('/', c => {
  const s = c.get('session');
  const body = s
    ? html`<h1>Hello, ${s.user.name}</h1><p><a href="/auth/account">Your account</a> · <a href="/auth/admin">Admin</a> (admins only)</p>
<form method="post" action="/auth/logout"><button type="submit">Sign out</button></form>`
    : html`<h1>Example App</h1><p><a href="/auth/login">Sign in</a> or <a href="/auth/signup">create an account</a>.</p>`;
  return c.html(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Example App</title><link rel="stylesheet" href="/auth/auth.css"><main class="auth">${body}</main></html>`);
});

app.notFound(c => c.text('Not found', 404));
app.onError((err, c) => {
  console.error(JSON.stringify({ error: err.name, path: c.req.routePath }));
  return c.text('Something went wrong', 500);
});

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledController, env: Env, ctx: ExecutionContext) => { ctx.waitUntil(auth.cleanup(env.DB)); },
} satisfies ExportedHandler<Env>;
