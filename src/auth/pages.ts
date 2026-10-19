// Minimal example pages: sign in, create account, the username step after Google/Apple, manage sign-in methods,
// and message pages. Plain server-rendered HTML; public/auth/passkey.js wires the [data-*] hooks. Restyle them with
// AuthOptions.renderPage (your layout) and public/auth/auth.css, or replace them and call the JSON API directly.
import type { AuthConfig } from './config';
import { PROVIDER_NAMES } from './oauth';
import type { AccountView } from './account';
import type { AuthContext, PageInput, Provider } from './types';

/** Escaped HTML. Interpolated strings are escaped; nested html`` results and arrays of them are inserted as is. */
export class SafeHtml { constructor(readonly value: string) {} toString() { return this.value; } }
const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const escapeHtml = (s: string) => s.replace(/[&<>"']/g, ch => ESC[ch]!);
const part = (v: unknown): string => (v instanceof SafeHtml ? v.value : Array.isArray(v) ? v.map(part).join('') : v == null || v === false ? '' : escapeHtml(String(v)));
export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  return new SafeHtml(strings.reduce((out, s, i) => out + s + (i < values.length ? part(values[i]) : ''), ''));
}

export async function renderPage(c: AuthContext, cfg: AuthConfig, page: PageInput): Promise<Response> {
  if (cfg.renderPage) return cfg.renderPage(c, page);
  const nonce = c.get('nonce') ?? '';
  const doc = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${page.title} · ${cfg.appName}</title>
<link rel="stylesheet" href="${cfg.path('/auth/auth.css')}">
</head>
<body>
<main class="auth">
${new SafeHtml(page.body)}
</main>
${(page.scripts ?? []).map(src => html`<script type="module" nonce="${nonce}" src="${src}"></script>`)}
</body>
</html>`;
  return c.html(doc.value, (page.status ?? 200) as 200);
}

const statusRegion = html`<p class="auth-status" data-auth-status role="status" aria-live="polite"></p>`;
const startHref = (cfg: AuthConfig, p: Provider, intent: string, returnTo?: string) =>
  `${cfg.path(`/auth/${p}/start`)}?intent=${intent}${returnTo ? `&returnTo=${encodeURIComponent(returnTo)}` : ''}`;

function providerButtons(cfg: AuthConfig, providers: Record<Provider, boolean>, intent: 'login' | 'signup', returnTo?: string) {
  const list = (Object.keys(providers) as Provider[]).filter(p => providers[p]);
  if (!list.length) return html``;
  return html`<p class="auth-or">or</p>
<ul class="auth-providers">${list.map(p => html`<li><a class="auth-button" href="${startHref(cfg, p, intent, returnTo)}">Continue with ${PROVIDER_NAMES[p]}</a></li>`)}</ul>`;
}

export function loginPage(c: AuthContext, cfg: AuthConfig, o: { returnTo: string; providers: Record<Provider, boolean> }) {
  const body = html`<h1>Sign in</h1>
<form data-passkey-login data-return-to="${o.returnTo}">
  <button class="auth-button auth-button--primary" type="submit">Sign in with a passkey</button>
  ${statusRegion}
</form>
${providerButtons(cfg, o.providers, 'login', o.returnTo)}
<p class="auth-note">No account yet? <a href="${cfg.path('/auth/signup')}">Create an account</a></p>`;
  return renderPage(c, cfg, { title: 'Sign in', body: body.value, scripts: [cfg.path('/auth/passkey.js')] });
}

export function signupPage(c: AuthContext, cfg: AuthConfig, o: { providers: Record<Provider, boolean>; refused?: string }) {
  const body = o.refused
    ? html`<h1>Create an account</h1><p>${o.refused}</p><p><a href="${cfg.path('/auth/login')}">Sign in</a></p>`
    : html`<h1>Create an account</h1>
<form data-passkey-signup>
  <label for="name">Your name</label>
  <input id="name" name="name" autocomplete="name" required minlength="2" maxlength="100">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" required pattern="[a-z0-9][a-z0-9_.\\-]{2,31}" autocapitalize="none" spellcheck="false" aria-describedby="username-help">
  <p class="auth-help" id="username-help">3–32 characters: lower-case letters, digits, . _ or -</p>
  <button class="auth-button auth-button--primary" type="submit">Create account with a passkey</button>
  ${statusRegion}
</form>
${providerButtons(cfg, o.providers, 'signup')}
<p class="auth-note">Already have an account? <a href="${cfg.path('/auth/login')}">Sign in</a></p>`;
  return renderPage(c, cfg, { title: 'Create an account', body: body.value, scripts: o.refused ? [] : [cfg.path('/auth/passkey.js')], status: o.refused ? 403 : 200 });
}

export function signupCompletePage(c: AuthContext, cfg: AuthConfig, o: { provider: Provider; email: string | null; values: { name: string; username: string }; error?: string; status?: number }) {
  const body = html`<h1>Choose a username</h1>
<p>You’re signing up with ${PROVIDER_NAMES[o.provider]}${o.email ? html` (${o.email})` : ''}.</p>
<form method="post" action="${cfg.path('/auth/signup/complete')}">
  <label for="name">Your name</label>
  <input id="name" name="name" autocomplete="name" required minlength="2" maxlength="100" value="${o.values.name}">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" required autocapitalize="none" spellcheck="false" value="${o.values.username}">
  ${o.error ? html`<p class="auth-error" role="alert">${o.error}</p>` : ''}
  <button class="auth-button auth-button--primary" type="submit">Create account</button>
</form>
<p class="auth-note"><a href="${cfg.path('/auth/signup')}">Use another method</a></p>`;
  return renderPage(c, cfg, { title: 'Choose a username', body: body.value, status: o.status });
}

export function accountPage(c: AuthContext, cfg: AuthConfig, v: AccountView, o: { providers: Record<Provider, boolean>; fresh: boolean }) {
  const total = v.passkeys.length + v.identities.length;
  const linked = new Set(v.identities.map(i => i.provider));
  const linkable = (Object.keys(o.providers) as Provider[]).filter(p => o.providers[p] && !linked.has(p));
  const date = (ms: number | null) => (ms ? new Date(ms).toISOString().slice(0, 10) : 'never');
  const body = html`<h1>Sign-in methods</h1>
<p>Signed in as <strong>${v.user.name}</strong> (${v.user.username}).</p>
<section data-account data-fresh="${o.fresh ? 'true' : 'false'}">
  ${statusRegion}
  <h2>Passkeys</h2>
  <ul class="auth-list">
    ${v.passkeys.map(p => html`<li>
      <span><strong>${p.name}</strong><br><small>Added ${date(p.createdAt)} · last used ${date(p.lastUsedAt)}${p.backedUp ? ' · synced' : ''}</small></span>
      <span class="auth-actions">
        <button type="button" class="auth-button" data-passkey-rename data-id="${p.id}" data-name="${p.name}">Rename</button>
        <button type="button" class="auth-button" data-passkey-remove data-id="${p.id}" data-name="${p.name}" ${total <= 1 ? 'disabled' : ''}>Remove</button>
      </span>
    </li>`)}
  </ul>
  ${v.passkeys.length ? '' : html`<p>No passkeys yet.</p>`}
  <button type="button" class="auth-button auth-button--primary" data-passkey-add>Add a passkey</button>

  <h2>Linked accounts</h2>
  <ul class="auth-list">
    ${v.identities.map(i => html`<li>
      <span><strong>${PROVIDER_NAMES[i.provider]}</strong>${i.email ? html`<br><small>${i.email}</small>` : ''}</span>
      <span class="auth-actions"><button type="button" class="auth-button" data-identity-unlink data-id="${i.id}" ${total <= 1 ? 'disabled' : ''}>Unlink</button></span>
    </li>`)}
  </ul>
  ${linkable.map(p => html`<p><a class="auth-button" data-identity-link href="${startHref(cfg, p, 'link', cfg.path('/auth/account'))}">Link ${PROVIDER_NAMES[p]}</a></p>`)}
  ${total <= 1 ? html`<p class="auth-help">Your last sign-in method can’t be removed. Add another one first.</p>` : ''}

  <h2>Sessions</h2>
  <button type="button" class="auth-button" data-sign-out-everywhere>Sign out on all other devices</button>

  <h2>Delete account</h2>
  <form data-account-delete data-username="${v.user.username}">
    <p>This deletes your account and signs you out everywhere. It can’t be undone.</p>
    <label for="delete-username">Type your username (${v.user.username}) to confirm</label>
    <input id="delete-username" name="username" autocomplete="off" autocapitalize="none" spellcheck="false" required>
    <button class="auth-button auth-button--danger" type="submit">Delete my account</button>
  </form>
</section>
<form method="post" action="${cfg.path('/auth/logout')}"><button class="auth-button" type="submit">Sign out</button></form>`;
  return renderPage(c, cfg, { title: 'Sign-in methods', body: body.value, scripts: [cfg.path('/auth/passkey.js')] });
}

export function recoverPage(c: AuthContext, cfg: AuthConfig, o: { token: string; username: string | null }) {
  const body = o.username
    ? html`<h1>Recover your account</h1>
<section data-passkey-recover-root>
  <p>Create a new passkey for <strong>${o.username}</strong>. It replaces all your current passkeys, signs you out
  everywhere and unlinks Google/Apple (you can link them again afterwards).</p>
  <button type="button" class="auth-button auth-button--primary" data-passkey-recover data-token="${o.token}">Create a new passkey</button>
  ${statusRegion}
</section>`
    : html`<h1>Recover your account</h1><p>This recovery link is incorrect, has already been used or has expired. Ask for a new link.</p>
<p><a href="${cfg.path('/auth/login')}">Sign in</a></p>`;
  // The token is in the URL: never send it to other sites.
  c.header('Referrer-Policy', 'no-referrer');
  return renderPage(c, cfg, { title: 'Recover your account', body: body.value, scripts: o.username ? [cfg.path('/auth/passkey.js')] : [], status: o.username ? 200 : 400 });
}

export function messagePage(c: AuthContext, cfg: AuthConfig, o: { title: string; message: string; status?: number; links?: { href: string; label: string }[] }) {
  const body = html`<h1>${o.title}</h1><p>${o.message}</p>${(o.links ?? []).map(l => html`<p><a href="${l.href}">${l.label}</a></p>`)}`;
  return renderPage(c, cfg, { title: o.title, body: body.value, status: o.status ?? 400 });
}

export function noAccountPage(c: AuthContext, cfg: AuthConfig, provider: Provider) {
  return messagePage(c, cfg, {
    title: 'No account found',
    message: `There’s no account linked to this ${PROVIDER_NAMES[provider]} account yet.`,
    status: 404,
    links: [{ href: startHref(cfg, provider, 'signup'), label: `Create an account with ${PROVIDER_NAMES[provider]}` }, { href: cfg.path('/auth/login'), label: 'Sign in another way' }],
  });
}
