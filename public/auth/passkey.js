// Browser side of the auth kit: WebAuthn ceremonies (no SDK), the Signal API, step-up, and the [data-*] hooks of
// the example pages. A native ES module, no build step.
//
// Use it two ways:
//   1. Load it on the example pages (src/auth/pages.ts): it wires every [data-passkey-*] element automatically.
//   2. Import the functions in your own UI:
//        import { signInWithPasskey, signUpWithPasskey, reauthenticate, deleteAccount, recoverWithPasskey, postJson } from '/auth/passkey.js';
//
// The API lives next to this file: '/auth/passkey.js' → '/auth/api/…' (also under a basePath).

const BASE = new URL(import.meta.url).pathname.replace(/\/auth\/passkey\.js$/, '');
const api = path => `${BASE}/auth/api${path}`;

const MSG = {
  unsupported: 'This browser doesn’t support passkeys. Use a recent Safari, Chrome, Edge or Firefox.',
  cancelled: 'Cancelled. Nothing has changed.',
  exists: 'This passkey is already on this device. Choose another device or password manager.',
  security: 'Passkeys only work on this site’s real address.',
  failed: 'Something went wrong. Please try again.',
  network: 'No connection. Check your internet and try again.',
  waiting: 'Waiting for your passkey…',
  confirmTitle: 'Confirm it’s you',
  confirmText: 'For this change we ask you to use your passkey again.',
  confirmButton: 'Confirm with passkey',
  cancel: 'Cancel',
  confirmedClickAgain: label => `Confirmed. Click “${label}” again to continue (valid for 5 minutes).`,
  renamePrompt: 'New name for this passkey:',
  removeConfirm: name => `Remove the passkey “${name}”? You can’t use it to sign in here any more.`,
  unlinkConfirm: 'Unlink this account? You can link it again later.',
  signOutConfirm: 'Sign out on all your other devices?',
  signedOut: n => `Signed out on ${n} other ${n === 1 ? 'device' : 'devices'}.`,
  makePasskey: 'Create passkey',
  usernameMismatch: 'This doesn’t match your username.',
  deleteConfirm: 'Delete your account for good?',
  recovered: 'Done. Your new passkey works; you’re signed in.',
};

// ───────────── base64url + WebAuthn JSON ─────────────

export function toB64url(buf) {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

export const isSupported = () => typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;

function creationOptions(json) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  return {
    ...json,
    challenge: fromB64url(json.challenge),
    user: { ...json.user, id: fromB64url(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map(c => ({ ...c, id: fromB64url(c.id) })),
  };
}
function requestOptions(json) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  return { ...json, challenge: fromB64url(json.challenge), allowCredentials: (json.allowCredentials || []).map(c => ({ ...c, id: fromB64url(c.id) })) };
}

function credentialJSON(cred) {
  if (typeof cred.toJSON === 'function') { try { return cred.toJSON(); } catch { /* fall through */ } }
  const r = cred.response;
  const out = { id: cred.id, rawId: toB64url(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment ?? undefined, clientExtensionResults: cred.getClientExtensionResults?.() ?? {}, response: { clientDataJSON: toB64url(r.clientDataJSON) } };
  if (r.attestationObject) {
    out.response.attestationObject = toB64url(r.attestationObject);
    out.response.transports = r.getTransports?.() ?? [];
    if (r.getPublicKey) { const k = r.getPublicKey(); if (k) out.response.publicKey = toB64url(k); }
    if (r.getPublicKeyAlgorithm) out.response.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
    if (r.getAuthenticatorData) out.response.authenticatorData = toB64url(r.getAuthenticatorData());
  } else {
    out.response.authenticatorData = toB64url(r.authenticatorData);
    out.response.signature = toB64url(r.signature);
    if (r.userHandle) out.response.userHandle = toB64url(r.userHandle);
  }
  return out;
}

export async function createPasskey(optionsJSON, { signal } = {}) {
  if (!isSupported()) throw Object.assign(new Error('unsupported'), { name: 'NotSupportedError' });
  return credentialJSON(await navigator.credentials.create({ publicKey: creationOptions(optionsJSON), signal }));
}

export async function getPasskey(optionsJSON, { signal } = {}) {
  if (!isSupported()) throw Object.assign(new Error('unsupported'), { name: 'NotSupportedError' });
  return credentialJSON(await navigator.credentials.get({ publicKey: requestOptions(optionsJSON), mediation: 'optional', signal }));
}

// ───────────── Signal API (feature-detected, never throws) ─────────────
// Keeps password managers in sync with the server: drop deleted passkeys, update the shown username/name.

export async function signalUnknown(rpId, credentialId) {
  try { await PublicKeyCredential.signalUnknownCredential?.({ rpId, credentialId }); } catch { /* ignore */ }
}
export async function signalAccepted(rpId, userId, allAcceptedCredentialIds) {
  try { await PublicKeyCredential.signalAllAcceptedCredentials?.({ rpId, userId, allAcceptedCredentialIds }); } catch { /* ignore */ }
}
export async function signalDetails(rpId, userId, name, displayName) {
  try { await PublicKeyCredential.signalCurrentUserDetails?.({ rpId, userId, name, displayName }); } catch { /* ignore */ }
}

// ───────────── Errors and the API helper ─────────────

export const isCancel = err => err?.name === 'NotAllowedError' || err?.name === 'AbortError';

/** A message for a WebAuthn or API error. NotAllowedError means the user cancelled (or it timed out). */
export function errorMessage(err) {
  if (err?.apiMessage) return err.apiMessage;
  switch (err?.name) {
    case 'NotAllowedError': case 'AbortError': return MSG.cancelled;
    case 'InvalidStateError': return MSG.exists;
    case 'NotSupportedError': return MSG.unsupported;
    case 'SecurityError': return MSG.security;
    case 'TypeError': return MSG.network;
    default: return MSG.failed;
  }
}

/** POST JSON to an auth API path (e.g. '/passkey/login/options'). Throws { status, code, apiMessage, data } on errors. */
export async function postJson(path, body) {
  const res = await fetch(api(path), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body ?? {}), credentials: 'same-origin' });
  const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data?.error?.code || `http_${res.status}`), { status: res.status, code: data?.error?.code, apiMessage: data?.error?.message, data });
  return data;
}

// ───────────── Prepared options (Safari) ─────────────
// WebKit only shows the passkey sheet when navigator.credentials.get/create runs as part of the click itself; an
// awaited fetch before it can lose the user gesture and Safari silently shows nothing. Where the request body is
// known ahead, fetch the options before the click (flows live 10 minutes, so they are refreshed after 8).

export function preparedOptions(path, body) {
  let ready = null, timer = 0, loading = null;
  const load = () => {
    if (loading) return loading;
    loading = postJson(path, body)
      .then(v => { ready = v; clearTimeout(timer); timer = setTimeout(() => { ready = null; load(); }, 8 * 60e3); return v; })
      .catch(() => null)
      .finally(() => { loading = null; });
    return loading;
  };
  load();
  return {
    take() { const v = ready; ready = null; clearTimeout(timer); if (v) setTimeout(load, 0); return v; },
    refresh() { ready = null; return load(); },
  };
}

// ───────────── High-level flows (use these from your own UI) ─────────────

/** Usernameless sign-in. Resolves { redirect, … } after the session cookie is set. */
export async function signInWithPasskey({ returnTo, prepared, signal } = {}) {
  const { flowId, options } = prepared?.take() || await postJson('/passkey/login/options');
  const response = await getPasskey(options, { signal });
  try {
    const out = await postJson('/passkey/login/verify', { flowId, response, returnTo });
    await signalAccepted(out.rpId, out.userId, out.acceptedCredentialIds);
    await signalDetails(out.rpId, out.userId, out.name, out.displayName);
    return out;
  } catch (err) {
    // Let the password manager hide a passkey the server no longer knows, but only when the server says it is
    // provably orphaned (our user id, account gone).
    if (err.code === 'unknown_credential' && err.data?.signalUnknown === true) await signalUnknown(err.data.rpId, err.data.credentialId);
    throw err;
  }
}

/** Create an account: { name, username } → passkey → session. Resolves { redirect, … }. */
export async function signUpWithPasskey({ name, username }) {
  const { flowId, options } = await postJson('/signup/options', { name, username });
  const response = await createPasskey(options);
  const out = await postJson('/signup/verify', { flowId, response });
  await signalDetails(out.rpId, out.userId, out.name, out.displayName);
  return out;
}

/** Add a passkey to the signed-in account (needs fresh auth: wrap in withFreshAuth or catch reauth_required). */
export async function addPasskey() {
  const { flowId, options } = await postJson('/passkeys/options');
  const response = await createPasskey(options);
  const out = await postJson('/passkeys/verify', { flowId, response });
  await signalAccepted(out.rpId, out.userId, out.acceptedCredentialIds);
  return out;
}

/** Delete the signed-in account (needs fresh auth; the server checks `username`). Password managers drop its passkeys. */
export async function deleteAccount(username) {
  const out = await postJson('/account/delete', { username });
  await signalAccepted(out.rpId, out.userId, []);
  return out;
}

/** Finish a recovery link: create the new passkey that replaces all others. Resolves { redirect, … } once signed in. */
export async function recoverWithPasskey(token) {
  const { flowId, options } = await postJson('/recovery/options', { token });
  const response = await createPasskey(options);
  const out = await postJson('/recovery/verify', { flowId, response });
  await signalAccepted(out.rpId, out.userId, out.acceptedCredentialIds); // the old passkeys disappear from password managers
  await signalDetails(out.rpId, out.userId, out.name, out.displayName);
  return out;
}

// ───────────── Step-up ─────────────

let reauthInFlight = null;

function reauthDialog() {
  let dlg = document.getElementById('auth-reauth');
  if (dlg) return dlg;
  dlg = document.createElement('dialog');
  dlg.id = 'auth-reauth';
  dlg.className = 'auth-dialog';
  dlg.setAttribute('aria-labelledby', 'auth-reauth-title');
  const h = Object.assign(document.createElement('h2'), { id: 'auth-reauth-title', textContent: MSG.confirmTitle });
  const p = Object.assign(document.createElement('p'), { textContent: MSG.confirmText });
  const status = Object.assign(document.createElement('p'), { className: 'auth-status' });
  status.setAttribute('role', 'status');
  status.dataset.authStatus = '';
  const row = Object.assign(document.createElement('p'), { className: 'auth-actions' });
  const cancel = Object.assign(document.createElement('button'), { type: 'button', className: 'auth-button', textContent: MSG.cancel });
  cancel.dataset.reauthCancel = '';
  const ok = Object.assign(document.createElement('button'), { type: 'button', className: 'auth-button auth-button--primary', textContent: MSG.confirmButton });
  ok.dataset.reauthConfirm = '';
  row.append(cancel, ok);
  dlg.append(h, p, status, row);
  document.body.append(dlg);
  return dlg;
}

/**
 * Ask the user to confirm with their passkey (step-up, valid 5 minutes). Opens a small dialog whose button starts
 * the ceremony (a direct click keeps Safari's user gesture). Resolves true when confirmed, false when closed.
 * Accounts without a passkey continue with Google/Apple (intent=reauth), which leaves the page.
 * Don't repeat the original action automatically: ask the user to click again.
 */
export function reauthenticate() {
  if (reauthInFlight) return reauthInFlight;
  const dlg = reauthDialog();
  const ok = dlg.querySelector('[data-reauth-confirm]');
  const cancel = dlg.querySelector('[data-reauth-cancel]');
  const status = dlg.querySelector('[data-auth-status]');
  status.textContent = '';
  const prepared = preparedOptions('/reauth/options');
  reauthInFlight = new Promise(resolve => {
    let done = false;
    const finish = result => {
      if (done) return;
      done = true;
      ok.removeEventListener('click', run);
      cancel.removeEventListener('click', onCancel);
      dlg.removeEventListener('close', onClose);
      if (dlg.open) dlg.close();
      reauthInFlight = null;
      resolve(result);
    };
    const onCancel = () => finish(false);
    const onClose = () => finish(false);
    async function run() {
      ok.disabled = true;
      status.textContent = MSG.waiting;
      try {
        let start = prepared.take();
        try {
          start ??= await postJson('/reauth/options');
        } catch (err) {
          if (err.data?.provider) {
            location.href = `${BASE}/auth/${err.data.provider}/start?intent=reauth&returnTo=${encodeURIComponent(location.pathname + location.search)}`;
            return;
          }
          throw err;
        }
        const response = await getPasskey(start.options);
        await postJson('/reauth/verify', { flowId: start.flowId, response });
        finish(true);
      } catch (err) {
        status.textContent = errorMessage(err);
        prepared.refresh();
      } finally {
        ok.disabled = false;
      }
    }
    ok.addEventListener('click', run);
    cancel.addEventListener('click', onCancel);
    dlg.addEventListener('close', onClose);
  });
  dlg.showModal();
  return reauthInFlight;
}

/**
 * Run `fn`; on reauth_required, ask for step-up and tell the user to click again (`label`). Resolves true when
 * `fn` completed, false when it needs another click or was cancelled.
 */
export async function withFreshAuth(fn, { label, onMessage } = {}) {
  try {
    await fn();
    return true;
  } catch (err) {
    if (err?.code !== 'reauth_required') throw err;
    const ok = await reauthenticate();
    onMessage?.(ok ? MSG.confirmedClickAgain(label ?? '') : MSG.cancelled);
    return false;
  }
}

// ───────────── Example pages ─────────────

const statusOf = root => root.querySelector('[data-auth-status]');
const say = (root, text) => { const el = statusOf(root); if (el) el.textContent = text ?? ''; };
const busy = (el, on) => { if (el) { el.disabled = on; if (on) el.setAttribute('aria-busy', 'true'); else el.removeAttribute('aria-busy'); } };

function initLogin(form) {
  const button = form.querySelector('[type=submit]');
  if (!isSupported()) { busy(button, true); say(form, MSG.unsupported); return; }
  const prepared = preparedOptions('/passkey/login/options');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    busy(button, true);
    say(form, MSG.waiting);
    try {
      const out = await signInWithPasskey({ returnTo: form.dataset.returnTo, prepared });
      location.assign(out.redirect);
    } catch (err) {
      say(form, errorMessage(err));
      prepared.refresh();
    } finally {
      busy(button, false);
    }
  });
}

function initSignup(form) {
  const button = form.querySelector('[type=submit]');
  if (!isSupported()) { busy(button, true); say(form, MSG.unsupported); return; }
  // Safari: these options depend on the form, so they can't be fetched ahead. If WebKit refuses the sheet because
  // the fetch broke the user gesture (NotAllowedError within a moment), keep the options and let the next click
  // ("Create passkey") call WebAuthn directly.
  let pending = null;
  const originalLabel = button?.textContent;
  form.addEventListener('input', () => { if (pending) { pending = null; button.textContent = originalLabel; } });
  const finish = async (flowId, response) => {
    const out = await postJson('/signup/verify', { flowId, response });
    await signalDetails(out.rpId, out.userId, out.name, out.displayName);
    location.assign(out.redirect);
  };
  form.addEventListener('submit', async e => {
    e.preventDefault();
    busy(button, true);
    say(form, MSG.waiting);
    try {
      if (pending) {
        const p = pending;
        pending = null;
        button.textContent = originalLabel;
        await finish(p.flowId, await createPasskey(p.options));
        return;
      }
      const fd = new FormData(form);
      const { flowId, options } = await postJson('/signup/options', { name: String(fd.get('name') ?? '').trim(), username: String(fd.get('username') ?? '').trim().toLowerCase() });
      const t0 = Date.now();
      let response;
      try {
        response = await createPasskey(options);
      } catch (err) {
        if (err?.name === 'NotAllowedError' && Date.now() - t0 < 400) {
          pending = { flowId, options };
          button.textContent = MSG.makePasskey;
          say(form, '');
          return;
        }
        throw err;
      }
      await finish(flowId, response);
    } catch (err) {
      say(form, errorMessage(err));
      const field = { invalid_name: 'name', invalid_username: 'username', username_taken: 'username' }[err?.code];
      if (field) form.elements.namedItem(field)?.focus();
    } finally {
      busy(button, false);
    }
  });
}

function initAccount(root) {
  const message = text => say(root, text);
  const reload = () => location.replace(location.pathname);
  const action = (selector, run) => root.querySelectorAll(selector).forEach(btn => btn.addEventListener('click', async e => {
    e.preventDefault();
    busy(btn, true);
    try {
      if (await withFreshAuth(() => run(btn), { label: btn.textContent.trim(), onMessage: message })) reload();
    } catch (err) {
      if (err?.message !== 'skip') message(errorMessage(err));
    } finally {
      busy(btn, false);
    }
  }));
  const skip = () => { throw new Error('skip'); }; // the user said no to the prompt/confirm

  action('[data-passkey-add]', () => addPasskey());
  action('[data-passkey-rename]', async btn => {
    const name = prompt(MSG.renamePrompt, btn.dataset.name ?? '');
    if (name === null) skip();
    await postJson(`/passkeys/${encodeURIComponent(btn.dataset.id)}/rename`, { name });
  });
  action('[data-passkey-remove]', async btn => {
    if (!confirm(MSG.removeConfirm(btn.dataset.name ?? ''))) skip();
    const out = await postJson(`/passkeys/${encodeURIComponent(btn.dataset.id)}/delete`);
    await signalAccepted(out.rpId, out.userId, out.acceptedCredentialIds); // password managers drop the removed one
  });
  action('[data-identity-unlink]', async btn => {
    if (!confirm(MSG.unlinkConfirm)) skip();
    await postJson(`/identities/${encodeURIComponent(btn.dataset.id)}/delete`);
  });
  root.querySelectorAll('[data-sign-out-everywhere]').forEach(btn => btn.addEventListener('click', async () => {
    if (!confirm(MSG.signOutConfirm)) return;
    busy(btn, true);
    try {
      let revoked = 0;
      if (await withFreshAuth(async () => { revoked = (await postJson('/sign-out-everywhere')).revoked; }, { label: btn.textContent.trim(), onMessage: message })) message(MSG.signedOut(revoked));
    } catch (err) { message(errorMessage(err)); } finally { busy(btn, false); }
  }));
  // Linking Google/Apple needs a fresh session first (the start route checks again); then the user clicks again.
  root.querySelectorAll('[data-identity-link]').forEach(a => a.addEventListener('click', async e => {
    if (root.dataset.fresh === 'true') return;
    e.preventDefault();
    const ok = await reauthenticate();
    if (ok) root.dataset.fresh = 'true';
    message(ok ? MSG.confirmedClickAgain(a.textContent.trim()) : MSG.cancelled);
  }));
  if (new URLSearchParams(location.search).get('reauth') === '1') reauthenticate().then(ok => { if (ok) root.dataset.fresh = 'true'; });
}

function initDelete(form) {
  const button = form.querySelector('[type=submit]');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const typed = String(form.elements.namedItem('username')?.value ?? '').trim().toLowerCase();
    if (typed !== form.dataset.username) { say(form.closest('[data-account]') ?? form, MSG.usernameMismatch); return; }
    if (!confirm(MSG.deleteConfirm)) return;
    const root = form.closest('[data-account]') ?? form;
    busy(button, true);
    try {
      let out = null;
      if (await withFreshAuth(async () => { out = await deleteAccount(typed); }, { label: button.textContent.trim(), onMessage: m => say(root, m) })) location.assign(out.redirect);
    } catch (err) { say(root, errorMessage(err)); } finally { busy(button, false); }
  });
}

function initRecover(button) {
  const root = button.closest('[data-passkey-recover-root]') ?? document.body;
  if (!isSupported()) { busy(button, true); say(root, MSG.unsupported); return; }
  button.addEventListener('click', async () => {
    busy(button, true);
    say(root, MSG.waiting);
    try {
      const out = await recoverWithPasskey(button.dataset.token);
      say(root, MSG.recovered);
      location.assign(out.redirect);
    } catch (err) {
      say(root, errorMessage(err));
      if (err?.code === 'recovery_invalid') button.hidden = true;
    } finally {
      busy(button, false);
    }
  });
}

function init() {
  document.querySelectorAll('form[data-passkey-login]').forEach(initLogin);
  document.querySelectorAll('form[data-passkey-signup]').forEach(initSignup);
  document.querySelectorAll('[data-account]').forEach(initAccount);
  document.querySelectorAll('form[data-account-delete]').forEach(initDelete);
  document.querySelectorAll('[data-passkey-recover]').forEach(initRecover);
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
}
