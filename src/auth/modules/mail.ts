// Optional module: sending mail. A small adapter interface with adapters for Resend (plain fetch, no SDK), the
// console (local development) and memory (tests), plus overridable English templates. The other modules mail
// through sendMail(); without this module they simply don't send (and say so where it matters).
//
//   import { mail, resendMailer, consoleMailer } from './auth/modules/mail';
//   createAuth({ appName, modules: [mail({ mailer: env => env.RESEND_API_KEY ? resendMailer({ apiKey: env.RESEND_API_KEY, from: env.MAIL_FROM }) : consoleMailer(env) })] });
import type { AuthConfig } from '../config';
import { hmac } from '../crypto';
import { logIncident } from '../http';
import type { AuthModule } from '../extensions';
import { hitRateLimit } from '../rate-limit';
import type { AuthBindings, AuthContext } from '../types';

export interface MailMessage { to: string; subject: string; text: string; html?: string }
export interface Mailer { send(m: MailMessage): Promise<void> }

/** Resend (https://resend.com) over its HTTP API. `from` must be on a domain verified in Resend. */
export function resendMailer(o: { apiKey: string; from: string; replyTo?: string; fetch?: typeof fetch }): Mailer {
  const f = o.fetch ?? fetch;
  return {
    async send(m) {
      const res = await f('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${o.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: o.from, to: [m.to], subject: m.subject, text: m.text, ...(m.html ? { html: m.html } : {}), ...(o.replyTo ? { reply_to: o.replyTo } : {}) }),
      });
      // The response body may echo the address: never put it in the error.
      if (!res.ok) throw new Error(`resend_${res.status}`);
    },
  };
}

/**
 * Logs mail instead of sending it. The body (with its links) is only printed when APP_ENV is 'local'; deployed, the
 * log shows the subject only, because links in mail are bearer tokens.
 */
export function consoleMailer(env?: Pick<AuthBindings, 'APP_ENV'>): Mailer {
  const local = env?.APP_ENV === 'local';
  return { async send(m) { console.log(local ? `\n── mail to ${m.to}: ${m.subject}\n${m.text}\n` : JSON.stringify({ mail: m.subject, body: 'hidden outside APP_ENV=local' })); } };
}

/** Keeps sent mail in `sent` (tests, previews). */
export function memoryMailer(): Mailer & { sent: MailMessage[] } {
  const sent: MailMessage[] = [];
  return { sent, async send(m) { sent.push(m); } };
}

// ───────────── Templates ─────────────

export interface TemplateData {
  'verify-email': { name: string; link: string; change: boolean };
  'email-change-notice': { name: string; newEmail: string };
  recovery: { name: string; username: string; link: string };
  'signup-pending-admin': { username: string; name: string; adminLink: string };
  'account-approved': { name: string; link: string };
  invite: { link: string; days: number };
}
export type TemplateName = keyof TemplateData;
export interface RenderedMail { subject: string; text: string; html?: string }
export type Templates = { [K in TemplateName]: (d: TemplateData[K], app: string) => RenderedMail };

export const DEFAULT_TEMPLATES: Templates = {
  'verify-email': (d, app) => ({
    subject: `Confirm your e-mail address for ${app}`,
    text: `Hi ${d.name},\n\n${d.change ? 'You asked to use this address' : 'You added this address'} for your ${app} account. Open this link to confirm it (valid for 24 hours):\n\n${d.link}\n\nDidn't ask for this? Ignore this mail; nothing changes.\n`,
  }),
  'email-change-notice': (d, app) => ({
    subject: `Your ${app} e-mail address is being changed`,
    text: `Hi ${d.name},\n\nSomeone signed in to your ${app} account asked to change its e-mail address to ${d.newEmail}. It only changes once that address is confirmed.\n\nWasn't this you? Sign in, remove passkeys you don't recognise and choose "Sign out on all other devices".\n`,
  }),
  recovery: (d, app) => ({
    subject: `Recover your ${app} account`,
    text: `Hi ${d.name},\n\nUse this link to create a new passkey for ${d.username} (valid for 15 minutes, works once). It replaces all your current passkeys and signs you out everywhere.\n\n${d.link}\n\nDidn't ask for this? Ignore this mail; nothing changes.\n`,
  }),
  'signup-pending-admin': (d, app) => ({
    subject: `New ${app} signup waiting for approval: ${d.username}`,
    text: `${d.name} (${d.username}) created an account and is waiting for approval.\n\nReview it: ${d.adminLink}\n`,
  }),
  'account-approved': (d, app) => ({
    subject: `Your ${app} account is ready`,
    text: `Hi ${d.name},\n\nYour account has been approved. Sign in here: ${d.link}\n`,
  }),
  invite: (d, app) => ({
    subject: `You're invited to ${app}`,
    text: `You've been invited to create an account on ${app}. Open this link to sign up (valid for ${d.days} days, works once):\n\n${d.link}\n`,
  }),
};

// ───────────── Module ─────────────

export interface MailOptions {
  /** Pick the adapter per request; secrets come from env (e.g. RESEND_API_KEY). */
  mailer: (env: AuthBindings & Record<string, unknown>) => Mailer;
  /** Replace any template, e.g. { invite: (d, app) => ({ subject, text, html }) }. */
  templates?: Partial<Templates>;
  /** Mails to one address per hour (verification, recovery, notices). Default 5. */
  perRecipientPerHour?: number;
}

export interface MailModule extends AuthModule {
  name: 'mail';
  options: MailOptions;
}

export function mail(options: MailOptions): MailModule {
  return { name: 'mail', options };
}

export type SendResult = 'sent' | 'no-mail-module' | 'limited' | 'failed';

/**
 * Render and send a template. Never throws: a failure is logged (without the address) and reported as 'failed'.
 * Limited per recipient (HMAC of the address in the key, never the address itself).
 */
export async function sendMail<K extends TemplateName>(c: AuthContext, cfg: AuthConfig, to: string, template: K, data: TemplateData[K]): Promise<SendResult> {
  const m = cfg.modules.find((x): x is MailModule => x.name === 'mail');
  if (!m) return 'no-mail-module';
  try {
    const limit = await hitRateLimit(c.env.DB, `mail:to:${await hmac(c.env.SESSION_SECRET, 'mail', to.toLowerCase())}`, m.options.perRecipientPerHour ?? 5, 60 * 60_000);
    if (!limit.allowed) return 'limited';
    const render = (m.options.templates?.[template] ?? DEFAULT_TEMPLATES[template]) as (d: TemplateData[K], app: string) => RenderedMail;
    const msg = render(data, cfg.appName);
    await m.options.mailer(c.env as AuthBindings & Record<string, unknown>).send({ to, ...msg });
    return 'sent';
  } catch (e) {
    logIncident(`mail.${template}`, e);
    return 'failed';
  }
}

export const hasMail = (cfg: AuthConfig) => cfg.modules.some(m => m.name === 'mail');
