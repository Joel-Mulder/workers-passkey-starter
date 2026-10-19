// Small helpers shared by the optional modules.
import { fail, type Fail } from '../users';

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]+$/;
const MSG = {
  email: 'Enter a valid e-mail address, or leave the field empty.',
  emailRequired: 'Enter a valid e-mail address.',
};

/** Optional address: empty → null. Stored lowercase, at most 254 characters. */
export function validateEmail(input: unknown, required = false): { ok: true; value: string | null } | Fail {
  if (input === undefined || input === null || (typeof input === 'string' && input.trim() === '')) {
    return required ? fail(422, 'invalid_email', MSG.emailRequired) : { ok: true, value: null };
  }
  if (typeof input !== 'string') return fail(422, 'invalid_email', MSG.email);
  const value = input.trim().toLowerCase();
  if (value.length > 254 || !EMAIL_RE.test(value)) return fail(422, 'invalid_email', required ? MSG.emailRequired : MSG.email);
  return { ok: true, value };
}
