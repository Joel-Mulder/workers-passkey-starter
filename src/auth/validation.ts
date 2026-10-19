// Field validation for signup and renames.
import { fail, type Fail } from './users';

export const USERNAME_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
// eslint-disable-next-line no-control-regex
// Control characters, line separators and bidi marks/overrides/isolates (they can disguise a name in admin lists).
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]/;

export const MSG = {
  nameLength: 'Your name must be between 2 and 100 characters long.',
  nameInvalid: 'Your name contains characters that aren’t allowed.',
  username: 'Choose a username of 3 to 32 characters: lower-case letters, digits, full stop, underscore or hyphen. Start with a letter or digit.',
};

export function validateName(input: unknown): { ok: true; value: string } | Fail {
  if (typeof input !== 'string') return fail(422, 'invalid_name', MSG.nameLength);
  const value = input.trim().replace(/\s+/g, ' ');
  const len = [...value].length;
  if (len < 2 || len > 100) return fail(422, 'invalid_name', MSG.nameLength);
  if (CONTROL_RE.test(value)) return fail(422, 'invalid_name', MSG.nameInvalid);
  return { ok: true, value };
}

export function validateUsername(input: unknown): { ok: true; value: string } | Fail {
  if (typeof input !== 'string') return fail(422, 'invalid_username', MSG.username);
  const value = input.trim().toLowerCase();
  if (!USERNAME_RE.test(value)) return fail(422, 'invalid_username', MSG.username);
  return { ok: true, value };
}

export interface Profile { name: string; username: string }

export function validateProfile(input: { name?: unknown; username?: unknown }): { ok: true; value: Profile } | Fail {
  const name = validateName(input.name);
  if (!name.ok) return name;
  const username = validateUsername(input.username);
  if (!username.ok) return username;
  return { ok: true, value: { name: name.value, username: username.value } };
}
