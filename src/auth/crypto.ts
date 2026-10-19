// Small Web Crypto helpers. All encodings are base64url unless named otherwise.
const enc = new TextEncoder();

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, c => c.charCodeAt(0));
}

export const randomToken = (bytes = 32): string => b64url(crypto.getRandomValues(new Uint8Array(bytes)));
export const uuid = () => crypto.randomUUID();

export async function sha256Hex(input: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/** HMAC-SHA256 with a purpose-separated key derived from `secret` (SESSION_SECRET). */
export async function hmac(secret: string, purpose: string, message: string): Promise<string> {
  // Fail closed: without a real secret, rate-limit and mail-limit keys would be predictable.
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('SESSION_SECRET must be set to at least 32 random characters');
  const key = await crypto.subtle.importKey('raw', enc.encode(`${purpose}\u0000${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

export function timingSafeEqual(a: string, b: string): boolean {
  const ab = enc.encode(a), bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  for (let i = 0; i < Math.max(ab.length, bb.length); i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}
