import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import worker, { auth } from '../src/index';
import { insertSession } from '../src/auth/session';
import { client, count, insertUser, makeCfg, makeEnv, ORIGIN } from './helpers/auth';

afterEach(() => vi.restoreAllMocks());
const chunked = (bytes: number) => new ReadableStream({
  start(c) { for (let i = 0; i < bytes; i += 16_384) c.enqueue(new Uint8Array(Math.min(16_384, bytes - i)).fill(97)); c.close(); },
});

describe('headers', () => {
  it('HTML gets a strict CSP; every response gets the WebAuthn Permissions-Policy and friends', async () => {
    const res = await client(worker.fetch, makeEnv({ APP_ENV: 'production' }))('/auth/login');
    const csp = res.headers.get('content-security-policy')!;
    expect(csp).toMatch(/script-src 'nonce-[^']+' 'strict-dynamic'/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self' https://accounts.google.com https://appleid.apple.com");
    expect(res.headers.get('permissions-policy')).toContain('publickey-credentials-get=(self), publickey-credentials-create=(self)');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('strict-transport-security')).toMatch(/max-age=31536000/);
    expect(res.headers.get('cache-control')).toBe('no-store');
    // Local dev over http: no HSTS.
    expect((await client(worker.fetch, makeEnv())('/auth/login')).headers.get('strict-transport-security')).toBeNull();
  });
});

describe('CSRF origin check', () => {
  it('refuses writes without our Origin and reports them', async () => {
    const events = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const env = makeEnv();
    const u = await insertUser(env.DB);
    const s = await insertSession(env.DB, makeCfg(), u, 'passkey');
    const req = client(worker.fetch, env);
    for (const origin of ['https://evil.example', null]) {
      const res = await req('/auth/api/sign-out-everywhere', { method: 'POST', origin, cookie: `auth_session=${s.token}` });
      expect(res.status).toBe(403);
    }
    expect((await req('/auth/logout', { method: 'POST', origin: 'https://evil.example', cookie: `auth_session=${s.token}` })).status).toBe(403);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions')).toBe(1);
    expect(events.mock.calls.map(c => String(c[0])).join()).toMatch(/origin-blocked.*foreign_origin.*origin-blocked.*no_origin/);
  });
});

describe('body limit counts actual bytes', () => {
  it('rejects an oversized Apple form_post without Content-Length (413) before parsing', async () => {
    const res = await client(worker.fetch, makeEnv())('/auth/apple/callback', {
      method: 'POST', origin: 'https://appleid.apple.com', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: chunked(300 * 1024), duplex: 'half',
    } as RequestInit);
    expect(res.status).toBe(413);
  });

  it('rejects an oversized chunked JSON body; small ones still work', async () => {
    const req = client(worker.fetch, makeEnv());
    const big = await req('/auth/api/passkey/login/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: chunked(300 * 1024), duplex: 'half' } as RequestInit);
    expect(big.status).toBe(413);
    const small = await req('/auth/api/passkey/login/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(small.status).toBe(200);
  });
});

describe('rate limits', () => {
  it('limits flow starts per IP (HMAC’d, never stored raw) and sends Retry-After', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const env = makeEnv({ GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 's' });
    const req = client(worker.fetch, env);
    const opts = (ip: string) => req('/auth/api/passkey/login/options', { method: 'POST', body: '{}', ip });
    for (let i = 0; i < 60; i++) expect((await opts('203.0.113.7')).status).toBe(200);
    const limited = await opts('203.0.113.7');
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
    expect((await opts('203.0.113.8')).status).toBe(200);
    for (let i = 0; i < 60; i++) expect((await req('/auth/google/start', { ip: '203.0.113.9' })).status).toBe(302);
    expect((await req('/auth/google/start', { ip: '203.0.113.9' })).status).toBe(429);
    expect(await count(env.DB, "SELECT COUNT(*) AS n FROM rate_counters WHERE key LIKE '%203.0.113%'")).toBe(0);
  });
});

describe('housekeeping and config', () => {
  it('cleanup removes expired sessions, flows and counters only', async () => {
    const env = makeEnv();
    const u = await insertUser(env.DB);
    await insertSession(env.DB, makeCfg(), u, 'passkey', Date.now() - 40 * 86_400_000);
    await insertSession(env.DB, makeCfg(), u, 'passkey');
    await env.DB.prepare("INSERT INTO auth_flows (id, kind, data, expires_at, created_at) VALUES ('old', 'passkey-login', '{}', 1, 0), ('new', 'passkey-login', '{}', ?, 0)").bind(Date.now() + 60_000).run();
    await auth.cleanup(env.DB);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM sessions')).toBe(1);
    expect(await count(env.DB, 'SELECT COUNT(*) AS n FROM auth_flows')).toBe(1);
  });

  it('wrangler.jsonc keeps invocation logs off and has no secrets', () => {
    const w = readFileSync('wrangler.jsonc', 'utf8');
    expect(w).toMatch(/"invocation_logs": false/);
    expect(w).not.toMatch(/"(SESSION_SECRET|GOOGLE_CLIENT_SECRET|APPLE_PRIVATE_KEY)"\s*:/);
  });

  it('logIncident never logs the error message', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { logIncident } = await import('../src/auth/http');
    const id = logIncident('test', new Error('token=secret-value'));
    expect(id).toHaveLength(8);
    expect(String(log.mock.calls[0]![0])).not.toContain('secret-value');
  });

  it('the example origin is what the tests use', () => {
    expect(ORIGIN).toBe('http://localhost:8787');
  });
});
