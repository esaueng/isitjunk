import { beforeAll, beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import { fakeD1, makeEnv } from './helpers';
import type { Env } from '../src/types';

const origin = 'https://admin.example.com';
let privateKey: CryptoKey;
let jwk: Awaited<ReturnType<typeof exportJWK>>;
let handleAdmin: typeof import('../src/admin').handleAdmin;
let fetchKeys: ReturnType<typeof vi.fn>;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  jwk = { ...(await exportJWK(pair.publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
});
beforeEach(async () => {
  vi.resetModules();
  fetchKeys = vi.fn(async () => Response.json({ keys: [jwk] }));
  vi.stubGlobal('fetch', fetchKeys);
  ({ handleAdmin } = await import('../src/admin'));
});
afterEach(() => vi.unstubAllGlobals());

async function assertion(overrides: JWTPayload = {}, key = privateKey, algorithm = 'RS256') {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: 'https://test.cloudflareaccess.com', aud: ['admin-audience'], sub: 'test-user',
    email: 'admin@example.com', type: 'app', iat: now, exp: now + 3600, ...overrides,
  }).setProtectedHeader({ alg: algorithm, kid: 'test-key' }).sign(key);
}
async function send(path = '/admin', init: RequestInit = {}, env: Partial<Env> = {}) {
  const url = new URL(path.startsWith('https:') ? path : `${origin}${path.replace(/^\/admin(?=\/|$)/, '') || '/'}`);
  return handleAdmin(new Request(url, init), makeEnv(env), url);
}
async function authed(path = '/admin', init: RequestInit = {}, env: Partial<Env> = {}) {
  const headers = new Headers(init.headers);
  headers.set('cf-access-jwt-assertion', await assertion());
  return send(path, { ...init, headers }, env);
}

describe('Access-only admin', () => {
  it.each(['/admin', '/admin/stats', '/admin/login', `${origin}/`, `${origin}/login`])('requires signed Access identity at %s', async path => {
    const res = await send(path);
    expect(res?.status).toBe(403);
    expect(res?.headers.get('cache-control')).toBe('no-store');
    expect(fetchKeys).not.toHaveBeenCalled();
  });
  it.each([
    { authorization: 'Bearer super-secret-admin-token' },
    { cookie: 'ij_admin=old-session' },
    { 'cf-access-authenticated-user-email': 'admin@example.com' },
  ])('does not trust legacy credentials or an unsigned email header', async headers => {
    expect((await send('/admin', { headers: Object.entries(headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string') }))?.status).toBe(403);
  });
  it('renders the dashboard immediately after verified Access sign-in', async () => {
    const res = await authed(`${origin}/`);
    expect(res?.status).toBe(200);
    expect(res?.headers.get('cache-control')).toBe('no-store');
    const body = await res!.text();
    expect(body).toContain('Reset stats');
    expect(body).not.toContain('Admin token');
    expect(body).toContain(`action="${origin}/reset-stats"`);
    expect(body).toContain(`href="${origin}/cdn-cgi/access/logout"`);
    expect(res?.headers.has('set-cookie')).toBe(false);
    expect(fetchKeys.mock.calls[0][0].toString()).toBe('https://test.cloudflareaccess.com/cdn-cgi/access/certs');
  });
  it.each([
    { iss: 'https://other.cloudflareaccess.com' }, { aud: ['another-application'] },
    { exp: 1 }, { exp: undefined }, { iat: undefined }, { sub: undefined },
    { nbf: Math.floor(Date.now() / 1000) + 3600 },
    { email: 'someone@example.com' }, { email: undefined }, { type: 'org' },
  ])('rejects invalid claims %j', async claims => {
    const res = await send('/admin', { headers: { 'cf-access-jwt-assertion': await assertion(claims) } });
    expect(res?.status).toBe(403);
  });
  it('rejects forged signatures', async () => {
    const other = await generateKeyPair('RS256');
    expect((await send('/admin', { headers: { 'cf-access-jwt-assertion': await assertion({}, other.privateKey) } }))?.status).toBe(403);
  });
  it('rejects unsupported signing algorithms', async () => {
    const other = await generateKeyPair('ES256');
    expect((await send('/admin', { headers: { 'cf-access-jwt-assertion': await assertion({}, other.privateKey, 'ES256') } }))?.status).toBe(403);
  });
  it('rejects malformed tokens', async () => {
    expect((await send('/admin', { headers: { 'cf-access-jwt-assertion': 'not.a.jwt' } }))?.status).toBe(403);
  });
  it('fails closed when signing keys are unavailable', async () => {
    fetchKeys.mockRejectedValue(new Error('unavailable'));
    expect((await authed())?.status).toBe(403);
  });
  it('accepts email capitalization without trusting the unsigned email header', async () => {
    expect((await send('/admin', { headers: { 'cf-access-jwt-assertion': await assertion({ email: 'ADMIN@EXAMPLE.COM' }) } }))?.status).toBe(200);
  });
  it.each(['ACCESS_TEAM_DOMAIN', 'ACCESS_AUD', 'ADMIN_HOST', 'ADMIN_EMAIL'])('fails closed without %s', async setting => {
    const config = { [setting]: '' };
    const url = setting === 'ADMIN_HOST' ? new URL(`${origin}/admin`) : new URL(`${origin}/`);
    expect((await handleAdmin(new Request(url), makeEnv(config), url))?.status).toBe(503);
  });
  it.each([
    { ACCESS_TEAM_DOMAIN: 'attacker.example' }, { ADMIN_HOST: 'http://admin.example.com' },
    { ADMIN_HOST: 'admin.example.com/path' }, { ADMIN_HOST: 'user:pass@admin.example.com' },
  ])('rejects unsafe configuration %j', async config => {
    const { accessConfig } = await import('../src/access');
    expect(accessConfig(makeEnv(config))).toBeNull();
  });
  it.each(['GET', 'POST'])('redirects legacy %s login to the dashboard without creating a session', async method => {
    const res = await authed('/admin/login', { method });
    expect(res?.status).toBe(303);
    expect(res?.headers.get('location')).toBe(`${origin}/`);
    expect(res?.headers.has('set-cookie')).toBe(false);
  });
  it('uses Access logout', async () => {
    const res = await authed('/admin/logout', { method: 'POST', headers: { origin } });
    expect(res?.headers.get('location')).toBe(`${origin}/cdn-cgi/access/logout`);
  });
  it('preserves stats and daily trends', async () => {
    const { db } = fakeD1({ total_processed: 3, total_junk: 1, total_notjunk: 1, total_uncertain: 1 });
    const res = await authed(`${origin}/stats`, {}, { DB: db });
    expect(res?.status).toBe(200);
    expect(await res!.json()).toMatchObject({ stats_enabled: true, total_processed: 3, total_junk: 1, history: [] });
  });
  it('reports disabled storage and disables reset when D1 is absent', async () => {
    const res = await authed('/admin', {}, { DB: undefined });
    const body = await res!.text();
    expect(body).toContain('Stats storage is not configured');
    expect(body).toContain('disabled aria-disabled="true"');
    const stats = await authed('/admin/stats', {}, { DB: undefined });
    expect(await stats!.json()).toMatchObject({ stats_enabled: false });
  });
  it.each([undefined, 'null', 'https://evil.example', 'http://admin.example.com', 'https://admin.example.com:444'])('rejects reset Origin %s without touching counters', async requestOrigin => {
    const { db, peek } = fakeD1({ total_processed: 9 });
    const headers: Record<string, string> = requestOrigin ? { origin: requestOrigin } : {};
    const res = await authed('/admin/reset-stats', { method: 'POST', headers }, { DB: db });
    expect(res?.status).toBe(403);
    expect(peek()?.total_processed).toBe(9);
  });
  it('accepts a reset from the configured HTTPS admin origin', async () => {
    const { db, peek } = fakeD1({ total_processed: 9, total_junk: 4, total_notjunk: 3, total_uncertain: 2 });
    const res = await authed('/admin/reset-stats', { method: 'POST', headers: { origin, accept: 'text/html' } }, { DB: db });
    expect(res?.status).toBe(303);
    expect(res?.headers.get('location')).toBe(`${origin}/`);
    expect(peek()).toMatchObject({ total_processed: 0, total_junk: 0, total_notjunk: 0, total_uncertain: 0 });
  });
  it('ignores spoofed forwarded-host headers', async () => {
    const res = await authed('/admin/reset-stats', { method: 'POST', headers: { origin: 'https://evil.example', 'x-forwarded-host': 'evil.example' } });
    expect(res?.status).toBe(403);
  });
  it('rejects an unauthenticated reset without touching counters', async () => {
    const { db, peek } = fakeD1({ total_processed: 9 });
    expect((await send('/admin/reset-stats', { method: 'POST', headers: { origin } }, { DB: db }))?.status).toBe(403);
    expect(peek()?.total_processed).toBe(9);
  });
  it('returns JSON for authenticated reset clients on the public host', async () => {
    const { db } = fakeD1({ total_processed: 9 });
    const res = await authed(`${origin}/reset-stats`, { method: 'POST', headers: { origin } }, { DB: db });
    expect(res?.status).toBe(200);
    expect(await res!.json()).toMatchObject({ ok: true, total_processed: 0 });
  });
  it('does not reset counters via GET', async () => {
    expect((await authed('/admin/reset-stats'))?.status).toBe(405);
  });
  it('keeps admin unavailable on other hosts even with a signed assertion', async () => {
    expect(await authed('https://backend.workers.dev/admin')).toBeNull();
  });
  it('preserves prefixed bookmark redirects', async () => {
    const res = await authed(`${origin}/admin/stats?view=all`);
    expect(res?.status).toBe(308);
    expect(res?.headers.get('location')).toBe('/stats?view=all');
  });
  it('preserves CSP and reset confirmation without inline event handlers', async () => {
    const res = await authed();
    const csp = res!.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("'sha256-");
    const body = await res!.text();
    expect(body).toContain('data-confirm-reset');
    expect(body).not.toContain('onsubmit=');
  });
  it.each(['/', '/public/stats'])('leaves non-admin host route %s alone', async path => {
    expect(await send(`https://backend.workers.dev${path}`)).toBeNull();
  });
});
