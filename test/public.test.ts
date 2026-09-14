import { describe, expect, it } from 'vitest';
import { handlePublic } from '../src/public';
import { recordAnalysis } from '../src/stats';
import { fakeD1, makeEnv } from './helpers';

describe('public stats', () => {
  it('keeps lifetime fields and adds bounded aggregate-only history', async () => {
    const { db } = fakeD1();
    const env = makeEnv({ DB: db });
    await recordAnalysis(env, "Yes, it's Junk", new Date('2026-07-18T12:00:00Z'));
    await recordAnalysis(env, 'No, Not Junk', new Date('2026-07-19T12:00:00Z'));

    const request = new Request('https://www.isitjunk.com/public/stats');
    const response = await handlePublic(request, env, new URL(request.url));

    expect(response?.status).toBe(200);
    expect(await response!.json()).toEqual({
      total_processed: 2,
      total_junk: 1,
      total_notjunk: 1,
      total_uncertain: 0,
      history: [
        { day: '2026-07-18', total_processed: 1, total_junk: 1, total_notjunk: 0, total_uncertain: 0 },
        { day: '2026-07-19', total_processed: 1, total_junk: 0, total_notjunk: 1, total_uncertain: 0 },
      ],
    });
  });

  it('renders a server-side daily trend without message-level data', async () => {
    const { db } = fakeD1();
    const env = makeEnv({ DB: db });
    await recordAnalysis(env, 'Uncertain', new Date('2026-07-19T12:00:00Z'));

    const request = new Request('https://www.isitjunk.com/public');
    const response = await handlePublic(request, env, new URL(request.url));
    const body = await response!.text();

    expect(body).toContain('Last 1 active days');
    expect(body).toContain('2026-07-19');
    expect(body).toContain('Aggregate totals only');
  });
});

async function cspHashOfEmbeddedScript(body: string): Promise<string> {
  const src = body.slice(body.indexOf('<script>') + '<script>'.length, body.indexOf('</script>'));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(src));
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

describe('public page — security headers', () => {
  it('sends a strict CSP whose script hash matches the embedded refresh script, plus anti-framing/sniffing headers', async () => {
    const { db } = fakeD1({ total_processed: 3 });
    const res = await handlePublic(new Request('https://www.isitjunk.com/public'), makeEnv({ DB: db }), new URL('https://www.isitjunk.com/public'));
    expect(res?.status).toBe(200);
    const body = await res!.text();
    const csp = res!.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    const scriptSrc = csp.match(/script-src ([^;]*)/)?.[1] ?? '';
    expect(scriptSrc).not.toContain('unsafe-inline'); // scripts are allowed by hash only
    expect(scriptSrc).toMatch(/^'sha256-[A-Za-z0-9+/=]+'$/);
    expect(csp).toContain(`script-src 'sha256-${await cspHashOfEmbeddedScript(body)}'`);
    expect(csp).toContain("connect-src 'self'"); // the refresh fetch
    expect(res!.headers.get('x-frame-options')).toBe('DENY');
    expect(res!.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res!.headers.get('referrer-policy')).toBe('no-referrer');
  });
});
