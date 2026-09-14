import { afterEach, describe, it, expect, vi } from 'vitest';
import { parseAnalysis, runAnalysis, runExtraction } from '../src/openrouter';
import { HttpError } from '../src/util';
import { makeEnv } from './helpers';

describe('parseAnalysis', () => {
  it('splits the ~-separated four fields and trims them', () => {
    const a = parseAnalysis("0.91~Yes, it's Junk~Suspicious links~Account Notice");
    expect(a).toEqual({
      score: '0.91',
      label: "Yes, it's Junk",
      reason: 'Suspicious links',
      subject: 'Account Notice',
    });
  });
  it('uses null for empty or missing fields', () => {
    expect(parseAnalysis('0.1~No, Not Junk')).toEqual({
      score: '0.1',
      label: 'No, Not Junk',
      reason: null,
      subject: null,
    });
    expect(parseAnalysis('')).toEqual({ score: null, label: null, reason: null, subject: null });
  });

  it('keeps subject as the last field when reason contains extra ~', () => {
    const a = parseAnalysis("0.9~Yes, it's Junk~links ~ urgent tone~Real Subject");
    expect(a).toEqual({
      score: '0.9',
      label: "Yes, it's Junk",
      reason: 'links ~ urgent tone',
      subject: 'Real Subject',
    });
  });
});

describe('runAnalysis — ZDR enforcement', () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubFetch(impl: (url: string, init: RequestInit) => Response) {
    const spy = vi.fn(async (url: unknown, init: unknown) =>
      impl(String(url), init as RequestInit),
    );
    vi.stubGlobal('fetch', spy);
    return spy;
  }

  it('sends provider.zdr=true and data_collection=deny on every request', async () => {
    let sentBody: any;
    const spy = stubFetch((_url, init) => {
      sentBody = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ choices: [{ message: { content: '0.1~No, Not Junk~ok~S' } }] }), {
        status: 200,
      });
    });

    const out = await runAnalysis(makeEnv(), 'email text');
    expect(out).toContain('No, Not Junk');
    expect(spy).toHaveBeenCalledOnce();
    expect(sentBody.provider).toEqual({ zdr: true, data_collection: 'deny' });
    expect(sentBody.model).toBe('openai/gpt-5.5');
  });

  it('uses the current smaller GPT model for sender extraction by default', async () => {
    let sentBody: any;
    stubFetch((_url, init) => {
      sentBody = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ choices: [{ message: { content: '{}' } }] }), { status: 200 });
    });

    await runExtraction(makeEnv(), 'email text');
    expect(sentBody.model).toBe('openai/gpt-5.4-mini');
    expect(sentBody.provider).toEqual({ zdr: true, data_collection: 'deny' });
  });

  it('uses a ZDR-enforced models[] array when fallbacks are configured', async () => {
    let sentBody: any;
    stubFetch((_url, init) => {
      sentBody = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ choices: [{ message: { content: '0.1~No~ok~S' } }] }), {
        status: 200,
      });
    });

    await runAnalysis(makeEnv({ OPENROUTER_MODEL: 'm/primary', OPENROUTER_FALLBACK_MODELS: 'm/a, m/b' }), 'x');
    expect(sentBody.provider).toEqual({ zdr: true, data_collection: 'deny' });
    expect(sentBody.models).toEqual(['m/primary', 'm/a', 'm/b']);
    expect(sentBody.model).toBeUndefined();
  });

  it('fails closed (503, no retry) when no ZDR provider can route the model', async () => {
    const spy = stubFetch(() =>
      new Response(JSON.stringify({ error: { message: 'No allowed providers are available for the selected data policy' } }), {
        status: 404,
      }),
    );

    const err = await runAnalysis(makeEnv(), 'x').catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(503);
    // Crucially: no retry onto another (possibly non-ZDR) provider.
    expect(spy).toHaveBeenCalledOnce();
  });

  it('returns 502 when the model returns empty content', async () => {
    stubFetch(() => new Response(JSON.stringify({ choices: [{ message: { content: '' } }] }), { status: 200 }));
    await expect(runAnalysis(makeEnv(), 'x')).rejects.toMatchObject({ status: 502 });
  });

  it('fails closed (503) on a 200 body carrying a ZDR/data-policy error', async () => {
    const spy = stubFetch(() =>
      new Response(JSON.stringify({ error: { message: 'No allowed providers for your data policy' } }), {
        status: 200,
      }),
    );
    const err = await runAnalysis(makeEnv(), 'x').catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(503);
    expect(spy).toHaveBeenCalledOnce();
  });

  it('returns 502 on a 200 body carrying a non-ZDR error', async () => {
    stubFetch(() => new Response(JSON.stringify({ error: { message: 'temporary upstream hiccup' } }), { status: 200 }));
    await expect(runAnalysis(makeEnv(), 'x')).rejects.toMatchObject({ status: 502 });
  });

  it('fails closed (503) when a ZDR refusal is surfaced as a 5xx', async () => {
    // 5xx is retried (same ZDR-enforced body each time); the final response still
    // classifies as a data-policy refusal, so we fail closed rather than 502.
    stubFetch(() => new Response('No allowed providers for your data policy', { status: 500 }));
    const err = await runAnalysis(makeEnv(), 'x').catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect(err.status).toBe(503);
  }, 10000);
});

describe('runAnalysis — request timeout', () => {
  it('sends every OpenRouter attempt with an abort signal', async () => {
    let seen: RequestInit | undefined;
    vi.stubGlobal('fetch', vi.fn(async (_url: unknown, init: unknown) => {
      seen = init as RequestInit;
      return new Response(JSON.stringify({ choices: [{ message: { content: '0.5~Uncertain~x~y' } }] }), { status: 200 });
    }));
    await runAnalysis({ OPENROUTER_API_KEY: 'sk-or-test' } as never, 'hello');
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
    vi.unstubAllGlobals();
  });
});
