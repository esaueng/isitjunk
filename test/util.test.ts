import { describe, it, expect, vi, afterEach } from 'vitest';
import { escapeHtml, fetchWithRetry } from '../src/util';

describe('escapeHtml', () => {
  it('escapes the dangerous characters', () => {
    expect(escapeHtml('<script>"x"&\'y\'')).toBe('&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;');
  });
});

describe('fetchWithRetry timeout', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('aborts an attempt that exceeds timeoutMs and gives each attempt a fresh signal', async () => {
    const signals: AbortSignal[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: unknown, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            signals.push(init.signal!);
            init.signal!.addEventListener('abort', () => reject(init.signal!.reason));
          }),
      ),
    );
    await expect(fetchWithRetry('https://upstream.test/', {}, { retries: 1, backoffMs: 0, timeoutMs: 20 })).rejects.toThrow();
    expect(signals).toHaveLength(2);
    expect(signals[0]).not.toBe(signals[1]);
    expect(signals.every((s) => s.aborted)).toBe(true);
  });

  it('passes no signal when timeoutMs is not set', async () => {
    let seen: RequestInit | undefined;
    vi.stubGlobal('fetch', vi.fn(async (_url: unknown, init: RequestInit) => { seen = init; return new Response('ok'); }));
    await fetchWithRetry('https://upstream.test/', {}, { retries: 0 });
    expect(seen?.signal).toBeUndefined();
  });
});

describe('fetchWithRetry response ownership', () => {
  afterEach(() => vi.unstubAllGlobals());

  function response(status: number, text: string, cancel: () => void | Promise<void>) {
    return new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode(text)); },
      cancel,
    }), { status });
  }

  it('cancels discarded 429/5xx bodies before the next request and preserves the identical request body', async () => {
    const cancelled: number[] = [];
    const body = JSON.stringify({ provider: { zdr: true } });
    const seenBodies: BodyInit[] = [];
    const final = new Response('ok');
    let attempt = 0;
    vi.stubGlobal('fetch', vi.fn(async (_url: unknown, init: RequestInit) => {
      expect(cancelled).toHaveLength(attempt);
      seenBodies.push(init.body!);
      if (attempt++ === 0) return response(429, 'retry', () => { cancelled.push(429); });
      if (attempt === 2) return response(503, 'retry', () => { cancelled.push(503); });
      return final;
    }));
    const result = await fetchWithRetry('https://upstream.test/', { method: 'POST', body }, { retries: 2, backoffMs: 0 });
    expect(result).toBe(final);
    expect(cancelled).toEqual([429, 503]);
    expect(seenBodies).toEqual([body, body, body]);
    expect(await result.text()).toBe('ok');
  });

  it.each(['rejects', 'never settles'] as const)('keeps retrying when body cancellation %s', async (mode) => {
    const cancel = vi.fn(() => mode === 'rejects'
      ? Promise.reject(new Error('cleanup failed'))
      : new Promise<void>(() => undefined));
    const final = new Response('ok');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response(503, 'retry', cancel)).mockResolvedValueOnce(final));
    expect(await fetchWithRetry('https://upstream.test/', {}, { retries: 1, backoffMs: 0, timeoutMs: 50 })).toBe(final);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it.each([400, 429, 503])('leaves a returned %i response body owned by the caller', async (status) => {
    const cancel = vi.fn();
    const final = response(status, 'caller body', cancel);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(final));
    const result = await fetchWithRetry('https://upstream.test/', {}, { retries: 0 });
    expect(result).toBe(final);
    expect(cancel).not.toHaveBeenCalled();
    const reader = result.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('caller body');
    await reader.cancel();
  });

  it('keeps the exhausted transient response readable after releasing earlier attempts', async () => {
    const firstCancel = vi.fn();
    const finalCancel = vi.fn();
    const final = response(503, 'final error', finalCancel);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response(503, 'discard', firstCancel)).mockResolvedValueOnce(final));
    const result = await fetchWithRetry('https://upstream.test/', {}, { retries: 1, backoffMs: 0 });
    expect(firstCancel).toHaveBeenCalledOnce();
    expect(finalCancel).not.toHaveBeenCalled();
    const reader = result.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('final error');
    await reader.cancel();
  });
});
