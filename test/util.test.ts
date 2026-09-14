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
