import { afterEach, describe, it, expect, vi } from 'vitest';
import { verifyDomains } from '../src/verify';
import type { ExtractedSender } from '../src/types';

const BASE: ExtractedSender = {
  originalFromEmail: 'bob@quenvvorthinc.net',
  originalFromName: 'Quenvorth, Inc',
  originalReplyTo: null,
  claimedCompany: 'Quenvorth, Inc',
  isContactForm: false,
  submitterEmail: null,
  candidateDomains: ['quenvvorthinc.net'],
  confidence: 'high',
  method: 'inline-headers',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('bounded verification of attacker input', () => {
  it('discards oversized company claims without losing independent domain facts', async () => {
    const fetcher = vi.fn(async () => Response.json({ Status: 0, Answer: [] }));
    const [evidence] = await verifyDomains({ ...BASE, claimedCompany: 'z'.repeat(390_000) }, { fetcher });
    expect(evidence.lookalikeOf).toBeNull();
    expect(evidence.domain).toBe(BASE.candidateDomains[0]);
  });

  it.each([
    'https://unrelated.example/', 'http://quenvvorthinc.net/',
    'https://quenvvorthinc.net/path', 'https://quenvvorthinc.net/?tracking=1',
    'https://quenvvorthinc.net/#fragment', 'https://user:pass@quenvvorthinc.net/',
    'https://quenvvorthinc.net:8443/', 'http://127.0.0.1/',
  ])('records but never fetches a disallowed website redirect %#', async (location) => {
    const websiteRequests: string[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 0, Answer: [] });
      if (url.includes('rdap.org')) return Response.json({});
      websiteRequests.push(url);
      expect(init?.redirect).toBe('manual');
      return new Response(null, { status: 302, headers: { location } });
    });
    const [evidence] = await verifyDomains(BASE, { fetcher });
    expect(websiteRequests).toEqual(['https://quenvvorthinc.net/']);
    expect(evidence.website.status).toBe('unchecked');
    expect(evidence.checkedAt).toBe('partial');
  });

  it('follows a legitimate HTTPS apex-to-www root redirect', async () => {
    const websiteRequests: string[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 0, Answer: [] });
      if (url.includes('rdap.org')) return Response.json({});
      websiteRequests.push(url);
      return url === 'https://quenvvorthinc.net/'
        ? new Response(null, { status: 301, headers: { location: 'https://www.quenvvorthinc.net/' } })
        : new Response('<title>Vendor</title>');
    });
    const [evidence] = await verifyDomains(BASE, { fetcher });
    expect(websiteRequests).toEqual(['https://quenvvorthinc.net/', 'https://www.quenvvorthinc.net/']);
    expect(evidence.website.title).toBe('Vendor');
  });
});

describe('verifyDomains', () => {
  it('skips network verification for freemail domains and emits the freemail fact', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const evidence = await verifyDomains(
      {
        ...BASE,
        originalFromEmail: 'sender@gmail.com',
        originalFromName: 'A Business',
        claimedCompany: 'A Business',
        candidateDomains: ['gmail.com'],
      },
      { timeoutMs: 500, now: new Date('2026-07-07T00:00:00Z') },
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(evidence).toEqual([
      expect.objectContaining({
        domain: 'gmail.com',
        role: 'original-from',
        freemail: true,
        checkedAt: 'skipped',
        website: expect.objectContaining({ status: 'unchecked' }),
      }),
    ]);
  });

  it('assembles DNS, parked website, RDAP age, and look-alike evidence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('cloudflare-dns.com') && url.includes('type=A')) {
          return Response.json({ Status: 0, Answer: [{ data: '203.0.113.10' }] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=AAAA')) {
          return Response.json({ Status: 0, Answer: [] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=MX')) {
          return Response.json({ Status: 0, Answer: [] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('name=_dmarc.')) {
          return Response.json({ Status: 0, Answer: [] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=TXT')) {
          return Response.json({ Status: 0, Answer: [{ data: '"v=spf1 include:spf.example -all"' }] });
        }
        if (url === 'https://quenvvorthinc.net/') {
          return new Response('<html><title>For sale</title><body>This domain is for sale on GoDaddy.</body></html>');
        }
        if (url.includes('rdap.org/domain/quenvvorthinc.net')) {
          return Response.json({
            events: [{ eventAction: 'registration', eventDate: '2026-06-20T00:00:00Z' }],
            entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'NameSilo']]] }],
            status: ['active'],
          });
        }
        return new Response('not found', { status: 404 });
      }),
    );

    const evidence = await verifyDomains(BASE, {
      timeoutMs: 1000,
      now: new Date('2026-07-07T00:00:00Z'),
    });

    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({
      domain: 'quenvvorthinc.net',
      role: 'original-from',
      dns: { resolves: true, hasMx: false, hasSpf: true, dmarcPolicy: null },
      website: { status: 'parked', httpStatus: 200, finalDomain: 'quenvvorthinc.net', title: 'For sale' },
      registration: { ageDays: 17, registrar: 'NameSilo', unregistered: false },
      freemail: false,
      disposable: false,
      lookalikeOf: 'quenvorth.com',
      checkedAt: 'complete',
    });
  });

  it('keeps DNS facts unknown when DoH is unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('cloudflare-dns.com')) return new Response('resolver down', { status: 503 });
        if (url === 'https://quenvvorthinc.net/') return new Response('<html><title>Quenvorth</title></html>');
        if (url.includes('rdap.org/domain/quenvvorthinc.net')) return Response.json({ events: [] });
        return new Response('not found', { status: 404 });
      }),
    );

    const evidence = await verifyDomains(BASE, { timeoutMs: 1000, now: new Date('2026-07-07T00:00:00Z') });

    expect(evidence[0].dns).toEqual({ resolves: null, hasMx: null, hasSpf: null, dmarcPolicy: null });
  });

  it('keeps successful DNS facts when one DoH subquery fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('cloudflare-dns.com') && url.includes('type=AAAA')) {
          throw new Error('AAAA timeout');
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=A')) {
          return Response.json({ Status: 0, Answer: [{ data: '203.0.113.10' }] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=MX')) {
          return Response.json({ Status: 0, Answer: [{ data: '10 mail.example.net.' }] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('name=_dmarc.')) {
          return Response.json({ Status: 0, Answer: [{ data: '"v=DMARC1; p=reject"' }] });
        }
        if (url.includes('cloudflare-dns.com') && url.includes('type=TXT')) {
          return Response.json({ Status: 0, Answer: [{ data: '"v=spf1 -all"' }] });
        }
        if (url === 'https://quenvvorthinc.net/') return new Response('<html><title>Quenvorth</title></html>');
        if (url.includes('rdap.org/domain/quenvvorthinc.net')) return Response.json({ events: [] });
        return new Response('not found', { status: 404 });
      }),
    );

    const evidence = await verifyDomains(BASE, { timeoutMs: 1000, now: new Date('2026-07-07T00:00:00Z') });

    expect(evidence[0]).toMatchObject({
      dns: { resolves: true, hasMx: true, hasSpf: true, dmarcPolicy: 'reject' },
      checkedAt: 'partial',
    });
  });

  it('uses one shared timeout signal for all checks on a domain', async () => {
    const signals: AbortSignal[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.signal) signals.push(init.signal);
      const url = String(input);
      if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 0, Answer: [] });
      if (url === 'https://quenvvorthinc.net/') return new Response('<html><title>Quenvorth</title></html>');
      if (url.includes('rdap.org/domain/quenvvorthinc.net')) return Response.json({ events: [] });
      return new Response('not found', { status: 404 });
    });

    await verifyDomains(BASE, {
      fetcher: fetcher as typeof fetch,
      timeoutMs: 1000,
      now: new Date('2026-07-07T00:00:00Z'),
    });

    expect(new Set(signals).size).toBe(1);
  });

  it('records unrelated website redirects, body size, and RDAP status values', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('cloudflare-dns.com') && url.includes('type=A')) {
          return Response.json({ Status: 0, Answer: [{ data: '203.0.113.10' }] });
        }
        if (url.includes('cloudflare-dns.com')) return Response.json({ Status: 0, Answer: [] });
        if (url === 'https://quenvvorthinc.net/') {
          const body = '<html><title>Hosted Landing</title><body>ok</body></html>';
          const res = new Response(body);
          Object.defineProperty(res, 'url', { value: 'https://unrelated-hosting.com/landing' });
          return res;
        }
        if (url.includes('rdap.org/domain/quenvvorthinc.net')) {
          return Response.json({
            events: [{ eventAction: 'registration', eventDate: '2025-07-07T00:00:00Z' }],
            status: ['clientHold', 'serverTransferProhibited'],
          });
        }
        return new Response('not found', { status: 404 });
      }),
    );

    const evidence = await verifyDomains(BASE, { timeoutMs: 1000, now: new Date('2026-07-07T00:00:00Z') });

    expect(evidence[0]).toMatchObject({
      website: {
        status: 'live',
        finalDomain: 'unrelated-hosting.com',
        redirectedToUnrelatedDomain: true,
        bodyBytes: 57,
      },
      registration: {
        ageDays: 365,
        statuses: ['clientHold', 'serverTransferProhibited'],
      },
    });
  });
});
