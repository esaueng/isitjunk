import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import { extractSender } from '../src/extract';
import { readInbound } from '../src/payload';
import type { ExtractedSender, InboundEmail } from '../src/types';
import { verifyDomains } from '../src/verify';

function inbound(body: string): InboundEmail {
  const raw = `From: reporter@example.com\r\nTo: report@isitjunk.com\r\n\r\n${body}`;
  return {
    from: 'reporter@example.com', to: 'report@isitjunk.com', subject: 'Check',
    messageId: '', authResults: '', autoSubmitted: '', precedence: '', autoResponseSuppress: '',
    raw, rawSize: raw.length, rawBytesRead: raw.length, rawTruncated: false,
  };
}

describe('bounded sender parsing', () => {
  // A generous per-operation budget: these inputs previously took seconds on
  // an idle machine. Keep the fixtures below the ingress byte cap.
  it('finds a real contact address after a long non-address prefix', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(`Email: ${'!'.repeat(32_000)} @invalid person@vendor.example\r\nCompany: Vendor`));
    expect(result.submitterEmail).toBe('person@vendor.example');
    expect(result.candidateDomains).toEqual(['vendor.example']);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('finishes the forwarded-header parser and its regex fallback for a non-address', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(`---------- Forwarded message ---------\r\nFrom: ${'!'.repeat(32_000)}\r\nSubject: Hello`));
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(result.method).toBe('none');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('rejects a long model-derived non-address without a costly suffix search', async () => {
    const start = performance.now();
    const result = await extractSender(inbound('Hello'), {
      llmExtract: async () => ({ reply_to: '!'.repeat(64_000) }),
    });
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(result.originalReplyTo).toBeNull();
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it.each([
    ['repeated mailto attributes', `<a ${'href="mailto:!"'.repeat(16_000)}`],
    ['unclosed nested tags', '<a '.repeat(16_000)],
    ['invalid bracketed address', `<x@a${'.'.repeat(32_000)}!>`],
  ])('handles %s without repeated suffix scans', async (_name, body) => {
    const start = performance.now();
    const result = await extractSender(inbound(body));
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('keeps mailto extraction, display names, punctuation and case normalization', async () => {
    const result = await extractSender(inbound('Email: <a title="contact" href="mailto:Buyer+Tag@Vendor-Name.example">Contact us</a>\r\nCompany: Vendor'));
    expect(result.submitterEmail).toBe('buyer+tag@vendor-name.example');
    expect(result.candidateDomains).toEqual(['vendor-name.example']);
  });

  it('does not truncate an existing accepted local part into a different mailbox', async () => {
    const email = `${'!'.repeat(300)}@vendor.example`;
    const result = await extractSender(inbound(`Email: ${email}\r\nCompany: Vendor`));
    expect(result.submitterEmail).toBe(email);
  });

  it('preserves a mailto address when a quoted attribute contains a less-than sign', async () => {
    const result = await extractSender(inbound('Email: <a title="a < b" href="mailto:buyer@vendor.example">Contact</a><br>Company: Vendor LLC'));
    expect(result.submitterEmail).toBe('buyer@vendor.example');
    expect(result.method).toBe('contact-form');
    expect(result.candidateDomains).toEqual(['vendor.example']);
  });

  it('preserves first-substring matching across generated address and display-text forms', async () => {
    // Compatibility oracle: the previous expression, used only on short data.
    const previous = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/i;
    const atoms = ['Alice', '!', '@', '.', '-', '+tag', 'a'.repeat(70), 'x.y', ' < ', '>', ': ', '\n', 'K'];
    let seed = 0x51a7;
    for (let i = 0; i < 1000; i++) {
      let candidate = '';
      for (let j = 0; j < 10; j++) {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        candidate += atoms[seed % atoms.length];
      }
      if (i % 2) candidate += ' Buyer+tag@Vendor-Name.example second@other.example';
      const expected = candidate.match(previous)?.[0]?.toLowerCase() ?? null;
      const result = await extractSender(inbound('Hello'), {
        llmExtract: async () => ({ reply_to: candidate }),
      });
      expect(result.originalReplyTo, candidate).toBe(expected);
    }
  });
});

describe('equivalent parsing boundaries', () => {
  it('bounds malformed HTML processing during readInbound before sender admission', async () => {
    const raw = `Content-Type: text/html\r\n\r\n${'<a '.repeat(32_000)}`;
    const start = performance.now();
    const result = await readInbound({ from: 'reporter@example.com', to: 'report@isitjunk.com', headers: new Headers(), raw });
    expect(result.rawTruncated).toBe(false);
    expect(result.contentText).toContain('<a');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('normalizes a malicious redirect hostname in linear time and never fetches it', async () => {
    const extracted: ExtractedSender = {
      originalFromEmail: 'bob@vendor.example', originalFromName: null,
      originalReplyTo: null, claimedCompany: null, isContactForm: false,
      submitterEmail: null, candidateDomains: ['vendor.example'], confidence: 'high', method: 'inline-headers',
    };
    const host = `a${'.'.repeat(60_000)}b.com`;
    const requested: string[] = [];
    const fetcher = async (input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(String(input));
      if (url.hostname === 'cloudflare-dns.com') return Response.json({ Status: 0, Answer: [] });
      if (url.hostname === 'rdap.org') return Response.json({ events: [] });
      requested.push(url.href);
      return new Response(null, { status: 302, headers: { location: `https://${host}/` } });
    };
    const start = performance.now();
    const [result] = await verifyDomains(extracted, { fetcher });
    expect(requested).toEqual(['https://vendor.example/']);
    expect(result.website.status).toBe('unchecked');
    expect(result.website.finalDomain).toBe(host);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('bounded dash-run forward markers', () => {
  // The previous unanchored /-{2,}\s*forwarded message\s*-{2,}/ scan retried
  // every suffix of a long dash run at every position: quadratic on dash-heavy
  // bodies. These fixtures previously took seconds; keep them under a second.
  it('scans a long dash-only body without any marker', async () => {
    const start = performance.now();
    const result = await extractSender(inbound('-'.repeat(64_000)));
    expect(result.method).toBe('none');
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('scans a long dash run after a matched marker without suffix retries', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(
      '---------- Forwarded message ---------\r\nFrom: person@vendor.example\r\n' + `${'-'.repeat(64_000)}\r\nSubject: Hello`,
    ));
    expect(result.method).toBe('inline-headers');
    expect(result.originalFromEmail).toBe('person@vendor.example');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('scans dashes followed by a long whitespace run in bounded time', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(`${'-'.repeat(32_000)}${' '.repeat(32_000)}`));
    expect(result.method).toBe('none');
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('keeps dash-marker matching and its precedence intact', async () => {
    // A later "begin forwarded message:" must not outrank an existing dashed
    // Forwarded message marker.
    const forwardedWins = await extractSender(inbound(
      '---- Forwarded message ----\r\nFrom: fwd@x.example\r\n\r\nbegin forwarded message:\r\nSubject: hi',
    ));
    expect(forwardedWins.method).toBe('inline-headers');
    expect(forwardedWins.originalFromEmail).toBe('fwd@x.example');

    // A dashed Original message marker must not outrank a dashed Forwarded
    // message marker when the forwarded block carries the From line.
    const dashedForwardWins = await extractSender(inbound(
      '---- Original message ----\r\nFrom: orig@x.example\r\n\r\n---- Forwarded message ----\r\nFrom: fwd@y.example',
    ));
    expect(dashedForwardWins.originalFromEmail).toBe('fwd@y.example');

    // The last marker of the same kind wins, and a marker without a From line
    // is not rescued by an earlier block.
    const lastMarker = await extractSender(inbound(
      '---- Original message ----\r\nFrom: first@x.example\r\n\r\n---- Original message ----\r\nSubject: hi',
    ));
    expect(lastMarker.method).toBe('none');

    // Trailing dash runs shared between two markers are consumed once; the
    // second occurrence must not start a new match inside the first match.
    const sharedRun = await extractSender(inbound(
      '---- Forwarded message ------ Forwarded message ----\r\nFrom: fwd@x.example',
    ));
    expect(sharedRun.originalFromEmail).toBe('fwd@x.example');

    // Single dashes, missing dash runs and missing separators never match.
    for (const body of ['- Forwarded message -', 'Forwarded message', '- Forwarded message -- x']) {
      const result = await extractSender(inbound(`${body}\r\nFrom: fwd@x.example`));
      expect(result.method, body).toBe('none');
    }
    const minimal = await extractSender(inbound('-- Forwarded message --\r\nFrom: fwd@x.example'));
    expect(minimal.originalFromEmail).toBe('fwd@x.example');
  });
});

describe('bounded multiline field extraction', () => {
  it('keeps the existing multiline field syntax', async () => {
    const result = await extractSender(inbound('Email\n:\nbuyer@vendor.example\nCompany: Vendor'));
    expect(result.method).toBe('contact-form');
    expect(result.submitterEmail).toBe('buyer@vendor.example');
    expect(result.claimedCompany).toBe('Vendor');
  });

  it('does not truncate or reinterpret field values', async () => {
    const email = `${'!'.repeat(300)}@vendor.example`;
    const result = await extractSender(inbound(`Email\n:\n${email}\nCompany: Vendor`));
    expect(result.submitterEmail).toBe(email);
    expect(result.claimedCompany).toBe('Vendor');
  });

  it('scans interior blank-line runs in bounded time', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(
      `Email: buyer@vendor.example\r\n${'\r\n'.repeat(16_000)}From: someone@vendor.example\r\nCompany: Vendor`,
    ));
    expect(result.method).toBe('contact-form');
    expect(result.submitterEmail).toBe('buyer@vendor.example');
    expect(result.candidateDomains).toEqual(['vendor.example']);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('scans blank-line runs when no label matches in bounded time', async () => {
    const start = performance.now();
    const result = await extractSender(inbound(`Hello\r\n${'\r\n'.repeat(16_000)}`));
    expect(result.method).toBe('none');
    expect(result.originalFromEmail).toBe('reporter@example.com');
    expect(performance.now() - start).toBeLessThan(1000);
  });

  // Differential oracle: the previous per-label multiline regex, used only on
  // short data, must agree with the bounded scan on the field outcome that
  // drives the contact-form path.
  function previousField(text: string, labels: string[]): string | null {
    for (const label of labels) {
      const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const match = new RegExp(`^\\s*${escaped}\\s*[:\\-]\\s*(.+)$`, 'im').exec(text);
      if (match) return match[1].replace(/\s+/g, ' ').trim();
    }
    return null;
  }
  const previousEmailRe = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/i;

  it('agrees with the previous multiline regex across generated contact-form texts', async () => {
    const atoms = ['Email', 'Company', 'Name', 'e-mail', 'Emails:', 'email -', ':', ': ', '-', '- ', ' ', '  ', '\t', '\n', '\n\n',
      'buyer@vendor.example', 'person@other.example', 'Vendor', 'x', '!', '@', '.', 'Email address'];
    let seed = 0x2b1f;
    for (let i = 0; i < 400; i++) {
      let candidate = 'Note: start\n';
      const count = 1 + (seed % 12);
      for (let j = 0; j < count; j++) {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        candidate += atoms[seed % atoms.length];
      }
      const body = `${candidate}\nNote: end`;
      const emailValue = previousField(body, ['email address', 'email', 'e-mail']);
      const expectedEmail = emailValue?.match(previousEmailRe)?.[0]?.toLowerCase() ?? null;
      const expectedCompany = previousField(body, ['company', 'organization', 'business']);
      const isForm = Boolean(expectedEmail && expectedCompany);
      const result = await extractSender(inbound(body));
      expect(result.method, body).toBe(isForm ? 'contact-form' : 'none');
      expect(result.submitterEmail, body).toEqual(isForm ? expectedEmail : null);
      expect(result.claimedCompany !== null, body).toBe(isForm);
    }
  });
});
