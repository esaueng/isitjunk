import { describe, expect, it } from 'vitest';
import { extractSender } from '../src/extract';
import { shouldSkipUnauthenticatedSender } from '../src/payload';
import type { InboundEmail } from '../src/types';

function inbound(raw: string, authResults = ''): InboundEmail {
  return {
    from: 'reporter@example.com', to: 'report@isitjunk.com', subject: 'Check this',
    messageId: '', authResults, autoSubmitted: '', precedence: '', autoResponseSuppress: '',
    raw, rawSize: raw.length, rawBytesRead: raw.length, rawTruncated: false,
  };
}

describe('security boundaries', () => {
  it('rejects oversized company identity rather than feeding it to domain matching', async () => {
    const raw = `From: reporter@example.com\r\n\r\nEmail: sender@vendor.example\r\nCompany: ${'a'.repeat(300_000)}\r\nMessage: Hello`;
    const result = await extractSender(inbound(raw));
    expect(result.claimedCompany).toBeNull();
    expect(result.submitterEmail).toBe('sender@vendor.example');
  });

  it('also rejects oversized names and company claims from model enrichment', async () => {
    const result = await extractSender(inbound('From: sender@vendor.example\r\n\r\nHello'), {
      llmExtract: async () => ({ original_from_name: 'a'.repeat(20_000), claimed_company: 'b'.repeat(20_000) }),
    });
    expect(result.originalFromEmail).toBe('sender@vendor.example');
    expect(result.originalFromName).toBeNull();
    expect(result.claimedCompany).toBeNull();
  });

  it.each(['none', 'neutral', 'temperror', 'permerror'])('does not authorize a reply from SPF %s and an unrelated DMARC pass', (spf) => {
    expect(shouldSkipUnauthenticatedSender(inbound('', `mx.cloudflare.net; spf=${spf} smtp.mailfrom=reporter@example.com; dmarc=pass header.from=attacker.example`))).toBe(true);
  });

  it('does not borrow SPF authorization from a different envelope address', () => {
    expect(shouldSkipUnauthenticatedSender(inbound('', 'mx.cloudflare.net; spf=pass smtp.mailfrom=other@attacker.example; dmarc=pass'))).toBe(true);
  });
});

describe('authentication parser ambiguity', () => {
  const pass = 'mx.cloudflare.net; spf=pass smtp.mailfrom=reporter@example.com; dmarc=pass';
  it('permits the normal trusted, positively authenticated reporter', () => {
    expect(shouldSkipUnauthenticatedSender(inbound('', pass))).toBe(false);
  });
  // Cloudflare's published authentication-result example includes separate
  // HELO and MAIL FROM SPF evaluations: https://blog.cloudflare.com/email-routing-subdomains/
  it.each(['none', 'fail', 'pass'])('uses MAIL FROM SPF independently of the HELO SPF result %s', (helo) => {
    expect(shouldSkipUnauthenticatedSender(inbound('', `mx.cloudflare.net; spf=${helo} smtp.helo=smtp.example.com; spf=pass smtp.mailfrom=reporter@example.com; dmarc=pass`))).toBe(false);
  });
  it.each([
    '',
    'spf=pass smtp.mailfrom=reporter@example.com; dmarc=pass',
    `${pass}, mx.cloudflare.net; spf=fail smtp.mailfrom=reporter@example.com`,
    'mx.cloudflare.net; spf=pass smtp.mailfrom=reporter@example.com; spf=fail',
    'mx.cloudflare.net; spf=pass smtp.mailfrom=reporter@example.com; spf=fail smtp.mailfrom=reporter@example.com',
    'mx.cloudflare.net; spf=pass smtp.helo=smtp.example.com; spf=none smtp.mailfrom=reporter@example.com',
    `${pass}; dmarc=fail`,
    'mx.cloudflare.net; spf=pass smtp.mailfrom=reporter@example.com smtp.mailfrom=attacker@example.com',
    'mx.cloudflare.net; dkim=pass reason="x; spf=pass smtp.mailfrom=reporter@example.com"',
    'mx.cloudflare.net; spf=pass reason="smtp.mailfrom=reporter@example.com"',
    'mx.cloudflare.net; spf=pass reason="x smtp.mailfrom=reporter@example.com "',
    'mx.cloudflare.net; spf=pass (unclosed comment smtp.mailfrom=reporter@example.com',
    'attacker.example; spf=pass smtp.mailfrom=reporter@example.com',
  ])('fails closed for missing, forged or ambiguous evidence %#', (header) => {
    expect(shouldSkipUnauthenticatedSender(inbound('', header))).toBe(true);
  });
  it('handles nested comments and a quoted mailbox without borrowing comment content', () => {
    expect(shouldSkipUnauthenticatedSender(inbound('', 'mx.cloudflare.net; spf=pass (ok (nested; spf=fail), text) smtp.mailfrom="reporter@example.com"; dmarc=pass'))).toBe(false);
  });
});
