import { describe, it, expect, vi } from 'vitest';
import { extractSender } from '../src/extract';
import type { InboundEmail } from '../src/types';

function inbound(raw: string, over: Partial<InboundEmail> = {}): InboundEmail {
  return {
    from: 'forwarder@gmail.com',
    to: 'report@isitjunk.com',
    subject: 'Fwd: suspicious',
    messageId: '<outer@example.com>',
    authResults: '',
    autoSubmitted: '',
    precedence: '',
    autoResponseSuppress: '',
    raw,
    rawSize: raw.length,
    rawBytesRead: raw.length,
    rawTruncated: false,
    ...over,
  };
}

describe('extractSender', () => {
  it('uses the innermost message/rfc822 attachment as the original sender', async () => {
    const raw = [
      'From: Forwarder <forwarder@gmail.com>',
      'To: report@isitjunk.com',
      'Subject: Fwd: suspicious',
      'Content-Type: multipart/mixed; boundary="b1"',
      '',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Please check this.',
      '--b1',
      'Content-Type: message/rfc822',
      '',
      'From: "Acme Corp" <bob@acme-corp-inc.net>',
      'Reply-To: Support <support@acme-corp-inc.net>',
      'To: forwarder@gmail.com',
      'Subject: Quote request',
      '',
      'Hello from Acme.',
      '--b1--',
    ].join('\r\n');

    const extracted = await extractSender(inbound(raw));

    expect(extracted).toMatchObject({
      originalFromEmail: 'bob@acme-corp-inc.net',
      originalFromName: 'Acme Corp',
      originalReplyTo: 'support@acme-corp-inc.net',
      claimedCompany: 'Acme Corp',
      confidence: 'high',
      method: 'rfc822-part',
    });
    expect(extracted.candidateDomains).toEqual(['acme-corp-inc.net']);
  });

  it('parses Gmail-style inline forwarded headers and excludes the forwarder domain', async () => {
    const raw = [
      'From: Forwarder <forwarder@gmail.com>',
      'To: report@isitjunk.com',
      'Subject: Fwd: invoice',
      '',
      '---------- Forwarded message ---------',
      'From: "Quenvorth, Inc" <bob@quenvvorthinc.net>',
      'Date: Tue, 7 Jul 2026 at 09:00',
      'Subject: Overdue invoice',
      'To: Forwarder <forwarder@gmail.com>',
      '',
      'Please pay today.',
    ].join('\n');

    const extracted = await extractSender(inbound(raw));

    expect(extracted.originalFromEmail).toBe('bob@quenvvorthinc.net');
    expect(extracted.claimedCompany).toBe('Quenvorth, Inc');
    expect(extracted.method).toBe('inline-headers');
    expect(extracted.candidateDomains).toEqual(['quenvvorthinc.net']);
  });

  it('treats contact-form submitter fields as the sender under analysis', async () => {
    const raw = [
      'From: Website Form <noreply@forms.example>',
      'To: report@isitjunk.com',
      'Subject: New contact form submission',
      '',
      'Name: Alice Buyer',
      'Email Address: alice@new-vendor.example',
      'Company: New Vendor LLC',
      'Message: We would like to sell you services.',
    ].join('\n');

    const extracted = await extractSender(inbound(raw, { from: 'noreply@forms.example' }));

    expect(extracted).toMatchObject({
      originalFromEmail: 'alice@new-vendor.example',
      submitterEmail: 'alice@new-vendor.example',
      claimedCompany: 'New Vendor LLC',
      isContactForm: true,
      confidence: 'high',
      method: 'contact-form',
    });
    expect(extracted.candidateDomains).toEqual(['new-vendor.example']);
  });

  it('lets LLM extraction fill gaps but not override a header-derived email address', async () => {
    const raw = [
      'From: Sales Team <sales@young-domain.test>',
      'To: report@isitjunk.com',
      'Subject: Partnership',
      '',
      'We can help your company grow.',
    ].join('\n');
    const llmExtract = vi.fn(async () => ({
      original_from_email: 'wrong@other.test',
      claimed_company: 'Young Domain LLC',
      reply_to: 'ceo@young-domain.test',
    }));

    const extracted = await extractSender(inbound(raw, { from: 'sales@young-domain.test' }), { llmExtract });

    expect(llmExtract).toHaveBeenCalledTimes(1);
    expect(extracted.originalFromEmail).toBe('sales@young-domain.test');
    expect(extracted.originalReplyTo).toBe('ceo@young-domain.test');
    expect(extracted.claimedCompany).toBe('Young Domain LLC');
    expect(extracted.candidateDomains).toEqual(['young-domain.test']);
  });
});
