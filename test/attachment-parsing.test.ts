import { afterEach, describe, expect, it, vi } from 'vitest';
import PostalMime from 'postal-mime';
import { extractSender } from '../src/extract';
import type { InboundEmail } from '../src/types';
import worker from '../src/index';
import { fakeD1, makeEnv } from './helpers';

function inbound(raw: string): InboundEmail {
  return {
    from: 'reporter@example.com', to: 'report@isitjunk.com', subject: 'Check this',
    messageId: '', authResults: '', autoSubmitted: '', precedence: '', autoResponseSuppress: '',
    raw, rawSize: raw.length, rawBytesRead: raw.length, rawTruncated: false,
  };
}

const LEAF = 'From: Leaf LLC <sender@vendor.example>\r\nReply-To: help@vendor.example\r\n\r\nHello';
const RFC822 = 'Content-Type: message/rfc822';
const EML = 'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="forward.EML"';
const FROM_TEXT = 'Content-Type: text/plain\r\nContent-Disposition: attachment; filename="notes.txt"';

function wrapper(children: string[], boundary: string, headers = RFC822, base64 = false): string {
  return [
    'From: Wrapper LLC <wrapper@wrapper.example>',
    `Content-Type: multipart/mixed; boundary="${boundary}"`, '',
    `--${boundary}`, 'Content-Type: text/plain', '', 'Please check the attached mail.',
    ...children.flatMap((child) => [
      `--${boundary}`, headers, ...(base64 ? ['Content-Transfer-Encoding: base64'] : []), '',
      base64 ? Buffer.from(child).toString('base64') : child,
    ]),
    `--${boundary}--`,
  ].join('\r\n');
}

function nested(levels: number, headers = RFC822): string {
  let raw = LEAF;
  for (let i = 0; i < levels; i++) raw = wrapper([raw], `level-${i}`, headers);
  return raw;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('attached-message parsing budget', () => {
  it.each([RFC822, EML, FROM_TEXT])('stops a nested attachment chain before a seventeenth parse (%s)', async (headers) => {
    const parse = vi.spyOn(PostalMime, 'parse');
    const raw = nested(16, headers);
    expect(raw.length).toBeLessThan(10_000);
    await expect(extractSender(inbound(raw))).rejects.toThrow('Attached-message parsing limit exceeded');
    expect(parse).toHaveBeenCalledTimes(16);
  });

  it('shares the budget across sibling branches and discards partial sender selection', async () => {
    const parse = vi.spyOn(PostalMime, 'parse');
    const raw = wrapper(Array.from({ length: 8 }, (_, i) => wrapper([LEAF], `sibling-${i}`)), 'outer');
    await expect(extractSender(inbound(raw))).rejects.toThrow('Attached-message parsing limit exceeded');
    expect(parse).toHaveBeenCalledTimes(16);
  });

  it('counts failed child parses without swallowing the budget error', async () => {
    const originalParse = PostalMime.parse.bind(PostalMime);
    const parse = vi.spyOn(PostalMime, 'parse').mockImplementation(async (raw, options) => {
      if (typeof raw === 'string' && raw.startsWith('From: Broken')) throw new Error('Malformed attachment');
      return originalParse(raw, options);
    });
    const broken = 'From: Broken <broken@vendor.example>\r\n\r\nBroken';
    await expect(extractSender(inbound(wrapper(Array(16).fill(broken), 'failures'))))
      .rejects.toThrow('Attached-message parsing limit exceeded');
    expect(parse).toHaveBeenCalledTimes(16);
  });

  it('keeps the innermost sender at the budget boundary and resets the budget per message', async () => {
    const parse = vi.spyOn(PostalMime, 'parse');
    for (let i = 0; i < 2; i++) {
      const result = await extractSender(inbound(nested(15)));
      expect(result).toMatchObject({
        originalFromEmail: 'sender@vendor.example', originalReplyTo: 'help@vendor.example',
        claimedCompany: 'Leaf LLC', method: 'rfc822-part', candidateDomains: ['vendor.example'],
      });
    }
    expect(parse).toHaveBeenCalledTimes(32);
  });

  it.each([RFC822, EML, FROM_TEXT])('keeps transfer-encoded forwarded mail within budget (%s)', async (headers) => {
    const raw = wrapper([nested(2)], 'encoded', headers, true);
    expect(await extractSender(inbound(raw))).toMatchObject({
      originalFromEmail: 'sender@vendor.example', method: 'rfc822-part',
    });
  });

  it.each(['uint8array', 'arraybuffer'])('applies the same budget to %s attachment content', async (representation) => {
    const originalParse = PostalMime.parse.bind(PostalMime);
    const parse = vi.spyOn(PostalMime, 'parse').mockImplementation(async (raw, options) => {
      const parsed = await originalParse(raw, options);
      for (const attachment of parsed.attachments) {
        if (typeof attachment.content !== 'string') continue;
        const bytes = new TextEncoder().encode(attachment.content);
        attachment.content = representation === 'uint8array' ? bytes : bytes.buffer as ArrayBuffer;
      }
      return parsed;
    });
    await expect(extractSender(inbound(nested(16, EML))))
      .rejects.toThrow('Attached-message parsing limit exceeded');
    expect(parse).toHaveBeenCalledTimes(16);
  });

  it('preserves last-successful-sibling selection and skips individual parser failures', async () => {
    const originalParse = PostalMime.parse.bind(PostalMime);
    vi.spyOn(PostalMime, 'parse').mockImplementation(async (raw, options) => {
      if (typeof raw === 'string' && raw.startsWith('From: Broken')) throw new Error('Malformed attachment');
      return originalParse(raw, options);
    });
    const last = 'From: Last LLC <last@last.example>\r\n\r\nHello';
    const raw = wrapper([nested(2), last, 'From: Broken\r\n\r\nBroken'], 'siblings');
    expect(await extractSender(inbound(raw))).toMatchObject({
      originalFromEmail: 'last@last.example', method: 'rfc822-part', candidateDomains: ['last.example'],
    });
  });

  it('preserves raw-header fallback after a top-level parser failure', async () => {
    vi.spyOn(PostalMime, 'parse').mockRejectedValue(new Error('Malformed MIME'));
    expect(await extractSender(inbound(LEAF))).toMatchObject({
      originalFromEmail: 'sender@vendor.example', originalReplyTo: 'help@vendor.example', method: 'none',
    });
  });

  it('continues classification without partial sender evidence after budget exhaustion', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const fetchMock = vi.fn(async () => Response.json({ choices: [{ message: {
      content: "0.9~Yes, it's Junk~Suspicious request~Prize",
    } }] }));
    vi.stubGlobal('fetch', fetchMock);
    const { db, peek, peekBudget } = fakeD1();
    const raw = nested(16, EML);
    const message = {
      from: 'reporter@example.com', to: 'report@isitjunk.com', raw, rawSize: raw.length,
      headers: new Headers({
        subject: 'Check this',
        'authentication-results': 'mx.cloudflare.net; spf=pass smtp.mailfrom=reporter@example.com; dmarc=pass',
      }),
      reply: vi.fn(), setReject: vi.fn(),
    };
    await worker.email!(message as never, makeEnv({ DB: db }));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
    const request = JSON.parse(String(init?.body)) as { messages: { role: string; content: string }[] };
    const input = request.messages.find((message) => message.role === 'user')?.content;
    expect(input).toBeDefined();
    expect(input).not.toContain('--- EXTRACTED SENDER');
    expect(input).not.toContain('--- DOMAIN VERIFICATION');
    expect(message.reply).toHaveBeenCalledTimes(1);
    expect(message.setReject).not.toHaveBeenCalled();
    expect(peek()).toMatchObject({ total_processed: 1, total_junk: 1 });
    expect(Object.values(peekBudget())).toEqual([1]);
  });

  it('reuses the root parse for optional enrichment when the budget is fully consumed', async () => {
    const parse = vi.spyOn(PostalMime, 'parse');
    const llmExtract = vi.fn(async () => ({ claimed_company: 'Vendor LLC' }));
    const raw = nested(15).replace('From: Leaf LLC', 'From: Sales');
    expect(await extractSender(inbound(raw), { llmExtract })).toMatchObject({
      originalFromEmail: 'sender@vendor.example', claimedCompany: 'Vendor LLC', method: 'rfc822-part',
    });
    expect(llmExtract).toHaveBeenCalledTimes(1);
    expect(parse).toHaveBeenCalledTimes(16);
  });

  it('does not invoke enrichment after an incomplete attachment traversal', async () => {
    const llmExtract = vi.fn(async () => ({ original_from_email: 'wrapper@wrapper.example' }));
    await expect(extractSender(inbound(nested(16)), { llmExtract }))
      .rejects.toThrow('Attached-message parsing limit exceeded');
    expect(llmExtract).not.toHaveBeenCalled();
  });
});
