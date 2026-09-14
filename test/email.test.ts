import { describe, it, expect } from 'vitest';
import PostalMime from 'postal-mime';
import {
  buildFailureBody,
  buildFailureReplyMime,
  buildReplyMime,
  buildResultBody,
  buildResultHtml,
  constrainAnalysisForReply,
  constrainReplyText,
  MAX_REPLY_REASON_CHARS,
  REPLY_DISCLAIMER,
  REPLY_VERIFICATION_LIMITS,
  replySubject,
} from '../src/email';
import type { Analysis } from '../src/types';

/** Decode a header value that may be a single RFC2047 base64 encoded-word. */
function decodeHeaderValue(line: string): string {
  const value = line.replace(/^[^:]+:\s*/, '');
  const m = value.match(/=\?utf-8\?B\?(.+?)\?=/i);
  if (!m) return value;
  return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (c) => c.charCodeAt(0)));
}

function headerLine(mime: string, name: string): string {
  return mime.split(/\r?\n/).find((l) => l.toLowerCase().startsWith(`${name.toLowerCase()}:`)) ?? '';
}

const analysis: Analysis = {
  score: '0.91',
  label: "Yes, it's Junk",
  reason: 'Suspicious sender and phishing-style links',
  subject: 'Account Notice',
};

describe('replySubject', () => {
  it('formats as "Is it Junk? [label]"', () => {
    expect(replySubject("Yes, it's Junk")).toBe("Is it Junk? [Yes, it's Junk]");
  });
  it('uses empty brackets when the label is missing', () => {
    expect(replySubject(null)).toBe('Is it Junk? []');
  });
});

describe('buildResultBody', () => {
  it('leads with the verdict and advice, then evidence, score, and limitations', () => {
    const body = buildResultBody(analysis);
    expect(body.startsWith('Likely junk\nMark as junk or delete it.')).toBe(true);
    expect(body).toContain('Account Notice');
    expect(body).toContain('Suspicious sender and phishing-style links');
    expect(body).toContain('Junk score: 91/100 — High');
    expect(body).toContain('70–100: likely junk');
    expect(body).toContain('above 30 and below 70: uncertain');
    expect(body).toContain('0–30: likely not junk');
    expect(body).toContain('not a measured probability');
    expect(body).toContain(REPLY_VERIFICATION_LIMITS);
    expect(body.indexOf('Why this verdict')).toBeLessThan(body.indexOf('Junk score:'));
    expect(body.indexOf('Junk score:')).toBeLessThan(body.indexOf('Score guide'));
  });

  it('falls back gracefully for missing fields', () => {
    const body = buildResultBody({ score: null, label: null, reason: null, subject: null });
    expect(body).toContain('No Subject');
    expect(body).toContain('Uncertain');
    expect(body).toContain('No reason provided.');
    expect(body).toContain('N/A');
  });

  it.each([
    ['0', 'No, Not Junk', '0/100 — Low'],
    ['0.30', 'No, Not Junk', '30/100 — Low'],
    ['0.3001', 'Uncertain', '30.01/100 — Uncertain'],
    ['0.6999', 'Uncertain', '69.99/100 — Uncertain'],
    ['0.70', "Yes, it's Junk", '70/100 — High'],
    ['1', "Yes, it's Junk", '100/100 — High'],
  ])('preserves the classification boundary for score %s', (score, label, display) => {
    expect(buildResultBody({ ...analysis, score, label })).toContain(`Junk score: ${display}`);
  });

  it('distinguishes a scam from marketing without changing the classification label', () => {
    const scam = buildResultBody({ ...analysis, reason: 'Scam: Implausible $200 million offer; Unsupported authority claim; Resembles an advance-fee scam, but no fee is requested.' });
    expect(scam.startsWith('Likely scam\nDo not reply, send money, or share personal information.')).toBe(true);
    expect(scam).toContain('- Implausible $200 million offer\n- Unsupported authority claim\n- Resembles an advance-fee scam, but no fee is requested.');
    const marketing = buildResultBody({ ...analysis, reason: 'Unwanted marketing: Repetitive bulk promotion' });
    expect(marketing.startsWith('Unwanted marketing\nIf unwanted, mark as junk or delete it.')).toBe(true);
    expect(marketing).not.toContain('Likely scam');
    expect(buildResultBody({ ...analysis, reason: 'Other junk: Repeated irrelevant messages' })).toContain('Likely junk');
  });

  it('does not infer scam categories from negation or an unrelated label', () => {
    expect(buildResultBody({ ...analysis, reason: 'No evidence of a scam; Unwanted bulk email' })).toMatch(/^Likely junk/);
    const benign = buildResultBody({ ...analysis, score: '0.1', label: 'No, Not Junk', reason: 'Scam: quoted subject, not a category' });
    expect(benign).toMatch(/^Likely not junk/);
    expect(benign).not.toContain('Do not reply, send money');
    expect(benign).toContain('Verify unexpected requests');
  });

  it('keeps legacy domain punctuation and overflow clauses intact', () => {
    const body = buildResultBody({ ...analysis, reason: 'Sender example.com; First signal; Second signal; Third signal' });
    expect(body).toContain('- Sender example.com\n- First signal\n- Second signal; Third signal');
  });
});

describe('HTML and MIME report', () => {
  it('round-trips complete matching HTML and text alternatives with threading intact', async () => {
    const parsed = await PostalMime.parse(buildReplyMime(analysis, { toEmail: 'one@example.com', inReplyTo: '<original@example.com>' }));
    expect(parsed.text?.trim()).toBe(buildResultBody(analysis));
    expect(parsed.html?.trim()).toBe(buildResultHtml(analysis));
    expect(parsed.inReplyTo).toBe('<original@example.com>');
    expect(parsed.references).toBe('<original@example.com>');
    expect(parsed.attachments).toHaveLength(0);
    expect(parsed.html).toContain('<html lang="en">');
    expect(parsed.html).toContain('<h1');
    expect(parsed.html).toContain('max-width:640px');
    expect(parsed.html).not.toMatch(/<script\b|<img\b|<iframe\b|<link\b/i);
  });

  it('escapes model HTML and preserves reply constraints in both alternatives', async () => {
    const malicious = {
      ...analysis,
      subject: '<img src=x onerror=alert(1)> & "urgent"\r\nBcc: other@example.com',
      reason: 'Scam: <a href="https://evil.example/login?token=bad">click</a>; <script>alert(1)</script> & credential lure',
    };
    const parsed = await PostalMime.parse(buildReplyMime(malicious, { toEmail: 'one@example.com', inReplyTo: '' }));
    expect(parsed.html).not.toMatch(/<img\b|<script\b|<a href="https?:/i);
    expect(parsed.html).toContain('&lt;img');
    expect(parsed.html).toContain('&lt;script&gt;');
    expect(parsed.html).toContain('&amp;');
    expect(parsed.html?.match(/<a /g)).toHaveLength(1); // fixed support address only
    expect(parsed.headers.some((header) => header.key === 'bcc')).toBe(false);
    for (const body of [parsed.text, parsed.html]) {
      expect(body).not.toContain('https://evil.example/login');
      expect(body).toContain(REPLY_DISCLAIMER);
      expect(body).toContain(REPLY_VERIFICATION_LIMITS);
    }
  });

  it('handles Unicode and long unbroken subjects without losing the length cap', async () => {
    const input = { ...analysis, subject: '請求書 — ' + 'x'.repeat(400), reason: 'Scam: 疑わしい送信者; Unexpected payment request' };
    const parsed = await PostalMime.parse(buildReplyMime(input, { toEmail: 'one@example.com', inReplyTo: '' }));
    expect(parsed.text).toContain('請求書 — ');
    expect(parsed.html).toContain('疑わしい送信者');
    expect(parsed.text).not.toContain('x'.repeat(200));
    expect(parsed.html).toContain('overflow-wrap:anywhere');
  });
});

describe('buildReplyMime', () => {
  it('produces a threaded MIME message with the right headers and body', () => {
    const mime = buildReplyMime(analysis, {
      toEmail: 'one@example.com',
      inReplyTo: '<abc123@mail.example.com>',
    });
    expect(mime).toMatch(/^From: .*report@isitjunk\.com/m);
    expect(mime).toMatch(/^To: .*one@example\.com/m);
    expect(mime).toMatch(/^Auto-Submitted: auto-replied/m);
    expect(decodeHeaderValue(headerLine(mime, 'Subject'))).toBe("Is it Junk? [Yes, it's Junk]");
    expect(mime).toMatch(/^In-Reply-To: <abc123@mail\.example\.com>/m);
    expect(mime).toMatch(/^References: <abc123@mail\.example\.com>/m);
    expect(mime).toMatch(/Content-Type: text\/plain/i);
  });

  it('omits threading headers when no Message-ID is available', () => {
    const mime = buildReplyMime(analysis, { toEmail: 'one@example.com', inReplyTo: '' });
    expect(mime).not.toMatch(/^In-Reply-To:/m);
  });

  it('honors an overridden From address', () => {
    const mime = buildReplyMime(analysis, {
      toEmail: 'one@example.com',
      inReplyTo: '<m@x>',
      fromEmail: 'report@isitjunk.com',
      fromName: 'Is It Junk?',
    });
    expect(mime).toMatch(/^From: .*report@isitjunk\.com/m);
  });
});

describe('failure reply', () => {
  it('is generic, threaded, and marked as an automatic response', () => {
    const body = buildFailureBody();
    expect(body).toContain('could not analyze this email');
    expect(body).not.toMatch(/OpenRouter|API|token|provider/i);

    const mime = buildFailureReplyMime({ toEmail: 'one@example.com', inReplyTo: '<m@x>' });
    expect(decodeHeaderValue(headerLine(mime, 'Subject'))).toBe('Is it Junk? [Analysis unavailable]');
    expect(mime).toMatch(/^Auto-Submitted: auto-replied/m);
    expect(mime).toMatch(/^In-Reply-To: <m@x>/m);
  });
});

describe('constrainReplyText', () => {
  it('reduces URLs to their host and mailto links to the address', () => {
    expect(constrainReplyText('Confirm at https://evil.example/login?x=1 now', 600)).toBe('Confirm at evil.example now');
    expect(constrainReplyText('see HTTP://Evil.Example/a/b and ftp://files.example/x', 600)).toBe('see Evil.Example and files.example');
    expect(constrainReplyText('write to mailto:ceo@evil.example?subject=hi', 600)).toBe('write to ceo@evil.example');
  });

  it('keeps bare domains, which a verdict legitimately names', () => {
    expect(constrainReplyText('Sender domain is a look-alike of dhl.com', 600)).toBe('Sender domain is a look-alike of dhl.com');
  });

  it('collapses line breaks and control characters so the reason cannot fake layout', () => {
    expect(constrainReplyText('Line one\r\n\r\nRegards,\nThe Team\u0007\u0000\u2028', 600)).toBe('Line one Regards, The Team');
  });

  it('caps length with an ellipsis and returns null for empty input', () => {
    const long = 'x'.repeat(MAX_REPLY_REASON_CHARS + 50);
    const out = constrainReplyText(long, MAX_REPLY_REASON_CHARS)!;
    expect(out.length).toBe(MAX_REPLY_REASON_CHARS);
    expect(out.endsWith('…')).toBe(true);
    expect(constrainReplyText('', 600)).toBeNull();
    expect(constrainReplyText('   ', 600)).toBeNull();
    expect(constrainReplyText(null, 600)).toBeNull();
  });
});

describe('constrainAnalysisForReply', () => {
  it('only lets the three real verdicts through as the label', () => {
    expect(constrainAnalysisForReply({ score: '0.9', label: "Yes, it's Junk", reason: null, subject: null }).label).toBe("Yes, it's Junk");
    expect(constrainAnalysisForReply({ score: '0.1', label: 'No, Not Junk', reason: null, subject: null }).label).toBe('No, Not Junk');
    expect(constrainAnalysisForReply({ score: '0.5', label: 'Uncertain', reason: null, subject: null }).label).toBe('Uncertain');
    expect(
      constrainAnalysisForReply({ score: '0.1', label: 'No, Not Junk] URGENT: click https://evil.example', reason: null, subject: null }).label,
    ).toBe('Uncertain');
    expect(constrainAnalysisForReply({ score: null, label: null, reason: null, subject: null }).label).toBeNull();
  });

  it('accepts only a numeric score in [0, 1]', () => {
    for (const ok of ['0', '0.95', '1', '1.0', '.5']) {
      expect(constrainAnalysisForReply({ score: ok, label: null, reason: null, subject: null }).score).toBe(ok);
    }
    for (const bad of ['1.5', '-0.1', '0.95 (click here)', 'high', '']) {
      expect(constrainAnalysisForReply({ score: bad, label: null, reason: null, subject: null }).score).toBeNull();
    }
  });

  it.each([
    { score: '0.98', label: 'No, Not Junk' },
    { score: '0.1', label: "Yes, it's Junk" },
    { score: '0.9', label: 'Uncertain' },
    { score: 'invalid', label: 'No, Not Junk' },
    { score: null, label: "Yes, it's Junk" },
  ])('does not send reassuring or contradictory advice for $score / $label', (fields) => {
    const input = { ...analysis, ...fields };
    expect(constrainAnalysisForReply(input)).toMatchObject({ score: null, label: 'Uncertain' });
    const body = buildResultBody(input);
    expect(body).toMatch(/^Uncertain\nReview carefully/);
    expect(body).toContain('Junk score: N/A');
    expect(body).not.toContain('No strong junk signals');
    expect(decodeHeaderValue(headerLine(buildReplyMime(input, { toEmail: 'one@example.com', inReplyTo: '' }), 'Subject'))).toBe('Is it Junk? [Uncertain]');
  });
});

describe('buildReplyMime applies the reply constraints', () => {
  const hijacked = {
    score: '0.10',
    label: 'No, Not Junk',
    reason: 'URGENT: Your mailbox will be suspended in 24h. Confirm your password at https://evil.example/login now.',
    subject: 'Account Notice\r\nX-Fake: header',
  };

  it('strips the link path and line breaks from the echoed reason and subject', () => {
    const raw = buildReplyMime(hijacked, { toEmail: 'u@example.com', inReplyTo: '<m@example.com>' });
    expect(raw).not.toContain('https://evil.example/login');
    expect(raw).toContain('Confirm your password at evil.example now.');
    expect(raw).not.toMatch(/^X-Fake:/m);
  });

  it('carries the fixed disclaimer in every verdict', () => {
    const raw = buildReplyMime(hijacked, { toEmail: 'u@example.com', inReplyTo: '<m@example.com>' });
    expect(raw).toContain(REPLY_DISCLAIMER);
    expect(buildResultBody(hijacked)).toContain(REPLY_DISCLAIMER);
  });
});
