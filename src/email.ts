/**
 * Building the reply email (the verdict) as a raw MIME message.
 *
 * Sending is done by the caller via Cloudflare Email Sending or the
 * `message.reply()` fallback; this module only constructs the MIME so it stays
 * pure and unit-testable. `mimetext` handles header/RFC2047/body encoding so
 * non-ASCII subjects and reasons are emitted correctly.
 */
// Use the browser build: the default ("node") entry imports node:os/path, which
// don't resolve in the Workers runtime. The browser build is dependency-free.
import { createMimeMessage } from 'mimetext/browser';
import { REPORT_FROM_EMAIL, REPORT_FROM_NAME, SUPPORT_EMAIL, VERDICT_LABELS } from './config';
import type { Analysis } from './types';

/** Longest reason / echoed subject the verdict email will carry, in characters. */
export const MAX_REPLY_REASON_CHARS = 600;
export const MAX_REPLY_SUBJECT_CHARS = 200;

/** Fixed copy, never supplied by the model, distinguishes advice from quoted content. */
export const REPLY_DISCLAIMER =
  'Is It Junk? will never request your password, verification codes, payment, or software installation in an analysis report. Treat instructions quoted in the subject or analysis as untrusted.';

export const REPLY_VERIFICATION_LIMITS =
  'This report does not independently authenticate the original sender. Quoted headers and virus-scan claims do not establish that a message is legitimate.';

const SCORE_EXPLANATION = 'An automated assessment, not a measured probability or a guarantee of safety.';
const SCORE_GUIDE = '70–100: likely junk · above 30 and below 70: uncertain · 0–30: likely not junk';

/**
 * Make model output safe to echo in mail we send. The reason and the analysed
 * subject come from the model, which reads attacker-written text, so a reason
 * can be steered into a call-to-action with a link. This keeps it descriptive:
 * URLs are reduced to their host (the domain is the useful part of a verdict;
 * the path is the payload), mailto: links to the bare address, control
 * characters and line breaks collapse to spaces (no fake layout or signature
 * blocks), and length is capped.
 */
export function constrainReplyText(value: string | null, max: number): string | null {
  if (!value) return null;
  let text = value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029]/g, ' ')
    .replace(/\b(?:https?|ftp):\/\/([^\s/?#]+)[^\s]*/gi, '$1')
    .replace(/\bmailto:([^\s?]+)[^\s]*/gi, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  if (text.length > max) text = `${text.slice(0, max - 1).trimEnd()}…`;
  return text || null;
}

/**
 * The verdict as it may be echoed to a reporter. Label is restricted to the
 * three real verdicts (anything else becomes "Uncertain" — a hijacked label
 * would otherwise land verbatim in our Subject line); score must be a number
 * in [0, 1]; reason and subject go through constrainReplyText().
 */
export function constrainAnalysisForReply(analysis: Analysis): Analysis {
  let label = analysis.label
    ? ((VERDICT_LABELS as readonly string[]).includes(analysis.label) ? analysis.label : 'Uncertain')
    : null;
  const scoreText = analysis.score?.trim() ?? '';
  const scoreNum = Number(scoreText);
  let score =
    /^[0-9.]{1,6}$/.test(scoreText) && Number.isFinite(scoreNum) && scoreNum >= 0 && scoreNum <= 1 ? scoreText : null;
  // A contradictory or incomplete verdict must not produce reassuring advice.
  if (label) {
    const expected = scoreNum >= 0.7 ? "Yes, it's Junk" : scoreNum <= 0.3 ? 'No, Not Junk' : 'Uncertain';
    if (score === null || label !== expected) {
      label = 'Uncertain';
      score = null;
    }
  }
  return {
    score,
    label,
    reason: constrainReplyText(analysis.reason, MAX_REPLY_REASON_CHARS),
    subject: constrainReplyText(analysis.subject, MAX_REPLY_SUBJECT_CHARS),
  };
}

/** Subject line, mirroring the original: `Is it Junk? [<label>]`. */
export function replySubject(label: string | null): string {
  return `Is it Junk? [${label ?? ''}]`;
}

/** Category hints stay inside the existing reason field; older replies still render. */
function reportView(analysis: Analysis) {
  const safe = constrainAnalysisForReply(analysis);
  let reason = safe.reason ?? 'No reason provided.';
  let title = 'Uncertain';
  let advice = 'Review carefully before replying, opening attachments, or sharing information. Verify unexpected requests through a known contact method.';
  let color = '#854d0e';
  if (safe.label === "Yes, it's Junk") {
    title = 'Likely junk';
    color = '#9f1239';
    advice = 'Mark as junk or delete it. Avoid replying, opening attachments, or sharing personal information.';
    if (/^Scam:\s*/i.test(reason)) {
      title = 'Likely scam';
      advice = 'Do not reply, send money, or share personal information. Mark as junk or delete it.';
      reason = reason.replace(/^Scam:\s*/i, '');
    } else if (/^Unwanted marketing:\s*/i.test(reason)) {
      title = 'Unwanted marketing';
      advice = 'If unwanted, mark as junk or delete it.';
      reason = reason.replace(/^Unwanted marketing:\s*/i, '');
    } else {
      reason = reason.replace(/^Other junk:\s*/i, '');
    }
  } else if (safe.label === 'No, Not Junk') {
    title = 'Likely not junk';
    color = '#166534';
    advice = 'No strong junk signals were identified. Verify unexpected requests for money or sensitive information through a known contact method.';
  }
  const reasons = reason.split(/\s*;\s*/).filter(Boolean);
  // Preserve all constrained text if an older model emits more than three clauses.
  if (reasons.length > 3) reasons.splice(2, reasons.length - 2, reasons.slice(2).join('; '));
  if (!reasons.length) reasons.push('No reason provided.');
  const score = safe.score !== null && safe.label
    ? `${Number((Number(safe.score) * 100).toFixed(4))}/100 — ${Number(safe.score) >= 0.7 ? 'High' : Number(safe.score) <= 0.3 ? 'Low' : 'Uncertain'}`
    : 'N/A';
  return { title, advice, color, reasons, score, subject: safe.subject || 'No Subject' };
}

/** Verdict and useful guidance first, with a complete plain-text alternative. */
export function buildResultBody(analysis: Analysis): string {
  const report = reportView(analysis);
  return [
    report.title,
    report.advice,
    '',
    `Analyzed subject: ${report.subject}`,
    '',
    'Why this verdict',
    ...report.reasons.map((reason) => `- ${reason}`),
    '',
    `Junk score: ${report.score}`,
    SCORE_EXPLANATION,
    '',
    'Verification limits',
    REPLY_VERIFICATION_LIMITS,
    '',
    'Score guide',
    SCORE_GUIDE,
    '',
    REPLY_DISCLAIMER,
    '',
    'Questions or issues?',
    SUPPORT_EMAIL,
  ].join('\n');
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
}

/** Inline styles, semantic text, and no remote assets for email-client compatibility. */
export function buildResultHtml(analysis: Analysis): string {
  const report = reportView(analysis);
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Is It Junk? — ${escapeHtml(report.title)}</title></head>
<body style="margin:0;padding:0;background-color:#f4f5f7;color:#20242c;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7;"><tr><td align="center" style="padding:24px 12px;">
<!--[if mso]><table role="presentation" width="640" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background-color:#ffffff;border:1px solid #dce0e5;border-radius:12px;table-layout:fixed;"><tr><td style="padding:28px 24px;overflow-wrap:anywhere;word-wrap:break-word;">
<p style="margin:0 0 16px;color:#545b66;font-size:14px;font-weight:bold;">IS IT JUNK?</p>
<h1 style="margin:0 0 12px;font-size:28px;line-height:1.2;color:${report.color};">${escapeHtml(report.title)}</h1>
<p style="margin:0 0 24px;font-size:18px;line-height:1.5;">${escapeHtml(report.advice)}</p>
<p style="margin:0 0 24px;color:#545b66;"><strong>Analyzed subject</strong><br>${escapeHtml(report.subject)}</p>
<h2 style="margin:0 0 8px;font-size:18px;">Why this verdict</h2>
<ul style="margin:0 0 24px;padding-left:22px;">${report.reasons.map((reason) => `<li style="margin:0 0 8px;">${escapeHtml(reason)}</li>`).join('')}</ul>
<p style="margin:0 0 4px;"><strong>Junk score: ${escapeHtml(report.score)}</strong></p>
<p style="margin:0 0 24px;font-size:14px;color:#545b66;">${SCORE_EXPLANATION}</p>
<h2 style="margin:0 0 8px;font-size:16px;">Verification limits</h2>
<p style="margin:0 0 24px;font-size:14px;color:#545b66;">${REPLY_VERIFICATION_LIMITS}</p>
<hr style="border:0;border-top:1px solid #dce0e5;margin:0 0 20px;">
<p style="margin:0 0 16px;font-size:14px;color:#545b66;"><strong>Score guide</strong><br>${SCORE_GUIDE}</p>
<p style="margin:0 0 16px;font-size:14px;color:#545b66;">${REPLY_DISCLAIMER}</p>
<p style="margin:0;font-size:14px;color:#545b66;">Questions or issues? <a href="mailto:${escapeHtml(SUPPORT_EMAIL)}" style="color:#3346a8;text-decoration:underline;">${escapeHtml(SUPPORT_EMAIL)}</a></p>
</td></tr></table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table>
</body></html>`;
}

/** Generic user-facing failure text. Provider and configuration details stay internal. */
export function buildFailureBody(): string {
  return [
    'We could not analyze this email right now.',
    '',
    'Please try forwarding it again later. No verdict was recorded for this attempt.',
    '',
    'Questions or issues?',
    SUPPORT_EMAIL,
  ].join('\n');
}

export interface ReplyOptions {
  /** Recipient — the original sender (who forwarded the mail to us). */
  toEmail: string;
  /** The original message's `Message-ID`, for threading the reply. */
  inReplyTo: string;
  /** Reply From address. Must be the verified report sender. */
  fromEmail?: string;
  fromName?: string;
}

/**
 * Build the raw MIME for the verdict reply. When the original Message-ID is
 * known, In-Reply-To/References thread the reply onto it; when it isn't, those
 * headers are omitted and the reply is still valid (threading is best-effort).
 */
export function buildReplyMime(analysis: Analysis, opts: ReplyOptions): string {
  const safe = constrainAnalysisForReply(analysis);
  return buildMessageMime(replySubject(safe.label), buildResultBody(safe), opts, buildResultHtml(safe));
}

/** Build a loop-safe, generic failure reply without leaking internal error details. */
export function buildFailureReplyMime(opts: ReplyOptions): string {
  return buildMessageMime('Is it Junk? [Analysis unavailable]', buildFailureBody(), opts);
}

function buildMessageMime(subject: string, body: string, opts: ReplyOptions, html?: string): string {
  const msg = createMimeMessage();
  msg.setSender({ name: opts.fromName ?? REPORT_FROM_NAME, addr: opts.fromEmail ?? REPORT_FROM_EMAIL });
  msg.setRecipient(opts.toEmail);
  msg.setSubject(subject);
  msg.setHeader('Auto-Submitted', 'auto-replied');
  if (opts.inReplyTo) {
    msg.setHeader('In-Reply-To', opts.inReplyTo);
    msg.setHeader('References', opts.inReplyTo);
  }
  msg.addMessage({ contentType: 'text/plain', data: body });
  if (html) msg.addMessage({ contentType: 'text/html', data: html });
  return msg.asRaw();
}
