/**
 * Original-sender extraction. This stage runs before classification so the LLM
 * receives a testable statement of who is under analysis and which domains may
 * be verified. Nothing extracted here is logged or persisted.
 */
import PostalMime, { addressParser } from 'postal-mime';
import type { Address, Email, Mailbox } from 'postal-mime';
import { getDomain } from 'tldts';
import type { ExtractedSender, InboundEmail, LlmExtractionResult } from './types';
import { stripHtmlTags, stripTrailingDots } from './util';

interface ExtractOptions {
  llmExtract?: (input: string) => Promise<LlmExtractionResult | null>;
}

// One extraction may traverse several attached messages. A per-parse MIME
// depth limit alone does not bound reparsing across attachments or siblings.
const MAX_MESSAGE_PARSES = 16;
type ParseBudget = { remaining: number };

type PartialExtraction = Omit<ExtractedSender, 'candidateDomains'> & { candidateDomains?: string[] };

const GENERIC_NAMES = new Set([
  'admin',
  'contact',
  'hello',
  'info',
  'mail',
  'marketing',
  'no reply',
  'noreply',
  'sales',
  'sales team',
  'support',
  'team',
  'website form',
]);

const EMAIL_LOCAL_CHAR_RE = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]/i;
const EMAIL_DOMAIN_RE = /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/iy;

/** Preserve first-substring matching without retrying every suffix of a local part. */
function findEmail(value: string): string | null {
  let localStart = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    if (char === '@' && i > localStart) {
      // A sticky domain match cannot search the rest of the field after a bad @.
      EMAIL_DOMAIN_RE.lastIndex = i + 1;
      if (EMAIL_DOMAIN_RE.test(value)) return value.slice(localStart, EMAIL_DOMAIN_RE.lastIndex);
    }
    if (!EMAIL_LOCAL_CHAR_RE.test(char)) localStart = i + 1;
  }
  return null;
}

export async function extractSender(email: InboundEmail, options: ExtractOptions = {}): Promise<ExtractedSender> {
  const budget = { remaining: MAX_MESSAGE_PARSES };
  const parsed = await safeParse(email.raw, budget);
  const base = await codeExtract(email, parsed, budget);
  let result = normalizeExtraction(base, email);

  if (options.llmExtract && needsLlmExtraction(result)) {
    try {
      const llm = await options.llmExtract(buildExtractionInput(email, parsed));
      if (llm) result = normalizeExtraction(mergeLlmExtraction(result, llm), email);
    } catch {
      // LLM extraction is enrichment only. Classification still proceeds with
      // deterministic extraction or no evidence.
    }
  }

  return result;
}

async function codeExtract(email: InboundEmail, parsed: Email | null, budget: ParseBudget): Promise<PartialExtraction> {
  const rfc822 = parsed ? await innermostAttachedMessage(parsed, budget) : null;
  if (rfc822) {
    const from = mailboxFromAddress(rfc822.from);
    const replyTo = firstMailbox(rfc822.replyTo);
    return {
      originalFromEmail: from?.address ?? null,
      originalFromName: from?.name || null,
      originalReplyTo: replyTo?.address ?? null,
      claimedCompany: companyFromName(from?.name),
      isContactForm: false,
      submitterEmail: null,
      confidence: 'high',
      method: 'rfc822-part',
    };
  }

  const bodyText = parsed ? messageSearchText(parsed, email.raw) : rawBody(email.raw);
  const contactForm = extractContactForm(bodyText);
  if (contactForm) return contactForm;

  const inline = extractInlineForward(bodyText);
  if (inline) return inline;

  const from = parsed ? mailboxFromAddress(parsed.from) : parseAddressHeader(headerValue(email.raw, 'from'));
  const replyTo = parsed ? firstMailbox(parsed.replyTo) : parseAddressHeader(headerValue(email.raw, 'reply-to'));
  const directEmail = from?.address || email.from || null;
  const directName = from?.name || null;
  return {
    originalFromEmail: directEmail,
    originalFromName: directName,
    originalReplyTo: replyTo?.address ?? null,
    claimedCompany: companyFromName(directName),
    isContactForm: false,
    submitterEmail: null,
    confidence: directEmail ? 'medium' : 'low',
    method: 'none',
  };
}

async function safeParse(raw: string | ArrayBuffer | Uint8Array, budget: ParseBudget): Promise<Email | null> {
  // Exhaustion aborts the entire extraction, rather than selecting a partially
  // traversed wrapper or sibling as the original sender. Parser failures still
  // use the existing fallback, but consume an attempt too.
  if (budget.remaining === 0) throw new Error('Attached-message parsing limit exceeded');
  budget.remaining--;
  try {
    return await PostalMime.parse(attachmentContentToString(raw), {
      rfc822Attachments: true,
      forceRfc822Attachments: true,
      attachmentEncoding: 'utf8',
      maxNestingDepth: 8,
    });
  } catch {
    return null;
  }
}

async function innermostAttachedMessage(parsed: Email, budget: ParseBudget, depth = 0): Promise<Email | null> {
  let found: Email | null = null;
  for (const attachment of parsed.attachments ?? []) {
    const looksRfc822 =
      attachment.mimeType?.toLowerCase() === 'message/rfc822' ||
      attachment.filename?.toLowerCase().endsWith('.eml') ||
      (typeof attachment.content === 'string' && /^from:/im.test(attachment.content));
    if (!looksRfc822) continue;

    const content = attachment.content;
    if (typeof content === 'string' ? !content : !content.byteLength) continue;
    const child = await safeParse(content, budget);
    if (!child) continue;
    found = (await innermostAttachedMessage(child, budget, depth + 1)) ?? child;
  }
  return depth > 0 ? found ?? parsed : found;
}

function attachmentContentToString(content: string | ArrayBuffer | Uint8Array): string {
  if (typeof content === 'string') return content;
  if (content instanceof Uint8Array) return new TextDecoder().decode(content);
  return new TextDecoder().decode(new Uint8Array(content));
}

function extractContactForm(text: string): PartialExtraction | null {
  const submitterEmail = field(text, ['email address', 'email', 'e-mail']);
  const company = field(text, ['company', 'organization', 'business']);
  const email = submitterEmail ? findEmail(submitterEmail) : null;
  if (!email || !company) return null;

  return {
    originalFromEmail: email,
    originalFromName: field(text, ['name', 'full name']),
    originalReplyTo: null,
    claimedCompany: cleanField(company),
    isContactForm: true,
    submitterEmail: email,
    confidence: 'high',
    method: 'contact-form',
  };
}

function extractInlineForward(text: string): PartialExtraction | null {
  const marker =
    lastDashKeywordIndex(text, 'forwarded message') ??
    lastIndexOfRegex(text, /begin forwarded message:/gi) ??
    lastDashKeywordIndex(text, 'original message');
  if (marker == null) return null;

  const block = text.slice(marker).split(/\r?\n/).slice(0, 80);
  const headers = parseForwardedHeaderBlock(block);
  const from = parseAddressHeader(headers.from ?? '');
  const replyTo = parseAddressHeader(headers.replyTo ?? '');
  if (!from?.address) return null;

  return {
    originalFromEmail: from.address,
    originalFromName: from.name || null,
    originalReplyTo: replyTo?.address ?? null,
    claimedCompany: companyFromName(from.name),
    isContactForm: false,
    submitterEmail: null,
    confidence: 'high',
    method: 'inline-headers',
  };
}

function parseForwardedHeaderBlock(lines: string[]): { from?: string; replyTo?: string } {
  const headers: { from?: string; replyTo?: string } = {};
  for (let i = 0; i < lines.length; i++) {
    const line = htmlToText(lines[i]).trim();
    const match = /^(from|von|de|reply-to|reply to|antwort an|répondre à)\s*:\s*(.+)$/i.exec(line);
    if (!match) continue;
    const key = match[1].toLowerCase();
    let value = match[2].trim();
    if (!findEmail(value)) {
      for (const next of lines.slice(i + 1, i + 4)) {
        const candidate = htmlToText(next).trim();
        if (findEmail(candidate)) {
          value = `${value} ${candidate}`;
          break;
        }
      }
    }
    if (key === 'from' || key === 'von' || key === 'de') headers.from = value;
    else headers.replyTo = value;
  }
  return headers;
}

function parseAddressHeader(value: string): Mailbox | null {
  if (!value) return null;
  try {
    const parsed = addressParser(value, { flatten: true });
    const mailbox = firstMailbox(parsed);
    if (mailbox?.address) return { name: mailbox.name || '', address: mailbox.address.toLowerCase() };
  } catch {
    // Fall through to regex.
  }
  const email = findEmail(value)?.toLowerCase();
  if (!email) return null;
  const name = value
    .replace(email, '')
    .replace(/[<>"']/g, '')
    .trim();
  return { name, address: email };
}

function firstMailbox(addresses: Address[] | Address | undefined): Mailbox | null {
  if (!addresses) return null;
  const list = Array.isArray(addresses) ? addresses : [addresses];
  for (const item of list) {
    if ('address' in item && item.address) return { name: item.name || '', address: item.address.toLowerCase() };
    if ('group' in item) {
      const nested = firstMailbox(item.group);
      if (nested) return nested;
    }
  }
  return null;
}

function mailboxFromAddress(address: Address | undefined): Mailbox | null {
  return firstMailbox(address);
}

function mergeLlmExtraction(current: ExtractedSender, llm: LlmExtractionResult): PartialExtraction {
  const llmEmail = stringValue(llm.original_from_email ?? llm.originalFromEmail);
  const llmName = stringValue(llm.original_from_name ?? llm.originalFromName);
  const llmReplyTo = stringValue(llm.reply_to ?? llm.originalReplyTo);
  const llmCompany = stringValue(llm.claimed_company ?? llm.claimedCompany);
  const llmSubmitter = stringValue(llm.submitter_email ?? llm.submitterEmail);
  const isContactForm = booleanValue(llm.is_contact_form ?? llm.isContactForm);

  return {
    ...current,
    originalFromEmail: current.originalFromEmail || normalizeEmail(llmEmail),
    originalFromName: current.originalFromName || llmName,
    originalReplyTo: current.originalReplyTo || normalizeEmail(llmReplyTo),
    claimedCompany: current.claimedCompany || llmCompany,
    isContactForm: current.isContactForm || isContactForm,
    submitterEmail: current.submitterEmail || normalizeEmail(llmSubmitter),
    confidence: current.confidence === 'low' ? 'medium' : current.confidence,
    method: current.method === 'none' && llmEmail ? 'llm' : current.method,
  };
}

function normalizeExtraction(extraction: PartialExtraction, inbound: InboundEmail): ExtractedSender {
  const originalFromEmail = normalizeEmail(extraction.originalFromEmail);
  const originalReplyTo = normalizeEmail(extraction.originalReplyTo);
  const submitterEmail = normalizeEmail(extraction.submitterEmail);
  return {
    originalFromEmail,
    originalFromName: cleanNullable(extraction.originalFromName),
    originalReplyTo,
    claimedCompany: cleanNullable(extraction.claimedCompany),
    isContactForm: Boolean(extraction.isContactForm),
    submitterEmail,
    confidence: extraction.confidence,
    method: extraction.method,
    candidateDomains: candidateDomains(
      { ...extraction, originalFromEmail, originalReplyTo, submitterEmail },
      inbound,
    ),
  };
}

function candidateDomains(extraction: PartialExtraction, inbound: InboundEmail): string[] {
  const excluded = new Set<string>();
  const toDomain = emailDomain(inbound.to);
  if (toDomain) excluded.add(toDomain);
  if (extraction.method !== 'none') {
    const forwarderDomain = emailDomain(inbound.from);
    const originalDomain = emailDomain(extraction.originalFromEmail);
    const submitterDomain = emailDomain(extraction.submitterEmail);
    if (forwarderDomain && forwarderDomain !== originalDomain && forwarderDomain !== submitterDomain) {
      excluded.add(forwarderDomain);
    }
  }

  const candidates = [
    emailDomain(extraction.originalFromEmail),
    emailDomain(extraction.originalReplyTo),
    extraction.isContactForm ? emailDomain(extraction.submitterEmail) : null,
    ...(extraction.candidateDomains ?? []),
  ];
  const out: string[] = [];
  for (const domain of candidates) {
    if (!domain || excluded.has(domain) || out.includes(domain)) continue;
    out.push(domain);
  }
  return out;
}

function needsLlmExtraction(result: ExtractedSender): boolean {
  return result.confidence === 'low' || Boolean(result.originalFromEmail && !result.claimedCompany);
}

function buildExtractionInput(email: InboundEmail, parsed: Email | null): string {
  const headers = [
    `Envelope-From: ${email.from}`,
    `Envelope-To: ${email.to}`,
    `Subject: ${email.subject}`,
    `Authentication-Results: ${email.authResults}`,
  ];
  const body = parsed ? textFromParsed(parsed, email.raw) : email.raw;
  const text = `${headers.join('\n')}\n\n${body}`;
  return text.length > 20_000 ? `${text.slice(0, 20_000)}\n\n[... truncated for extraction ...]` : text;
}

function messageSearchText(parsed: Email, raw: string): string {
  const body = rawBody(raw);
  return [textFromParsed(parsed, raw), body, htmlToText(body)]
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part, idx, all) => all.indexOf(part) === idx)
    .join('\n');
}

function textFromParsed(parsed: Email, raw: string): string {
  const text = parsed.text?.trim() || htmlToText(parsed.html ?? '').trim();
  return text || rawBody(raw);
}

function rawBody(raw: string): string {
  const split = raw.split(/\r?\n\r?\n/);
  return split.length > 1 ? split.slice(1).join('\n\n') : raw;
}

function replaceMailtoLinks(input: string): string {
  const starts = /<a\b/gi;
  const parts: string[] = [];
  let offset = 0;
  let start: RegExpExecArray | null;
  while ((start = starts.exec(input))) {
    const end = input.indexOf('>', start.index + 2);
    if (end < 0) break;
    const tag = input.slice(start.index, end + 1);
    // Retain the previous last-mailto behavior and permit '<' in attributes.
    let address: string | null = null;
    for (const match of tag.matchAll(/href=["']mailto:([^"']+)["']/gi)) address = match[1];
    parts.push(input.slice(offset, start.index), address ? ` ${address} ` : tag);
    offset = end + 1;
    starts.lastIndex = offset;
  }
  parts.push(input.slice(offset));
  return parts.join('');
}

function htmlToText(input: string): string {
  const text = replaceMailtoLinks(input)
    .replace(/<([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9.-]+))>/gi, (tag, email: string, domain: string) =>
      domain.slice(1, -1).includes('.') ? ` ${email} ` : tag)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n');
  return stripHtmlTags(text)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    // &amp; is decoded last so it cannot manufacture a sequence that an
    // earlier replacement would then double-unescape (&amp;quot; stays literal).
    .replace(/&amp;/g, '&');
}

function field(text: string, labels: string[]): string | null {
  for (const label of labels) {
    const value = matchField(text, label);
    if (value !== null) return cleanField(value);
  }
  return null;
}

/**
 * Equivalent of `^\\s*${label}\\s*[:\\-]\\s*(.+)$` with the `im` flags,
 * evaluated in linear time. The multiline leading `\s*` rescans interior
 * blank-line runs at every line start (quadratic on blank-line-heavy bodies),
 * so each label occurrence is visited directly instead. The capture stays the
 * exact rest of the matched line — including the engine's backtrack rule when
 * the whitespace run after the separator reaches the end of the text — so
 * fields are never truncated or reinterpreted.
 */
function matchField(text: string, label: string): string | null {
  const re = new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  for (const match of text.matchAll(re)) {
    const at = match.index ?? 0;
    // `^` plus `\\s*`: only whitespace that contains a line start may precede
    // the label, and the label must begin where that whitespace run ends.
    let start = at;
    let atLineStart = start === 0;
    while (start > 0 && isSpaceCode(text.charCodeAt(start - 1))) {
      start--;
      if (!atLineStart && isLineTerminatorCode(text.charCodeAt(start))) atLineStart = true;
    }
    if (!atLineStart) continue;
    // `\\s*[:\\-]`: the first non-whitespace after the label must be the
    // separator.
    const separator = at + label.length;
    let cursor = separator;
    while (cursor < text.length && isSpaceCode(text.charCodeAt(cursor))) cursor++;
    const code = text.charCodeAt(cursor);
    if (code !== 58 && code !== 45) continue;
    // `\\s*(.+)$`: the capture starts at the last position the engine's
    // greedy whitespace skip could backtrack to with a non-terminator there,
    // and runs to the end of that line. If the whitespace run reaches the end
    // of the text, the skip gives back one char at a time until a
    // non-terminator is found; the separator itself is never re-captured.
    let valueStart = cursor + 1;
    while (valueStart < text.length && isSpaceCode(text.charCodeAt(valueStart))) valueStart++;
    if (valueStart >= text.length) {
      let back = text.length - 1;
      while (back > cursor && isLineTerminatorCode(text.charCodeAt(back))) back--;
      if (back === cursor) continue;
      valueStart = back;
    }
    let lineEnd = valueStart;
    while (lineEnd < text.length && !isLineTerminatorCode(text.charCodeAt(lineEnd))) lineEnd++;
    return text.slice(valueStart, lineEnd);
  }
  return null;
}

function cleanField(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function cleanNullable(value: string | null | undefined): string | null {
  // Oversized identity claims are unknown, not a truncated claim about another company.
  if (value && value.length > 512) return null;
  const clean = value ? cleanField(value) : '';
  return clean || null;
}

function companyFromName(name: string | null | undefined): string | null {
  const clean = cleanNullable(name);
  if (!clean) return null;
  if (GENERIC_NAMES.has(clean.toLowerCase())) return null;
  if (/^(sales|support|info|contact|hello)\b/i.test(clean) && !/\b(inc|llc|ltd|corp|company|co\.?)\b/i.test(clean)) {
    return null;
  }
  return clean;
}

function normalizeEmail(value: string | null | undefined): string | null {
  const text = stringValue(value);
  return text ? findEmail(text)?.toLowerCase() ?? null : null;
}

function emailDomain(value: string | null | undefined): string | null {
  const email = normalizeEmail(value);
  const host = email?.split('@')[1]?.toLowerCase();
  if (!host) return null;
  return registrableDomain(host);
}

function registrableDomain(host: string): string | null {
  const normalized = stripTrailingDots(host.toLowerCase());
  return getDomain(normalized, { allowPrivateDomains: true }) ?? (normalized.includes('.') ? normalized : null);
}

function headerValue(raw: string, header: string): string {
  const match = new RegExp(`^${header}:\\s*(.+)$`, 'im').exec(raw);
  return match?.[1]?.trim() ?? '';
}

function lastIndexOfRegex(text: string, re: RegExp): number | null {
  let last: number | null = null;
  for (const match of text.matchAll(re)) last = match.index ?? last;
  return last;
}

function isSpaceCode(code: number): boolean {
  return (
    code === 32 ||
    (code >= 9 && code <= 13) ||
    code === 160 ||
    code === 5760 ||
    (code >= 8192 && code <= 8202) ||
    code === 8232 ||
    code === 8233 ||
    code === 8239 ||
    code === 8287 ||
    code === 12288 ||
    code === 65279
  );
}

function isLineTerminatorCode(code: number): boolean {
  return code === 10 || code === 13 || code === 8232 || code === 8233;
}

/**
 * Last index where /-{2,}<keyword>\s*... with dashes on both sides matches —
 * i.e. `-{2,}\\s*${keyword}\\s*-{2,}` with the `i` flag. The unanchored dash
 * pattern is quadratic under matchAll on long dash-only bodies (every suffix
 * of a dash run is retried), so the keyword occurrences are visited directly
 * and the dash sides are checked by walking the two adjacent runs. Match
 * order mirrors the regex engine: after a match, its trailing dash run is
 * consumed, and a leading run that starts inside an already-consumed span
 * cannot start a new match.
 */
function lastDashKeywordIndex(text: string, keyword: string): number | null {
  const re = new RegExp(keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  let from = 0;
  let last: number | null = null;
  for (const match of text.matchAll(re)) {
    const at = match.index ?? 0;
    if (at < from) continue;
    // Leading side: whitespace, then a run of at least two dashes ending at
    // the keyword. Both walks stop at `from` — an earlier match span cannot
    // supply dashes for a later one.
    let start = at;
    while (start > from && isSpaceCode(text.charCodeAt(start - 1))) start--;
    let dashes = 0;
    while (start > from && text.charCodeAt(start - 1) === 45) {
      start--;
      dashes++;
    }
    if (dashes < 2) continue;
    // Trailing side: whitespace, then at least two dashes.
    let end = at + keyword.length;
    while (end < text.length && isSpaceCode(text.charCodeAt(end))) end++;
    let trail = 0;
    while (end < text.length && text.charCodeAt(end) === 45) {
      end++;
      trail++;
    }
    if (trail < 2) continue;
    last = start;
    from = end;
  }
  return last;
}

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean {
  return value === true || (typeof value === 'string' && ['true', 'yes', '1'].includes(value.toLowerCase()));
}
