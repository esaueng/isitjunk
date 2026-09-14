/**
 * Original-sender extraction. This stage runs before classification so the LLM
 * receives a testable statement of who is under analysis and which domains may
 * be verified. Nothing extracted here is logged or persisted.
 */
import PostalMime, { addressParser } from 'postal-mime';
import type { Address, Email, Mailbox } from 'postal-mime';
import { getDomain } from 'tldts';
import type { ExtractedSender, InboundEmail, LlmExtractionResult } from './types';

interface ExtractOptions {
  llmExtract?: (input: string) => Promise<LlmExtractionResult | null>;
}

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

const EMAIL_RE = /[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/i;

export async function extractSender(email: InboundEmail, options: ExtractOptions = {}): Promise<ExtractedSender> {
  const base = await codeExtract(email);
  let result = normalizeExtraction(base, email);

  if (options.llmExtract && needsLlmExtraction(result)) {
    try {
      const llm = await options.llmExtract(await buildExtractionInput(email));
      if (llm) result = normalizeExtraction(mergeLlmExtraction(result, llm), email);
    } catch {
      // LLM extraction is enrichment only. Classification still proceeds with
      // deterministic extraction or no evidence.
    }
  }

  return result;
}

async function codeExtract(email: InboundEmail): Promise<PartialExtraction> {
  const parsed = await safeParse(email.raw);

  const rfc822 = parsed ? await innermostAttachedMessage(parsed) : null;
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

async function safeParse(raw: string): Promise<Email | null> {
  try {
    return await PostalMime.parse(raw, {
      rfc822Attachments: true,
      forceRfc822Attachments: true,
      attachmentEncoding: 'utf8',
      maxNestingDepth: 8,
    });
  } catch {
    return null;
  }
}

async function innermostAttachedMessage(parsed: Email, depth = 0): Promise<Email | null> {
  let found: Email | null = null;
  for (const attachment of parsed.attachments ?? []) {
    const looksRfc822 =
      attachment.mimeType?.toLowerCase() === 'message/rfc822' ||
      attachment.filename?.toLowerCase().endsWith('.eml') ||
      (typeof attachment.content === 'string' && /^from:/im.test(attachment.content));
    if (!looksRfc822) continue;

    const content = attachmentContentToString(attachment.content);
    if (!content) continue;
    const child = await safeParse(content);
    if (!child) continue;
    found = (await innermostAttachedMessage(child, depth + 1)) ?? child;
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
  if (!submitterEmail || !EMAIL_RE.test(submitterEmail)) return null;
  const email = submitterEmail.match(EMAIL_RE)?.[0] ?? null;
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
    lastIndexOfRegex(text, /-{2,}\s*forwarded message\s*-{2,}/gi) ??
    lastIndexOfRegex(text, /begin forwarded message:/gi) ??
    lastIndexOfRegex(text, /-{2,}\s*original message\s*-{2,}/gi);
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
    if (!EMAIL_RE.test(value)) {
      for (const next of lines.slice(i + 1, i + 4)) {
        const candidate = htmlToText(next).trim();
        if (EMAIL_RE.test(candidate)) {
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
  const email = value.match(EMAIL_RE)?.[0]?.toLowerCase();
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

async function buildExtractionInput(email: InboundEmail): Promise<string> {
  const parsed = await safeParse(email.raw);
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

function htmlToText(input: string): string {
  return input
    .replace(/<a\b[^>]*href=["']mailto:([^"']+)["'][^>]*>/gi, ' $1 ')
    .replace(/<([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z0-9.-]+)>/gi, ' $1 ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function field(text: string, labels: string[]): string | null {
  for (const label of labels) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const match = new RegExp(`^\\s*${escaped}\\s*[:\\-]\\s*(.+)$`, 'im').exec(text);
    if (match) return cleanField(match[1]);
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
  const email = stringValue(value)?.match(EMAIL_RE)?.[0]?.toLowerCase() ?? null;
  return email;
}

function emailDomain(value: string | null | undefined): string | null {
  const email = normalizeEmail(value);
  const host = email?.split('@')[1]?.toLowerCase();
  if (!host) return null;
  return registrableDomain(host);
}

function registrableDomain(host: string): string | null {
  const normalized = host.toLowerCase().replace(/\.+$/, '');
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

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean {
  return value === true || (typeof value === 'string' && ['true', 'yes', '1'].includes(value.toLowerCase()));
}
