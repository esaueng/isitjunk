/**
 * Domain verification: DNS-over-HTTPS, root website probe, RDAP age, and local
 * domain lists. All failures degrade to partial evidence; no verifier error
 * should prevent classification or a reply.
 */
import { getDomain, getDomainWithoutSuffix } from 'tldts';
import { DISPOSABLE_DOMAINS, FREEMAIL_DOMAINS, RDAP_BOOTSTRAP, TOP_BRAND_DOMAINS } from './domain-data';
import type { DomainEvidence, DomainRole, ExtractedSender } from './types';

interface VerifyOptions {
  timeoutMs?: number;
  maxDomains?: number;
  now?: Date;
  fetcher?: typeof fetch;
}

type DohAnswer = { data?: string; type?: number };
type DohResponse = { Status?: number; Answer?: DohAnswer[] };
type CheckOptions = Required<Pick<VerifyOptions, 'timeoutMs' | 'now' | 'fetcher'>> & { signal: AbortSignal };
type DnsResult = { dns: DomainEvidence['dns']; nxdomain: boolean; complete: boolean };
type WebsiteResult = { website: DomainEvidence['website']; complete: boolean };
type RdapResult = { registration: DomainEvidence['registration']; complete: boolean };

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_DOMAINS = 3;
const PREVIEW_BYTES = 64_000;

export async function verifyDomains(extracted: ExtractedSender, options: VerifyOptions = {}): Promise<DomainEvidence[]> {
  const maxDomains = options.maxDomains ?? DEFAULT_MAX_DOMAINS;
  const domains = extracted.candidateDomains.slice(0, maxDomains);
  const fetcher = options.fetcher ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = options.now ?? new Date();

  const roles = domainRoles(extracted);
  const checks = domains.map((domain) =>
    verifyDomain(domain, roles.get(domain) ?? 'original-from', extracted, {
      fetcher,
      timeoutMs,
      now,
    }),
  );
  return Promise.all(checks);
}

async function verifyDomain(
  domain: string,
  role: DomainRole,
  extracted: ExtractedSender,
  options: Required<Pick<VerifyOptions, 'timeoutMs' | 'now' | 'fetcher'>>,
): Promise<DomainEvidence> {
  const base = emptyEvidence(domain, role);
  const freemail = FREEMAIL_DOMAINS.has(domain);
  const disposable = DISPOSABLE_DOMAINS.has(domain);
  if (freemail) return { ...base, freemail, disposable, checkedAt: 'skipped' };
  const checkOptions: CheckOptions = { ...options, signal: timeoutSignal(options.timeoutMs) };

  const [dnsResult, websiteResult, rdapResult] = await Promise.allSettled([
    checkDns(domain, checkOptions),
    checkWebsite(domain, checkOptions),
    checkRdap(domain, checkOptions),
  ]);

  const dns = dnsResult.status === 'fulfilled' ? dnsResult.value : null;
  const website = websiteResult.status === 'fulfilled' ? websiteResult.value : null;
  const rdap = rdapResult.status === 'fulfilled' ? rdapResult.value : null;
  const dnsNxdomain = dns?.nxdomain === true;

  const evidence: DomainEvidence = {
    ...base,
    dns: dns?.dns ?? base.dns,
    website: dnsNxdomain ? nxdomainWebsite() : website?.website ?? base.website,
    registration: neutralizeRdap404WithoutNxdomain(rdap?.registration ?? null, dnsNxdomain) ?? base.registration,
    freemail,
    disposable,
    lookalikeOf: lookalikeOf(domain, extracted.claimedCompany),
    checkedAt: dns?.complete && (dnsNxdomain || website?.complete) && rdap?.complete ? 'complete' : 'partial',
  };

  if (dnsNxdomain && evidence.registration.unregistered) evidence.checkedAt = 'complete';
  return evidence;
}

function neutralizeRdap404WithoutNxdomain(
  registration: DomainEvidence['registration'] | null,
  dnsNxdomain: boolean,
): DomainEvidence['registration'] | null {
  if (!registration) return null;
  if (registration.unregistered && !dnsNxdomain) return { ...registration, unregistered: false };
  return registration;
}

function emptyEvidence(domain: string, role: DomainRole): DomainEvidence {
  return {
    domain,
    role,
    dns: { resolves: null, hasMx: null, hasSpf: null, dmarcPolicy: null },
    website: {
      status: 'unchecked',
      httpStatus: null,
      finalDomain: null,
      title: null,
      bodyBytes: null,
      redirectedToUnrelatedDomain: false,
    },
    registration: { ageDays: null, registrar: null, unregistered: false, statuses: [] },
    freemail: false,
    disposable: false,
    lookalikeOf: null,
    checkedAt: 'partial',
  };
}

function nxdomainWebsite(): DomainEvidence['website'] {
  return {
    status: 'nxdomain',
    httpStatus: null,
    finalDomain: null,
    title: null,
    bodyBytes: null,
    redirectedToUnrelatedDomain: false,
  };
}

async function checkDns(
  domain: string,
  options: CheckOptions,
): Promise<DnsResult> {
  const [a, aaaa, mx, txt, dmarc] = await Promise.all([
    doh(domain, 'A', options),
    doh(domain, 'AAAA', options),
    doh(domain, 'MX', options),
    doh(domain, 'TXT', options),
    doh(`_dmarc.${domain}`, 'TXT', options),
  ]);

  const nxdomain = a.nxdomain || aaaa.nxdomain;
  const resolves = nxdomain ? false : resolvePresence(a, aaaa);
  const complete = [a, aaaa, mx, txt, dmarc].every((result) => result.ok);
  return {
    dns: {
      resolves,
      hasMx: mx.nxdomain ? false : mx.ok ? hasAnswers(mx) : null,
      hasSpf: txt.nxdomain ? false : txt.ok ? txt.answers.some((data) => /(^|")v=spf1\b/i.test(data)) : null,
      dmarcPolicy: dmarc.nxdomain ? null : dmarcPolicy(dmarc.answers),
    },
    nxdomain,
    complete,
  };
}

async function doh(
  name: string,
  type: string,
  options: CheckOptions,
): Promise<{ nxdomain: boolean; answers: string[]; ok: boolean }> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  try {
    const res = await options.fetcher(url, {
      headers: { accept: 'application/dns-json' },
      signal: options.signal,
    });
    if (!res.ok) return { nxdomain: false, answers: [], ok: false };
    const json = (await res.json().catch(() => null)) as DohResponse | null;
    if (!json) return { nxdomain: false, answers: [], ok: false };
    return {
      nxdomain: json?.Status === 3,
      answers: (json?.Answer ?? []).map((answer) => String(answer.data ?? '')).filter(Boolean),
      ok: true,
    };
  } catch {
    return { nxdomain: false, answers: [], ok: false };
  }
}

function hasAnswers(result: { answers: string[] }): boolean {
  return result.answers.length > 0;
}

function resolvePresence(...results: Array<{ answers: string[]; ok: boolean }>): boolean | null {
  if (results.some((result) => result.answers.length > 0)) return true;
  return results.every((result) => result.ok) ? false : null;
}

function dmarcPolicy(answers: string[]): string | null {
  const joined = answers.join(' ').replace(/"/g, '');
  const match = /\bp\s*=\s*(reject|quarantine|none)\b/i.exec(joined);
  return match?.[1]?.toLowerCase() ?? null;
}

async function checkWebsite(
  domain: string,
  options: CheckOptions,
): Promise<WebsiteResult> {
  let partial = false;
  for (const url of [`https://${domain}/`, `https://www.${domain}/`]) {
    try {
      const { response: res, blockedTarget } = await fetchWebsiteRoot(url, domain, options);
      if (blockedTarget !== undefined) {
        return {
          website: {
            status: 'unchecked', httpStatus: res.status,
            finalDomain: blockedTarget,
            title: null, bodyBytes: 0,
            redirectedToUnrelatedDomain: Boolean(blockedTarget && blockedTarget !== domain),
          },
          complete: false,
        };
      }
      const preview = await readPreview(res);
      const finalUrl = res.url || url;
      const finalDomain = registrableDomain(new URL(finalUrl).hostname);
      const title = pageTitle(preview.text);
      return {
        website: {
          status: isParked(preview.text) ? 'parked' : 'live',
          httpStatus: res.status,
          finalDomain,
          title,
          bodyBytes: preview.bytes,
          redirectedToUnrelatedDomain: Boolean(finalDomain && finalDomain !== domain),
        },
        complete: true,
      };
    } catch {
      partial = partial || options.signal.aborted;
      // Try www fallback, then report unreachable.
    }
  }
  return {
    website: {
      status: 'unreachable',
      httpStatus: null,
      finalDomain: null,
      title: null,
      bodyBytes: null,
      redirectedToUnrelatedDomain: false,
    },
    complete: !partial,
  };
}

/** Only HTTPS apex/www root redirects are allowed; never visit a new third party. */
async function fetchWebsiteRoot(url: string, domain: string, options: CheckOptions): Promise<{
  response: Response; blockedTarget?: string | null;
}> {
  const seen = new Set<string>();
  let current = url;
  for (let hop = 0; ; hop++) {
    seen.add(current);
    const response = await options.fetcher(current, {
      method: 'GET', headers: { 'user-agent': 'isitjunk-verifier/1.0 (+https://www.isitjunk.com)' },
      redirect: 'manual', signal: options.signal,
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response };
    await response.body?.cancel();
    let next: URL;
    try { next = new URL(response.headers.get('location') ?? '', current); }
    catch { return { response, blockedTarget: null }; }
    const targetDomain = registrableDomain(next.hostname);
    if (hop >= 2 || seen.has(next.href) || next.protocol !== 'https:' || next.port ||
        next.username || next.password || next.pathname !== '/' || next.search || next.hash ||
        ![domain, `www.${domain}`].includes(next.hostname)) {
      return { response, blockedTarget: targetDomain };
    }
    current = next.href;
  }
}

async function readPreview(res: Response): Promise<{ text: string; bytes: number }> {
  if (!res.body) {
    const text = await res.text();
    const bytes = Math.min(new TextEncoder().encode(text).byteLength, PREVIEW_BYTES);
    return { text: text.slice(0, PREVIEW_BYTES), bytes };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < PREVIEW_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    chunks.push(value);
    total += value.byteLength;
  }
  try {
    await reader.cancel();
  } catch {
    // Nothing useful to do if the preview stream is already closed.
  }
  const merged = new Uint8Array(Math.min(total, PREVIEW_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    const slice = chunk.slice(0, Math.max(0, PREVIEW_BYTES - offset));
    merged.set(slice, offset);
    offset += slice.byteLength;
    if (offset >= PREVIEW_BYTES) break;
  }
  return { text: new TextDecoder().decode(merged), bytes: merged.byteLength };
}

function pageTitle(body: string): string | null {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(body);
  return match?.[1]?.replace(/\s+/g, ' ').trim() || null;
}

function isParked(body: string): boolean {
  const text = body.toLowerCase();
  return (
    text.includes('this domain is for sale') ||
    text.includes('domain is for sale') ||
    text.includes('parked free courtesy of') ||
    text.includes('sedo domain parking') ||
    text.includes('afternic') ||
    text.includes('dan.com') ||
    text.includes('godaddy') ||
    /buy this domain/.test(text) ||
    /parkingcrew|bodis|namecheap parking/.test(text)
  );
}

async function checkRdap(
  domain: string,
  options: CheckOptions,
): Promise<RdapResult> {
  const primary = await fetchRdap(`https://rdap.org/domain/${encodeURIComponent(domain)}`, options);
  const fallback = primary.data || primary.status === 404 ? null : await fetchBootstrapRdap(domain, options);
  const data = primary.data ?? fallback?.data ?? null;
  const notFound = primary.status === 404 || fallback?.status === 404;
  if (!data) {
    return {
      registration: { ageDays: null, registrar: null, unregistered: notFound, statuses: [] },
      complete: notFound,
    };
  }

  const registrationDate = registrationEventDate(data);
  return {
    registration: {
      ageDays: registrationDate ? Math.max(0, Math.floor((options.now.getTime() - registrationDate.getTime()) / 86_400_000)) : null,
      registrar: registrarName(data),
      unregistered: false,
      statuses: rdapStatuses(data),
    },
    complete: true,
  };
}

async function fetchBootstrapRdap(
  domain: string,
  options: CheckOptions,
): Promise<{ status: number; data: unknown | null } | null> {
  const tld = domain.split('.').pop()?.toLowerCase();
  const endpoint = tld ? RDAP_BOOTSTRAP[tld] : undefined;
  if (!endpoint) return null;
  return fetchRdap(`${endpoint}${encodeURIComponent(domain)}`, options);
}

async function fetchRdap(
  url: string,
  options: CheckOptions,
): Promise<{ status: number; data: unknown | null }> {
  try {
    const res = await options.fetcher(url, { headers: { accept: 'application/rdap+json, application/json' }, signal: options.signal });
    if (res.status === 404) return { status: 404, data: null };
    if (!res.ok) return { status: res.status, data: null };
    return { status: res.status, data: await res.json().catch(() => null) };
  } catch {
    return { status: 0, data: null };
  }
}

function rdapStatuses(data: unknown): string[] {
  const statuses = asRecord(data).status;
  if (!Array.isArray(statuses)) return [];
  return statuses.map((status) => String(status).trim()).filter(Boolean);
}

function registrationEventDate(data: unknown): Date | null {
  const events = asRecord(data).events;
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    const record = asRecord(event);
    const action = String(record.eventAction ?? '').toLowerCase();
    if (!action.includes('registration') && !action.includes('registered')) continue;
    const date = new Date(String(record.eventDate ?? ''));
    if (!Number.isNaN(date.getTime())) return date;
  }
  return null;
}

function registrarName(data: unknown): string | null {
  const entities = asRecord(data).entities;
  if (!Array.isArray(entities)) return null;
  for (const entity of entities) {
    const record = asRecord(entity);
    const roles = Array.isArray(record.roles) ? record.roles.map(String) : [];
    if (!roles.includes('registrar')) continue;
    const vcard = record.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const row of vcard[1]) {
        if (Array.isArray(row) && row[0] === 'fn' && typeof row[3] === 'string') return row[3];
      }
    }
    if (typeof record.name === 'string') return record.name;
  }
  return null;
}

function lookalikeOf(domain: string, claimedCompany: string | null): string | null {
  const domainSld = sldVariants(domain);
  const brandDomains = new Set(TOP_BRAND_DOMAINS);
  for (const token of companyTokens(claimedCompany)) brandDomains.add(`${token}.com`);

  for (const brand of brandDomains) {
    const brandDomain = registrableDomain(brand);
    if (!brandDomain || brandDomain === domain) continue;
    const brandSld = normalizeSld(getDomainWithoutSuffix(brandDomain) ?? brandDomain.split('.')[0]);
    for (const variant of domainSld) {
      if (variant.length < 4 || brandSld.length < 4) continue;
      const distance = damerauLevenshtein(variant, brandSld);
      if (distance > 0 && distance <= 2) return brandDomain;
    }
  }
  return null;
}

function sldVariants(domain: string): string[] {
  const sld = normalizeSld(getDomainWithoutSuffix(domain) ?? domain.split('.')[0]);
  const variants = new Set([sld]);
  let trimmed = sld;
  for (let i = 0; i < 3; i++) {
    const next = trimmed.replace(/(inc|llc|ltd|corp|corporation|company|co)$/i, '');
    if (next === trimmed) break;
    trimmed = next;
    if (trimmed) variants.add(trimmed);
  }
  return [...variants];
}

function companyTokens(company: string | null): string[] {
  if (!company || company.length > 512) return [];
  return company
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 4 && token.length <= 63 && !['company', 'corp', 'corporation', 'inc', 'llc', 'ltd'].includes(token));
}

function normalizeSld(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function domainRoles(extracted: ExtractedSender): Map<string, DomainRole> {
  const roles = new Map<string, DomainRole>();
  const original = emailDomain(extracted.originalFromEmail);
  const replyTo = emailDomain(extracted.originalReplyTo);
  const submitter = emailDomain(extracted.submitterEmail);
  if (original) roles.set(original, 'original-from');
  if (replyTo && !roles.has(replyTo)) roles.set(replyTo, 'reply-to');
  if (submitter && extracted.isContactForm) roles.set(submitter, 'form-submitter');
  return roles;
}

function emailDomain(value: string | null): string | null {
  const domain = value?.split('@')[1]?.toLowerCase();
  return domain ? registrableDomain(domain) : null;
}

function registrableDomain(host: string): string | null {
  const normalized = host.toLowerCase().replace(/\.+$/, '');
  return getDomain(normalized, { allowPrivateDomains: true }) ?? (normalized.includes('.') ? normalized : null);
}

function timeoutSignal(ms: number): AbortSignal {
  const maybeTimeout = (AbortSignal as typeof AbortSignal & { timeout?: (ms: number) => AbortSignal }).timeout;
  if (typeof maybeTimeout === 'function') return maybeTimeout(ms);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function damerauLevenshtein(a: string, b: string): number {
  // This caller only cares about distances <= 2. Reject impossible/invalid
  // comparisons before allocating; valid DNS labels bound the matrix to 64x64.
  if (a.length > 63 || b.length > 63 || Math.abs(a.length - b.length) > 2) return 3;
  const dp = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[a.length][b.length];
}
