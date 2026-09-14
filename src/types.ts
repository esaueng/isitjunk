/**
 * Shared types for the isitjunk-email Worker.
 */

/**
 * Worker bindings & environment.
 *
 * Secrets (OPENROUTER_API_KEY) are injected via `wrangler secret
 * put` and never committed. `DB` is required for email admission. Inbound mail arrives
 * via the Cloudflare Email Routing `email()` handler. Outbound verdicts use the
 * optional Cloudflare Email Sending binding when present, falling back to
 * `message.reply()` when it is not bound or fails at runtime.
 */
export interface Env {
  /**
   * D1 database holding aggregate verdict statistics and atomic daily admission counts.
   * If unavailable, email admission fails closed; HTTP stats can still report zeros.
   */
  DB?: D1Database;

  /**
   * Cloudflare Email Sending binding for verdict emails from report@isitjunk.com.
   * Optional in tests/local development; the deployment configuration binds it.
   */
  REPORT_EMAIL?: SendEmail;

  /**
   * Optional Cloudflare Rate Limiting binding for the inbound email path, keyed
   * by a SHA-256 of the envelope sender. When absent, only the global budget applies; binding errors deny admission.
   */
  EMAIL_RATE_LIMITER?: RateLimitBinding;

  /** OpenRouter API key. Required. */
  OPENROUTER_API_KEY: string;
  /** Existing Access team hostname, without a scheme or path. */
  ACCESS_TEAM_DOMAIN?: string;
  /** Audience tag of the existing admin Access application. */
  ACCESS_AUD?: string;
  /** Required dedicated HTTPS admin host; admin routes exist only on this host. */
  ADMIN_HOST?: string;
  /** Required signed email claim, in addition to the existing Access policy. */
  ADMIN_EMAIL?: string;

  /** OpenRouter model id. Optional — defaults to DEFAULT_OPENROUTER_MODEL. */
  OPENROUTER_MODEL?: string;
  /**
   * Optional comma-separated fallback model ids, tried in order if the primary
   * model is unavailable. ZDR is enforced for these exactly as for the primary.
   */
  OPENROUTER_FALLBACK_MODELS?: string;
  /** Optional cheaper model for stage-1 sender extraction. Defaults to the current GPT mini model. */
  OPENROUTER_EXTRACT_MODEL?: string;

  /** Domain verification kill switch. Defaults to enabled unless set to "false". */
  DOMAIN_VERIFY_ENABLED?: string;
  /** Total domain-verification budget in milliseconds. Defaults to 8000. */
  DOMAIN_VERIFY_TIMEOUT_MS?: string;
  /** Maximum domains to verify per message. Defaults to 3. */
  MAX_DOMAINS_CHECKED?: string;

  /**
   * Cap on admitted attempts per UTC day, including failed analyses. Defaults to 200.
   * Requires the DB binding; invalid configuration denies admission.
   */
  MAX_ANALYSES_PER_DAY?: string;

  /**
   * Optional CORS origin for GET /public/stats. Defaults to "*". Set to e.g.
   * "https://www.isitjunk.com" to restrict it.
   */
  ALLOWED_STATS_ORIGIN?: string;
}

/** The fields we extract from an inbound Cloudflare Email Routing message. */
export interface InboundEmail {
  /** Envelope sender — the person who forwarded the mail (our reply target). */
  from: string;
  /** Envelope recipient — the routed address, e.g. report@isitjunk.com. */
  to: string;
  /** Subject header of the received message. */
  subject: string;
  /** Original `Message-ID` header (empty if absent) — used to thread the reply. */
  messageId: string;
  /** `Authentication-Results` header (SPF/DKIM/DMARC), if present. */
  authResults: string;
  /** RFC 3834 Auto-Submitted header used to avoid auto-reply loops. */
  autoSubmitted: string;
  /** Legacy bulk/list/autoreply hint used to avoid mail loops and backscatter. */
  precedence: string;
  /** Microsoft/Exchange auto-response suppression hint, if present. */
  autoResponseSuppress: string;
  /** Full raw RFC822 message (headers + body). */
  raw: string;
  /** Parsed text/plain (or normalized HTML) body used to preserve useful content when raw input is oversized. */
  contentText?: string;
  /** Cloudflare-reported raw message size, or bytes observed while reading. */
  rawSize: number;
  /** Number of raw bytes decoded into `raw`. */
  rawBytesRead: number;
  /** True when the raw stream was intentionally capped before EOF. */
  rawTruncated: boolean;
}

export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Structured sender identified before classification. */
export interface ExtractedSender {
  originalFromEmail: string | null;
  originalFromName: string | null;
  originalReplyTo: string | null;
  claimedCompany: string | null;
  isContactForm: boolean;
  submitterEmail: string | null;
  candidateDomains: string[];
  confidence: 'high' | 'medium' | 'low';
  method: 'rfc822-part' | 'inline-headers' | 'contact-form' | 'llm' | 'none';
}

export type DomainRole = 'original-from' | 'reply-to' | 'form-submitter';

/** Live evidence gathered for a sender-related registrable domain. */
export interface DomainEvidence {
  domain: string;
  role: DomainRole;
  dns: {
    resolves: boolean | null;
    hasMx: boolean | null;
    hasSpf: boolean | null;
    dmarcPolicy: string | null;
  };
  website: {
    status: 'live' | 'parked' | 'unreachable' | 'nxdomain' | 'unchecked';
    httpStatus: number | null;
    finalDomain: string | null;
    title: string | null;
    bodyBytes: number | null;
    redirectedToUnrelatedDomain: boolean;
  };
  registration: {
    ageDays: number | null;
    registrar: string | null;
    unregistered: boolean;
    statuses: string[];
  };
  freemail: boolean;
  disposable: boolean;
  lookalikeOf: string | null;
  checkedAt: 'complete' | 'partial' | 'skipped';
}

/** Stage-1 LLM extraction shape. Providers may return snake_case or camelCase. */
export interface LlmExtractionResult {
  original_from_email?: unknown;
  originalFromEmail?: unknown;
  original_from_name?: unknown;
  originalFromName?: unknown;
  reply_to?: unknown;
  originalReplyTo?: unknown;
  claimed_company?: unknown;
  claimedCompany?: unknown;
  is_contact_form?: unknown;
  isContactForm?: unknown;
  submitter_email?: unknown;
  submitterEmail?: unknown;
}

/** The four parsed fields from the LLM's `~`-separated output. */
export interface Analysis {
  score: string | null;
  label: string | null;
  reason: string | null;
  subject: string | null;
}

/**
 * Aggregate tallies — the ONLY data this service persists. No message-level
 * data is ever stored (see the no-log policy in README.md).
 */
export interface StatsRecord {
  total_processed: number;
  total_junk: number;
  total_notjunk: number;
  total_uncertain: number;
}

/** One UTC day's aggregate-only classification counters. */
export interface DailyStatsRecord extends StatsRecord {
  day: string;
}

/** Lifetime counters plus a bounded daily trend series. */
export interface StatsSnapshot extends StatsRecord {
  history: DailyStatsRecord[];
}

/** The slice of an OpenRouter chat-completions response we rely on. */
export interface OpenRouterResponse {
  choices?: Array<{ message?: { content?: string } }>;
  error?: { message?: string; code?: number | string };
}
