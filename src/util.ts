/**
 * Small framework-free helpers: typed HTTP errors, JSON/HTML responses, a fetch
 * retry wrapper and hashing.
 *
 * NOTE ON LOGGING: nothing in here logs request/response bodies. Per the
 * service's strict no-log policy (see README), callers must log only generic
 * operational messages — never email content, addresses, headers, prompts, or
 * upstream response bodies.
 */

/** An error carrying an HTTP status and a client-safe message. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    /** Message safe to return to the caller (never leak secrets/internals). */
    readonly publicMessage: string,
  ) {
    super(publicMessage);
    this.name = 'HttpError';
  }
}

/** Build a JSON `Response` with the given status and optional extra headers. */
export function json(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

export interface HtmlOptions {
  /** CSP sha256 hashes (base64) of inline <script> blocks the page embeds. None → `script-src 'none'`. */
  scriptHashes?: string[];
}

/**
 * Build an HTML `Response` with a strict Content-Security-Policy and the usual
 * anti-framing / sniffing headers. Every page here is server-rendered from
 * escaped data; the headers are defence in depth for the day an escaping bug
 * slips in. Inline scripts are allowed only by hash (see scriptSha256), never
 * by 'unsafe-inline'.
 */
export function html(
  body: string,
  status = 200,
  extraHeaders?: Record<string, string>,
  options: HtmlOptions = {},
): Response {
  const scriptSrc = options.scriptHashes?.length
    ? options.scriptHashes.map((h) => `'sha256-${h}'`).join(' ')
    : "'none'";
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      // Admin/stats pages are dynamic; don't let intermediaries cache them.
      'cache-control': 'no-store',
      'content-security-policy': [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        `script-src ${scriptSrc}`,
        "connect-src 'self'",
        "img-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
      ].join('; '),
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...extraHeaders,
    },
  });
}

const scriptHashCache = new Map<string, string>();

/** CSP `sha256-…` value (base64) for an inline script's exact source text. Memoised: the scripts are static. */
export async function scriptSha256(source: string): Promise<string> {
  const cached = scriptHashCache.get(source);
  if (cached) return cached;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(source));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  scriptHashCache.set(source, b64);
  return b64;
}

/** Escape a string for safe interpolation into HTML text/attributes. */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

interface RetryOpts {
  retries?: number;
  backoffMs?: number;
  /** Per-attempt wall-clock limit. An attempt that exceeds it is aborted and counts as a transient failure. */
  timeoutMs?: number;
}

/**
 * `fetch` with bounded retries on transient failures (network errors, HTTP 429
 * and 5xx). Non-transient responses (incl. all 4xx) are returned to the caller
 * as-is — this is what makes ZDR fail-closed: a "no ZDR provider available"
 * error from OpenRouter is a 4xx and is therefore NOT retried. Every retry
 * re-sends the identical body, so ZDR enforcement is never dropped on a retry.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  { retries = 2, backoffMs = 500, timeoutMs }: RetryOpts = {},
): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      // A fresh signal per attempt: a hung upstream must not stall the handler
      // until the platform wall-clock limit.
      const attemptInit = timeoutMs ? { ...init, signal: AbortSignal.timeout(timeoutMs) } : init;
      const res = await fetch(url, attemptInit);
      if ((res.status >= 500 || res.status === 429) && attempt < retries) {
        await sleep(backoffMs * (attempt + 1));
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        await sleep(backoffMs * (attempt + 1));
        continue;
      }
      throw err;
    }
  }
  // Unreachable: the loop either returns a Response or throws.
  throw lastErr;
}

/** SHA-256 of a string as lowercase hex. Used to key rate limits without passing raw addresses around. */
export async function sha256Hex(message: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
