/**
 * OpenRouter chat-completions call and the `~`-separated output parser.
 *
 * ZERO DATA RETENTION (ZDR) — fail closed:
 *   Every request carries `provider: { zdr: true, data_collection: "deny" }`.
 *   OpenRouter then routes ONLY to provider endpoints that guarantee zero data
 *   retention and do not collect prompts/responses. If no such endpoint can
 *   serve the model, OpenRouter returns a 4xx (e.g. 404 "No allowed providers")
 *   rather than silently using a retaining provider.
 *
 *   We never weaken this: the same body (with ZDR enforced) is what every retry
 *   re-sends, and our fetch retry wrapper does NOT retry 4xx — so a "no ZDR
 *   provider" result surfaces immediately as a generic error. There is no code
 *   path that submits a request without ZDR, and the optional fallback models
 *   are sent inside the SAME ZDR-enforced request, so they too are ZDR-only.
 */
import { OPENROUTER_TIMEOUT_MS, OPENROUTER_URL, REPORT_FROM_NAME, SITE_URL, resolveExtractionModel, resolveFallbackModels, resolveModel } from './config';
import { SYSTEM_PROMPT } from './prompt';
import type { Analysis, Env, LlmExtractionResult, OpenRouterResponse } from './types';
import { HttpError, fetchWithRetry } from './util';

/** Provider privacy controls applied to EVERY request. Do not relax these. */
const ZDR_PROVIDER = { zdr: true, data_collection: 'deny' } as const;

/**
 * Send the email content to the LLM and return its raw text output.
 *
 * Throws HttpError(502) on upstream/transient failure or empty output, and
 * HttpError(503) when the request is rejected outright (4xx, or a 200 with an
 * error body) — typically because no ZDR-compatible provider is available — so
 * we fail closed instead of retrying elsewhere. The email() handler catches
 * either and simply skips the reply (the message is still accepted, no bounce).
 *
 * Logs only generic operational messages and HTTP status codes — never the
 * email content, the prompt, or the model's response (no-log policy).
 */
export async function runAnalysis(env: Env, content: string): Promise<string> {
  const primary = resolveModel(env);
  const fallbacks = resolveFallbackModels(env);
  // OpenRouter's `models` array provides ordered fallback within one request;
  // `provider.zdr` applies to all of them. Use it only when fallbacks exist.
  const modelField = fallbacks.length ? { models: [primary, ...fallbacks] } : { model: primary };

  return requestOpenRouter(env, {
    body: {
      ...modelField,
      provider: ZDR_PROVIDER,
      temperature: 0,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content },
      ],
    },
    networkLog: 'OpenRouter request failed (network error)',
    failureMessage: 'Email analysis failed',
    emptyMessage: 'Email analysis returned no result',
    unavailableMessage: 'Email analysis is temporarily unavailable',
  });
}

const EXTRACTION_PROMPT = `Identify the ORIGINAL sender of the innermost forwarded message or the contact-form submitter.
Never return the forwarder, wrapper sender, or receiving organization.
Return only JSON with these keys:
original_from_email, original_from_name, reply_to, claimed_company, is_contact_form, submitter_email.`;

/** Stage-1 structured extraction. Returns null when the model does not return parseable JSON. */
export async function runExtraction(env: Env, content: string): Promise<LlmExtractionResult | null> {
  const output = await requestOpenRouter(env, {
    body: {
      model: resolveExtractionModel(env),
      provider: ZDR_PROVIDER,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: EXTRACTION_PROMPT },
        { role: 'user', content },
      ],
    },
    networkLog: 'OpenRouter extraction request failed (network error)',
    failureMessage: 'Sender extraction failed',
    emptyMessage: 'Sender extraction returned no result',
    unavailableMessage: 'Sender extraction is temporarily unavailable',
  });
  return parseJsonObject(output);
}

async function requestOpenRouter(
  env: Env,
  options: {
    body: Record<string, unknown>;
    networkLog: string;
    failureMessage: string;
    emptyMessage: string;
    unavailableMessage: string;
  },
): Promise<string> {
  let res: Response;
  try {
    res = await fetchWithRetry(OPENROUTER_URL, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
        'content-type': 'application/json',
        // OpenRouter attribution headers (optional but recommended).
        'HTTP-Referer': SITE_URL,
        'X-Title': REPORT_FROM_NAME,
      },
      body: JSON.stringify(options.body),
    }, { timeoutMs: OPENROUTER_TIMEOUT_MS });
  } catch {
    // Network-level failure after retries. Don't log the cause object (could
    // theoretically carry request detail); a generic message is enough.
    console.error(options.networkLog);
    throw new HttpError(502, options.failureMessage);
  }

  if (!res.ok) {
    // Read (but do NOT log) the body so we can distinguish a ZDR-routing refusal
    // from other errors. The body may reference the prompt, so it never leaves
    // this function.
    const detail = await readErrorDetail(res);
    if (res.status >= 400 && res.status < 500) {
      // Fail closed. A 4xx here is most often "no ZDR-compatible provider"
      // (404/403) or a bad model id — not something a retry would fix, and we
      // must never retry onto a non-ZDR provider.
      console.error(`OpenRouter rejected request (status ${res.status}${detail.zdr ? ', ZDR routing' : ''})`);
      throw new HttpError(503, options.unavailableMessage);
    }
    if (detail.zdr) {
      // A ZDR/data-policy refusal surfaced as a 5xx/429 still fails CLOSED,
      // consistent with the 4xx and 200-error-body paths.
      console.error(`OpenRouter rejected request (status ${res.status}, ZDR routing)`);
      throw new HttpError(503, options.unavailableMessage);
    }
    console.error(`OpenRouter upstream error (status ${res.status})`);
    throw new HttpError(502, options.failureMessage);
  }

  const data = (await res.json().catch(() => null)) as OpenRouterResponse | null;

  // OpenRouter can return HTTP 200 with a body-level `{ error }` (e.g. a routing
  // or data-policy outcome) and no choices. Treat an explicit error as a hard
  // failure rather than a retryable empty result — and if it looks like a ZDR /
  // data-policy refusal, fail CLOSED (503, non-retryable) like the 4xx path.
  if (data?.error) {
    const zdr = looksLikeZdrRefusal(String(data.error.message ?? ''));
    console.error(`OpenRouter returned an error in a 200 body${zdr ? ' (ZDR routing)' : ''}`);
    if (zdr) throw new HttpError(503, options.unavailableMessage);
    throw new HttpError(502, options.failureMessage);
  }

  const output = data?.choices?.[0]?.message?.content;
  if (!output || !output.trim()) {
    console.error('OpenRouter returned empty content');
    throw new HttpError(502, options.emptyMessage);
  }
  return output;
}

/**
 * Heuristic: does this provider error text indicate "no provider satisfies the
 * data policy" — i.e. a ZDR-routing refusal we must fail closed on? OpenRouter
 * phrases these as data policy / no allowed providers / no endpoints found.
 */
function looksLikeZdrRefusal(text: string): boolean {
  const lc = text.toLowerCase();
  return (
    lc.includes('data policy') ||
    lc.includes('data_collection') ||
    lc.includes('zdr') ||
    lc.includes('no allowed providers') ||
    lc.includes('no endpoints found')
  );
}

/** Inspect (without logging) a 4xx error body to flag a likely ZDR refusal. */
async function readErrorDetail(res: Response): Promise<{ zdr: boolean }> {
  try {
    return { zdr: looksLikeZdrRefusal(await res.text()) };
  } catch {
    return { zdr: false };
  }
}

/**
 * Parse the model's `score~label~reason~subject` output into four fields.
 *
 * Well-formed output (exactly four parts) is handled identically to the n8n
 * "Parse Output" node. If the model emits EXTRA `~` characters, we degrade
 * gracefully instead of letting fields shift: score and label (which never
 * contain `~`) stay fixed, the LAST segment is taken as the subject, and any
 * middle overflow is folded back into the reason — so a stray `~` in the reason
 * never silently replaces the subject. Empty/missing parts become null.
 */
export function parseAnalysis(raw: string): Analysis {
  const parts = (raw ?? '').split('~');
  const score = parts[0]?.trim() || null;
  const label = parts[1]?.trim() || null;
  let reason: string | null;
  let subject: string | null;
  if (parts.length <= 4) {
    reason = parts[2]?.trim() || null;
    subject = parts[3]?.trim() || null;
  } else {
    reason = parts.slice(2, -1).join('~').trim() || null;
    subject = parts[parts.length - 1]?.trim() || null;
  }
  return { score, label, reason, subject };
}

function parseJsonObject(text: string): LlmExtractionResult | null {
  const trimmed = text.trim();
  const embedded = trimmed.match(/\{[\s\S]*\}/)?.[0];
  const candidates = embedded && embedded !== trimmed ? [trimmed, embedded] : [trimmed];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as LlmExtractionResult;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
}
