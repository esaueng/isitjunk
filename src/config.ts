/**
 * Constants and environment validation.
 */
import type { Env } from './types';

/** Default OpenRouter model for final classification (configurable via OPENROUTER_MODEL). */
export const DEFAULT_OPENROUTER_MODEL = 'openai/gpt-5.5';
/** Default smaller model for stage-1 sender extraction. */
export const DEFAULT_OPENROUTER_EXTRACT_MODEL = 'openai/gpt-5.4-mini';

/**
 * Reply sender identity. REPORT_FROM_EMAIL must be the routed and verified
 * report address in Cloudflare. Email Sending uses it as the sender, and the
 * message.reply() fallback still requires it to be one of the original
 * message's recipients.
 */
/** The only three labels a verdict may carry (mirrors the prompt's output contract). */
export const VERDICT_LABELS = ["Yes, it's Junk", 'No, Not Junk', 'Uncertain'] as const;

export const REPORT_FROM_EMAIL = 'report@isitjunk.com';
export const REPORT_FROM_NAME = 'Is It Junk?';
/** Support address shown in the result email footer. */
export const SUPPORT_EMAIL = 'help@isitjunk.com';

/** Canonical site URL (used for OpenRouter attribution headers only). */
export const SITE_URL = 'https://www.isitjunk.com';

/** Upstream API endpoint. */
export const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

/**
 * Hard cap on how much raw email we forward to the LLM. Forwarded mail can
 * carry large base64 attachments; truncating bounds token cost and request
 * size while keeping all headers (which appear first) intact.
 */
export const MAX_EMAIL_CHARS = 100_000;
export const RAW_EMAIL_READ_BYTE_LIMIT = MAX_EMAIL_CHARS * 4 + 1024;
export const DEFAULT_DOMAIN_VERIFY_TIMEOUT_MS = 8_000;
/** Per-attempt limit on an OpenRouter call. Retries get a fresh budget. */
export const OPENROUTER_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_DOMAINS_CHECKED = 3;
/**
 * Return the secrets the email pipeline needs that are missing. Access settings
 * (admin-only) and `DB` (required for admission) are checked at their own boundaries,
 * not here; `OPENROUTER_MODEL` has a default. REPORT_EMAIL is a Worker binding
 * configured in wrangler.jsonc and has a runtime fallback, so it is not treated
 * as a secret here.
 */
export function missingEnv(env: Env): string[] {
  const missing: string[] = [];
  if (!env.OPENROUTER_API_KEY) missing.push('OPENROUTER_API_KEY');
  return missing;
}

/** Resolve the primary model, falling back to the documented default. */
export function resolveModel(env: Env): string {
  return env.OPENROUTER_MODEL?.trim() || DEFAULT_OPENROUTER_MODEL;
}

/**
 * Resolve the optional fallback model list (comma-separated). ZDR is enforced
 * for these identically to the primary model — see openrouter.ts.
 */
export function resolveFallbackModels(env: Env): string[] {
  return (env.OPENROUTER_FALLBACK_MODELS ?? '')
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);
}

/** Resolve the extraction model, defaulting to the current smaller GPT model. */
export function resolveExtractionModel(env: Env): string {
  return env.OPENROUTER_EXTRACT_MODEL?.trim() || DEFAULT_OPENROUTER_EXTRACT_MODEL;
}

/** Domain verification is enabled by default and can be disabled with false/0/off/no. */
export function domainVerificationEnabled(env: Env): boolean {
  const raw = env.DOMAIN_VERIFY_ENABLED;
  if (raw == null || raw.trim() === '') return true;
  return !['false', '0', 'off', 'no'].includes(raw.trim().toLowerCase());
}

export function domainVerifyTimeoutMs(env: Env): number {
  const parsed = Number(env.DOMAIN_VERIFY_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, 30_000) : DEFAULT_DOMAIN_VERIFY_TIMEOUT_MS;
}

/** Safe default; malformed or nonpositive overrides cannot disable admission control. */
export function maxAnalysesPerDay(env: Env): number {
  const raw = env.MAX_ANALYSES_PER_DAY;
  if (raw == null || raw.trim() === '') return 200;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error('Invalid daily analysis budget');
  return parsed;
}

export function maxDomainsChecked(env: Env): number {
  const parsed = Number(env.MAX_DOMAINS_CHECKED);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(Math.floor(parsed), 10) : DEFAULT_MAX_DOMAINS_CHECKED;
}
