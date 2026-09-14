/**
 * isitjunk-email Worker — a Cloudflare Worker rebuild of the n8n "isitjunk"
 * email-analysis automation, using Cloudflare Email Routing for inbound mail
 * and Cloudflare Email Sending for outbound verdicts.
 *
 * email() handler  — Email Routing delivers forwarded mail here; the Worker
 *   analyses it (OpenRouter, ZDR enforced), records aggregate stats, and sends
 *   the verdict with Cloudflare Email Sending, falling back to message.reply().
 *
 * fetch() routes:
 *   GET  /public            — public aggregate-stats page (HTML).
 *   GET  /public/stats      — public aggregate-stats JSON (CORS).
 *   GET  /admin             — private dashboard (Cloudflare Access required).
 *   POST /admin/login       — redirect legacy login to the dashboard.
 *   POST /admin/logout      — redirect to Cloudflare Access logout.
 *   GET  /admin/stats       — aggregate stats JSON (auth required).
 *   POST /admin/reset-stats — reset counters (auth required).
 *   GET  /                  — health check.
 *
 * PRIVACY / NO-LOG POLICY: email content and metadata exist in memory only for
 * the duration of a message. Nothing message-level is ever persisted or logged.
 * Only lifetime and UTC-day aggregate counters in D1 are stored. console.* is used solely
 * for generic operational checkpoints, errors, and status codes.
 */
import { EmailMessage } from 'cloudflare:email';
import { handleAdmin } from './admin';
import {
  REPORT_FROM_EMAIL,
  domainVerificationEnabled,
  domainVerifyTimeoutMs,
  maxDomainsChecked,
  missingEnv,
  maxAnalysesPerDay,
} from './config';
import { buildFailureReplyMime, buildReplyMime, constrainAnalysisForReply } from './email';
import { extractSender } from './extract';
import { runAnalysis, parseAnalysis, runExtraction } from './openrouter';
import {
  buildLlmInput,
  normalizeAddress,
  readInbound,
  shouldSkipLoopRiskEmail,
  shouldSkipUnauthenticatedSender,
} from './payload';
import { handlePublic } from './public';
import { recordAnalysis, statsStorageConfigured } from './stats';
import type { Analysis, DomainEvidence, Env, ExtractedSender, InboundEmail } from './types';
import { json, sha256Hex } from './util';
import { verifyDomains } from './verify';
import { reserveAnalysis } from './budget';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      const adminRes = await handleAdmin(request, env, url);
      if (adminRes) return adminRes;

      const publicRes = await handlePublic(request, env, url);
      if (publicRes) return publicRes;

      if (url.pathname === '/' && request.method === 'GET') {
        return json({ ok: true, service: 'isitjunk-email' });
      }

      return json({ ok: false, error: 'Not found' }, 404);
    } catch {
      console.error('Unhandled error');
      return json({ ok: false, error: 'Internal server error' }, 500);
    }
  },

  /** Cloudflare Email Routing entry point: analyse → record → reply. */
  async email(message, env): Promise<void> {
    let inbound: InboundEmail | null = null;
    let replyAttempted = false;
    let admitted = false;
    try {
      console.info('Email received by Worker.');

      inbound = await readInbound(message);
      if (shouldSkipLoopRiskEmail(inbound)) {
        console.info('Skipping automated or loop-risk email.');
        return;
      }
      // The reply goes to the envelope sender. Require positive authentication
      // for that exact mailbox to avoid relaying mail to a spoofed address.
      if (shouldSkipUnauthenticatedSender(inbound)) {
        console.info('Skipping email whose sender failed authentication; no reply sent.');
        return;
      }

      // Denied admission is silent: flooding a limit must not generate a reply flood.
      if (await senderRateLimited(inbound, env)) {
        console.warn('Sender admission denied; skipping this message.');
        return;
      }
      if (!(await reserveAnalysis(env, maxAnalysesPerDay(env)))) {
        console.warn('Analysis admission denied; skipping this message.');
        return;
      }

      admitted = true;
      const missing = missingEnv(env);
      if (missing.length) {
        console.error(`Missing required configuration: ${missing.join(', ')}`);
        replyAttempted = true;
        await sendFailureEmail(env, message, inbound);
        return;
      }

      const { extracted, evidence } = await extractAndVerify(inbound, env);
      const raw = await runAnalysis(
        env,
        buildLlmInput(
          inbound,
          undefined,
          extracted || evidence.length ? { extracted, evidence } : undefined,
        ),
      );
      // Aggregate the same constrained verdict that the reporter receives.
      const analysis = constrainAnalysisForReply(parseAnalysis(raw));
      console.info('Email analysis completed.');

      // Stats are best-effort: a storage hiccup (or no store) must not abort the
      // reply.
      try {
        if (!statsStorageConfigured(env)) {
          console.info('Stats storage is not configured; skipping aggregate update.');
        }
        await recordAnalysis(env, analysis.label);
      } catch {
        console.error('Stats update failed (analysis still returned)');
      }

      replyAttempted = true;
      await sendVerdictEmail(env, message, inbound, analysis);
    } catch {
      console.error('Email processing failed');
      if (inbound && admitted && !replyAttempted) {
        await sendFailureEmail(env, message, inbound);
      }
    }
  },
} satisfies ExportedHandler<Env>;

async function extractAndVerify(
  inbound: InboundEmail,
  env: Env,
): Promise<{ extracted: ExtractedSender | null; evidence: DomainEvidence[] }> {
  if (!domainVerificationEnabled(env)) return { extracted: null, evidence: [] };

  let extracted: ExtractedSender | null = null;
  try {
    extracted = await extractSender(inbound, {
      llmExtract: (input) => runExtraction(env, input),
    });
  } catch {
    console.error('Sender extraction failed; continuing without domain evidence.');
    return { extracted: null, evidence: [] };
  }

  if (!extracted.candidateDomains.length) return { extracted, evidence: [] };

  try {
    const evidence = await verifyDomains(extracted, {
      timeoutMs: domainVerifyTimeoutMs(env),
      maxDomains: maxDomainsChecked(env),
    });
    return { extracted, evidence };
  } catch {
    console.error('Domain verification failed; continuing without domain evidence.');
    return { extracted, evidence: [] };
  }
}

/**
 * True when the envelope sender has exceeded the per-sender limit. The key is a
 * hash of the normalised address — the address itself is never handed to the
 * binding, stored, or logged. An absent binding uses the global budget only;
 * a configured binding that fails denies admission.
 */
async function senderRateLimited(inbound: InboundEmail, env: Env): Promise<boolean> {
  const limiter = env.EMAIL_RATE_LIMITER;
  if (!limiter) return false;
  const sender = normalizeAddress(inbound.from);
  if (!sender) return false;
  try {
    const result = await limiter.limit({ key: `sender:${await sha256Hex(sender)}` });
    return !result.success;
  } catch {
    console.error('Email rate limiter unavailable; denying the message.');
    return true;
  }
}

/** Send the verdict to the original sender (best-effort). */
async function sendVerdictEmail(
  env: Env,
  message: ForwardableEmailMessage,
  inbound: InboundEmail,
  analysis: Analysis,
): Promise<void> {
  const mime = buildReplyMime(analysis, {
    toEmail: inbound.from,
    inReplyTo: inbound.messageId,
    fromEmail: REPORT_FROM_EMAIL,
  });
  await sendReplyEmail(env, message, inbound, mime, 'Verdict');
}

async function sendFailureEmail(
  env: Env,
  message: ForwardableEmailMessage,
  inbound: InboundEmail,
): Promise<void> {
  try {
    const mime = buildFailureReplyMime({
      toEmail: inbound.from,
      inReplyTo: inbound.messageId,
      fromEmail: REPORT_FROM_EMAIL,
    });
    await sendReplyEmail(env, message, inbound, mime, 'Analysis unavailable');
  } catch {
    console.error('Failure response could not be built or sent.');
  }
}

async function sendReplyEmail(
  env: Env,
  message: ForwardableEmailMessage,
  inbound: InboundEmail,
  mime: string,
  kind: 'Verdict' | 'Analysis unavailable',
): Promise<void> {
  if (!inbound.from || shouldSkipUnauthenticatedSender(inbound)) {
    console.error('Reply destination is not authenticated; skipping reply.');
    return;
  }

  const fromEmail = REPORT_FROM_EMAIL;
  const email = new EmailMessage(fromEmail, inbound.from, mime);

  if (env.REPORT_EMAIL) {
    try {
      await env.REPORT_EMAIL.send(email);
      console.info(`${kind} email sent with Cloudflare Email Sending.`);
      return;
    } catch {
      console.error('Email Sending failed; trying Email Routing reply fallback.');
    }
  }

  try {
    await message.reply(email);
    console.info(`${kind} email sent with Email Routing reply fallback.`);
  } catch {
    console.error(`${kind} email send failed.`);
  }
}
