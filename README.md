# isitjunk

The Cloudflare Worker behind [Is It Junk?](https://www.isitjunk.com). A user forwards
suspicious email to `report@isitjunk.com`; the Worker checks sender-domain evidence,
asks a language model for a junk assessment, and emails a verdict with HTML and plain-text alternatives back.
This is an advisory second opinion. A low score is not a guarantee that a message,
link, or attachment is safe.

## Processing and admission

1. Cloudflare Email Routing invokes the `email()` handler. The Worker reads at most
   401,024 raw bytes and filters automated, bounce, no-reply and loop-risk messages.
2. Replies require one unambiguous `mx.cloudflare.net` authentication block with
   `spf=pass` and `smtp.mailfrom` equal to the actual envelope reply address. Missing,
   neutral, error, mismatched or duplicate MAIL FROM evidence is rejected. Separate
   HELO SPF results do not authorize or invalidate the envelope sender. A DMARC pass for a
   different header sender does not authorize a reply. DMARC failure also rejects it.
3. The optional per-sender rate limiter runs before paid work. Its key is a SHA-256
   of the normalized address. If a configured limiter fails or denies admission, the
   Worker makes no model call and sends no reply.
4. D1 atomically reserves one daily attempt **before extraction or classification**.
   `MAX_ANALYSES_PER_DAY` defaults to 200 and must be a positive integer. Missing or
   failing D1 and invalid limits deny admission without a reply. Failed analyses
   retain their reservation; resetting verdict statistics never replenishes it.
5. Deterministic MIME, inline-forward and contact-form parsing identifies the original
   sender. Optional model extraction fills gaps. Identity claims over 512 characters
   are treated as unknown, and local domain comparisons are bounded.
6. The Worker collects best-effort DNS, root-website and RDAP evidence, then requests a
   classification from OpenRouter with Zero Data Retention routing required.
7. Completed verdicts increment aggregate statistics. The constrained multipart reply
   goes to the authenticated envelope sender through `REPORT_EMAIL`, with
   `message.reply()` as the runtime fallback. Both paths repeat the same recipient
   authentication check. Accepted attempts that fail analysis get one generic failure
   reply; rejected admission does not produce backscatter.

The daily limit counts admitted attempts, **not dollars or individual API calls**.
Each attempt can make an extraction and a classification request, each with bounded
retries. Configure an independent OpenRouter account/key spending limit as well.
The optional sender limiter is an additional local abuse control; the global D1
reservation is the authoritative daily limit.

The authentication boundary assumes Cloudflare Email Routing supplies its own trusted
Authentication-Results header. Do not expose the handler through an HTTP wrapper that
accepts caller-supplied authentication results. Duplicate same-ID headers fail closed.
The gate verifies sending-domain authorization for the envelope identity; it cannot
prove individual mailbox consent on a provider that permits same-domain spoofing.

## Local development

Use Node 22.13+ (CI uses Node 22; tests include Node's built-in SQLite).

```sh
npm ci
cp .dev.vars.example .dev.vars
# Set the development OPENROUTER_API_KEY in .dev.vars if needed.
npm run db:init:local
npm run dev
npm run verify
```

Tests stub external mail and model services. Budget tests execute the actual admission
SQL in in-memory SQLite. No test sends real mail or submits email to a model.
`wrangler dev` serves HTTP routes; real inbound Email Routing and outbound delivery
require a separately authorized deployment and controlled end-to-end verification.

## Private deployment configuration

`wrangler.jsonc` is a local template with no production routes, admin identity, Access
application identifiers, or database ID. Its zero database ID must never be deployed.
The deployment wrapper refuses missing or example settings.

```sh
mkdir -p .deployment
cp deployment.example.json .deployment/settings.json
# Fill in your own non-secret deployment settings in this ignored file.
npm run config:deployment
```

Alternatively set `DEPLOYMENT_SETTINGS_PATH` to an approved private JSON file. The
wrapper generates `.deployment/wrangler.jsonc`, also ignored by Git. It preserves the
Worker name, models, daily budget, email binding, observability, and disabled
`workers.dev`/preview hosts from the template. Routes must include the dedicated
admin custom domain. Account selection stays outside source in
`CLOUDFLARE_ACCOUNT_ID` or the operator's authenticated Wrangler context.

For Cloudflare Workers Builds, provision the same JSON as a build secret named
`DEPLOYMENT_SETTINGS_JSON` on both production and preview triggers. Set the production
deploy command to `npm run deploy` and the non-production version command to
`npm run upload:version`. Both commands prepare private configuration before invoking
Wrangler. A direct `npx wrangler deploy` or `npx wrangler versions upload` uses the
public template and fails on its placeholder database ID. Build secrets take
precedence over the local settings file, and malformed secrets fail closed.

Set the API credential using the resolved private configuration:

```sh
npx wrangler secret put OPENROUTER_API_KEY --config .deployment/wrangler.jsonc
```

Configure a Cloudflare Access application over the **entire admin hostname**. The
Worker independently verifies RS256 signatures, issuer, audience, expiration,
application-token type and the configured administrator email. Admin POST mutations
also require the exact HTTPS Origin. There is no password or unsigned-header bypass.

When deployment is authorized:

```sh
npm run deploy
npm run tail
```

Use `npm run deploy -- --dry-run` to validate the private deployment without publishing.
Both commands use the ignored configuration. New build hosts need private settings
provisioned separately; do not paste them into source, PR descriptions, or public logs.
Treat deployment output as private because tooling can print binding values and routes.
The deploy/version wrapper redacts configured private values and account IDs from
Wrangler output. Direct Wrangler commands and live `tail` output remain private.
There is no automatic deployment job in this repository's CI workflow.

The Worker self-creates aggregate tables. `schema.sql` also defines them explicitly;
`npm run db:init:remote` applies it to the privately configured database and requires
separate authorization. Upgrading introduces `analysis_budget`: its allowance begins
when the new admission counter is first used, independently of existing verdict totals.

For inbound mail, configure Email Routing to deliver the reporting address to this
Worker. Configure Cloudflare Email Sending for the reporting domain and bind
`REPORT_EMAIL`. It has no static destination allowlist because legitimate reporters
vary; the application's positive sender-authentication gate controls replies. The
reply identity is defined in `src/config.ts` and must match the routed, verified domain.

## Configuration

| Setting | Behavior |
|---|---|
| `OPENROUTER_API_KEY` | Required secret for model calls; never committed |
| `DB` | Required for email admission; holds aggregate counters only |
| `MAX_ANALYSES_PER_DAY` | Positive integer, default 200; failures consume attempts |
| `EMAIL_RATE_LIMITER` | Optional sender limiter; configured binding errors deny admission |
| `OPENROUTER_MODEL` | Classification model, default `openai/gpt-5.5` |
| `OPENROUTER_EXTRACT_MODEL` | Extraction model, default `openai/gpt-5.4-mini` |
| `OPENROUTER_FALLBACK_MODELS` | Optional comma-separated fallbacks; ZDR remains enforced |
| `DOMAIN_VERIFY_ENABLED` | Default enabled; `false`, `0`, `off`, `no` disable verification |
| `DOMAIN_VERIFY_TIMEOUT_MS` | Default 8,000 ms, maximum 30,000 ms |
| `MAX_DOMAINS_CHECKED` | Default 3, maximum 10 |
| `ALLOWED_STATS_ORIGIN` | Public aggregate API CORS origin; default `*` |
| Private deployment `vars` | `ADMIN_HOST`, `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `ADMIN_EMAIL` |

To enable the optional sender limiter, add a `ratelimits` binding to the template:

```json
{
  "ratelimits": [{
    "name": "EMAIL_RATE_LIMITER",
    "namespace_id": "1002",
    "simple": { "limit": 5, "period": 60 }
  }]
}
```

## Domain evidence and classification

The verifier checks A/AAAA, MX, SPF and DMARC DNS records through Cloudflare DoH;
registration age/status through RDAP; root website status; and local freemail,
disposable and look-alike lists. Freemail domains skip network verification.
Lookup failures produce partial evidence rather than fabricated facts.

Website redirects are followed only between the candidate's HTTPS apex and `www`
roots, with a bounded hop count. Paths, query strings, credentials, alternate ports,
non-HTTPS URLs and unrelated destinations are not fetched. A blocked redirect is
reported as partial/unchecked evidence. RDAP queries go to RDAP providers, including
provider redirects and bundled TLD-specific fallbacks.

The classifier receives bounded, labelled evidence and untrusted email content. Names,
company claims and website text are data, not instructions. Prompts and heuristics are
not secrets or authorization controls. Model output is constrained before it is echoed:
known labels only, a score in [0,1], bounded single-line reason/subject, URL path removal,
and a fixed disclaimer. This does not guarantee resistance to every adversarial email.

Verdict reports include HTML and plain-text alternatives, with fixed advice, up to
three reason bullets, verification limits, and scores out of 100 labelled as assessments
rather than measured probabilities. The HTML contains no remote assets. Contradictory
score/label pairs become Uncertain with no displayed score; aggregate statistics use
that same constrained verdict. Optional `Scam:`, `Unwanted marketing:`, and `Other junk:`
reason prefixes select presentation while preserving the four-field model contract.
Extracted addresses remain claims, DNS records are not message authentication, and
missing original authentication is described as unavailable rather than failed.

The output format remains `score~label~reason~subject`: scores through 0.30 are
*No, Not Junk*, scores at least 0.70 are *Yes, it's Junk*, and intermediate scores are
*Uncertain*. The enhanced prompt retains this contract from the original automation.

## HTTP routes and statistics

| Route | Access |
|---|---|
| `GET /` | Health check on non-admin hosts |
| `GET /public` | Public aggregate HTML |
| `GET /public/stats` | Public aggregate JSON with CORS |
| Admin host `GET /`, `GET /stats` | Verified Cloudflare Access assertion |
| Admin host `POST /reset-stats` | Access plus exact HTTPS Origin |
| Admin host `/login`, `/logout` | Legacy redirect / Access logout |

Legacy `/admin/*` paths redirect on the admin host. Public responses contain lifetime
counts and up to 30 active UTC days of verdict totals. Reset clears verdict statistics
only; admission counters remain separate and are never exposed by the public API.

## Privacy and publication

Application-controlled persistence contains only lifetime/UTC-day verdict totals and
UTC-day admitted-attempt counts. No raw messages, addresses, subjects, message IDs,
headers, prompts, scores, reasons or per-message records are written to D1 or application
logs. Generic operational logs contain no message content. Optional sender-limit keys
are hashed addresses handled by the platform limiter, not stored in D1.

Message content exists transiently in Worker memory, is sent to OpenRouter for analysis,
and the verdict is delivered to the authenticated reporter. Both model requests include
`provider: { zdr: true, data_collection: "deny" }`; retries and configured fallbacks
retain those flags. A routing refusal never falls back to a retaining provider. Actual
provider/platform retention and mailbox copies remain external to source-level guarantees.

Domain checks disclose the candidate domain to DNS/RDAP services and permitted root
website hosts. They do not send email content, reporter identity, message links, or
operator credentials to lookup targets. A domain owner may still observe that its site
was checked. Lookup evidence is not cached or stored.

This public repository starts from a reviewed source snapshot with fresh Git history.
Private deployment settings, original repository history, PR discussions, build logs,
and local developer state are not included. Tests use illustrative identities; public
product/support/security contacts and license attribution are intentional.

Private settings, environment files and generated deployment configuration are
Git-ignored. Configure your own Cloudflare resources and credentials before deploying.
Never commit real deployment settings or copy private build output into public issues
or pull requests. Ignoring a file does not remove it from existing commits.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
