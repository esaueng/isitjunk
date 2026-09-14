/**
 * Public stats — safe to link from the main website.
 *
 * Routes:
 *   GET /public/stats  — aggregate counters as JSON (CORS-enabled)
 *   GET /public        — a minimal HTML page that fetches /public/stats
 *
 * Exposes AGGREGATE COUNTERS ONLY. It never reveals emails, senders, subjects,
 * reasons, IPs, headers, prompts, responses, or any message-level detail —
 * there is no such data to reveal (only lifetime and UTC-day counters are stored).
 */
import type { DailyStatsRecord, Env, StatsSnapshot } from './types';
import { readStatsSnapshot } from './stats';
import { html, json, scriptSha256 } from './util';

/** Dispatch /public and /public/stats. Returns null if not a public route. */
export async function handlePublic(request: Request, env: Env, url: URL): Promise<Response | null> {
  const path = url.pathname;

  if (path === '/public/stats') {
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }), env);
    if (request.method !== 'GET') {
      return withCors(json({ ok: false, error: 'Method not allowed' }, 405, { allow: 'GET' }), env);
    }
    return withCors(json(await readStatsSnapshot(env)), env);
  }

  if (path === '/public' || path === '/public/') {
    if (request.method !== 'GET') {
      return json({ ok: false, error: 'Method not allowed' }, 405, { allow: 'GET' });
    }
    return renderPublicPage(await readStatsSnapshot(env));
  }

  return null;
}

/** Apply CORS + short cache headers for the public stats JSON. */
function withCors(res: Response, env: Env): Response {
  const origin = env.ALLOWED_STATS_ORIGIN ?? '*';
  res.headers.set('Access-Control-Allow-Origin', origin);
  res.headers.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'accept');
  res.headers.set('Cache-Control', 'public, max-age=15');
  if (origin !== '*') res.headers.set('Vary', 'Origin');
  return res;
}

/**
 * Minimal public stats page. Renders server-side numbers immediately (works
 * without JS) and refreshes them client-side from /public/stats.
 */
/** Client-side refresh of the server-rendered numbers. Static text: its CSP hash is computed from this exact string. */
const PUBLIC_REFRESH_SCRIPT = `
    fetch('/public/stats', { headers: { accept: 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        ['total_processed', 'total_junk', 'total_notjunk', 'total_uncertain'].forEach(function (k) {
          if (typeof s[k] === 'number') document.getElementById(k).textContent = s[k].toLocaleString('en-US');
        });
      })
      .catch(function () { /* keep server-rendered values */ });
`;

async function renderPublicPage(stats: StatsSnapshot): Promise<Response> {
  return html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Is It Junk? — public stats</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; text-align: center; }
  h1 { font-size: 1.5rem; }
  .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin: 2rem 0; }
  .card { border: 1px solid #8884; border-radius: .75rem; padding: 1.25rem; }
  .n { font-size: 2.25rem; font-weight: 700; }
  .k { opacity: .7; font-size: .9rem; margin-top: .25rem; }
  .muted { opacity: .6; font-size: .85rem; }
  .trend { margin: 2rem 0; text-align: left; }
  .trend-row { display: grid; grid-template-columns: 6.5rem 1fr 3rem; gap: .6rem; align-items: center; margin: .35rem 0; font-size: .8rem; }
  .bar-track { height: .65rem; background: #8882; border-radius: 999px; overflow: hidden; }
  .bar { height: 100%; background: currentColor; opacity: .55; border-radius: inherit; }
</style></head>
<body>
  <h1>Is It Junk? — stats</h1>
  <p class="muted">Aggregate totals only. No emails, senders, or message details are ever stored.</p>
  <div class="grid">
    <div class="card"><div class="n" id="total_processed">${stats.total_processed.toLocaleString('en-US')}</div><div class="k">Emails processed</div></div>
    <div class="card"><div class="n" id="total_junk">${stats.total_junk.toLocaleString('en-US')}</div><div class="k">Junk</div></div>
    <div class="card"><div class="n" id="total_notjunk">${stats.total_notjunk.toLocaleString('en-US')}</div><div class="k">Not junk</div></div>
    <div class="card"><div class="n" id="total_uncertain">${stats.total_uncertain.toLocaleString('en-US')}</div><div class="k">Uncertain</div></div>
  </div>
  ${renderTrend(stats.history)}
  <script>${PUBLIC_REFRESH_SCRIPT}</script>
</body></html>`, 200, undefined, { scriptHashes: [await scriptSha256(PUBLIC_REFRESH_SCRIPT)] });
}

function renderTrend(history: DailyStatsRecord[]): string {
  if (!history.length) return '<p class="muted">Daily trend data will appear after the next completed analysis.</p>';
  const max = Math.max(...history.map((row) => row.total_processed), 1);
  const rows = history
    .map((row) => {
      const width = Math.max(2, Math.round((row.total_processed / max) * 100));
      return `<div class="trend-row"><time>${row.day}</time><div class="bar-track"><div class="bar" style="width:${width}%"></div></div><span>${row.total_processed}</span></div>`;
    })
    .join('');
  return `<section class="trend"><h2>Last ${history.length} active days</h2>${rows}</section>`;
}
