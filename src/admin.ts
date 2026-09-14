/** Private aggregate stats, authenticated exclusively by Cloudflare Access. */
import type { DailyStatsRecord, Env, StatsSnapshot } from './types';
import { readStatsSnapshot, resetStats, statsStorageConfigured } from './stats';
import { accessConfig, verifyAccess } from './access';
import { escapeHtml, html, json, scriptSha256 } from './util';

export async function handleAdmin(request: Request, env: Env, url: URL): Promise<Response | null> {
  if (env.ADMIN_HOST && url.host !== env.ADMIN_HOST) return null;
  const config = accessConfig(env);
  const isPrefixed = url.pathname === '/admin' || url.pathname.startsWith('/admin/');
  if (!env.ADMIN_HOST && !isPrefixed) return null;
  if (!config) return adminJson({ ok: false, error: 'Admin Access is not configured' }, 503);
  if (!(await verifyAccess(request, config))) {
    return adminJson({ ok: false, error: 'Cloudflare Access authentication required' }, 403);
  }

  if (isPrefixed) {
    const location = url.pathname.slice('/admin'.length) || '/';
    return new Response(null, { status: 308, headers: { location: location + url.search, 'cache-control': 'no-store' } });
  }
  const path = url.pathname === '/' ? '/admin' : `/admin${url.pathname}`;

  // Old bookmarks/form submissions may arrive here after Access sign-in.
  // No credentials or application session are created by this redirect.
  if (path === '/admin/login') {
    if (request.method !== 'GET' && request.method !== 'POST') return methodNotAllowed('GET, POST');
    return redirect(`${config.origin}/`);
  }

  if (request.method === 'POST' && request.headers.get('origin') !== config.origin) {
    return adminJson({ ok: false, error: 'Cross-origin request rejected' }, 403);
  }
  if (path === '/admin/logout') {
    if (request.method !== 'GET' && request.method !== 'POST') return methodNotAllowed('GET, POST');
    return redirect(`${config.origin}/cdn-cgi/access/logout`);
  }
  if (path === '/admin') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return renderDashboard(await readStatsSnapshot(env), statsStorageConfigured(env), config.origin);
  }
  if (path === '/admin/stats') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return adminJson({ stats_enabled: statsStorageConfigured(env), ...(await readStatsSnapshot(env)) });
  }
  if (path === '/admin/reset-stats') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const stats = await resetStats(env);
    if ((request.headers.get('accept') ?? '').includes('text/html')) return redirect(`${config.origin}/`);
    return adminJson({ ok: true, stats_enabled: statsStorageConfigured(env), ...stats });
  }
  return adminJson({ ok: false, error: 'Not found' }, 404);
}

function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store' } });
}

function methodNotAllowed(allow: string): Response {
  return json({ ok: false, error: 'Method not allowed' }, 405, { allow });
}

function adminJson(body: unknown, status = 200): Response {
  return json(body, status, { 'cache-control': 'no-store' });
}

/* ----------------------------- HTML rendering ----------------------------- */

const STYLE = `
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 36rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; } .muted { opacity: .7; font-size: .9rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: .75rem; margin: 1.5rem 0; }
  .card { border: 1px solid #8884; border-radius: .6rem; padding: 1rem; }
  .n { font-size: 2rem; font-weight: 700; } .k { opacity: .7; font-size: .85rem; }
  button { font: inherit; padding: .5rem 1rem; border-radius: .5rem; border: 1px solid #8886; cursor: pointer; background: #8881; }
  input { font: inherit; padding: .5rem; border-radius: .5rem; border: 1px solid #8886; width: 100%; box-sizing: border-box; }
  form.inline { margin-top: 1.5rem; } .err { color: #c00; }
  .warn { border: 1px solid #b7791f88; background: #b7791f22; border-radius: .5rem; padding: .75rem; }
  .trend { margin: 1.5rem 0; } .trend-row { display: grid; grid-template-columns: 6.5rem 1fr 3rem; gap: .6rem; align-items: center; margin: .35rem 0; font-size: .8rem; }
  .bar-track { height: .65rem; background: #8882; border-radius: 999px; overflow: hidden; }
  .bar { height: 100%; background: currentColor; opacity: .55; border-radius: inherit; }
  button[disabled] { cursor: not-allowed; opacity: .55; }
`;

/** Confirm before the destructive reset. Static text: its CSP hash is computed from this exact string. */
const DASHBOARD_CONFIRM_SCRIPT = `
    var form = document.querySelector('form[data-confirm-reset]');
    if (form) form.addEventListener('submit', function (e) {
      if (!confirm('Reset all counters to zero? This cannot be undone.')) e.preventDefault();
    });
`;

async function renderDashboard(stats: StatsSnapshot, statsEnabled: boolean, origin: string): Promise<Response> {
  const card = (k: string, n: number) =>
    `<div class="card"><div class="n">${n.toLocaleString('en-US')}</div><div class="k">${escapeHtml(k)}</div></div>`;
  const storageWarning = statsEnabled
    ? ''
    : '<p class="warn">Stats storage is not configured. Bind a Cloudflare D1 database as <code>DB</code> and redeploy so counters can update.</p>';
  const resetDisabled = statsEnabled ? '' : ' disabled aria-disabled="true"';
  return html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>isitjunk · admin</title><style>${STYLE}</style></head>
<body>
  <h1>Is It Junk? — admin</h1>
  <p class="muted">Aggregate counters only. No message-level data is stored.</p>
  ${storageWarning}
  <div class="grid">
    ${card('Total processed', stats.total_processed)}
    ${card('Junk', stats.total_junk)}
    ${card('Not junk', stats.total_notjunk)}
    ${card('Uncertain', stats.total_uncertain)}
  </div>
  ${renderTrend(stats.history)}
  <form class="inline" method="post" action="${escapeHtml(origin)}/reset-stats" data-confirm-reset>
    <button type="submit"${resetDisabled}>Reset stats</button>
  </form>
  <p><a href="${escapeHtml(origin)}/cdn-cgi/access/logout">Log out</a></p>
<script>${DASHBOARD_CONFIRM_SCRIPT}</script>
</body></html>`, 200, undefined, { scriptHashes: [await scriptSha256(DASHBOARD_CONFIRM_SCRIPT)] });
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
