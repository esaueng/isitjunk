import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('..', import.meta.url));

/** Merge only deployment settings; arbitrary config cannot re-enable preview hosts. */
export function buildDeploymentConfig(base, settings) {
  const vars = settings?.vars;
  const host = vars?.ADMIN_HOST;
  if (!vars || !/^[a-z0-9.-]+$/.test(host ?? '') || !host.includes('.') ||
      !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(vars.ACCESS_TEAM_DOMAIN ?? '') ||
      !/^[a-f0-9]{64}$/.test(vars.ACCESS_AUD ?? '') ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(vars.ADMIN_EMAIL ?? '') ||
      host.endsWith('.example.com') || vars.ADMIN_EMAIL.endsWith('@example.com')) {
    throw new Error('Valid private admin Access settings are required.');
  }
  if (!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(settings.database_id ?? '') || /^0{8}-/.test(settings.database_id)) {
    throw new Error('A real deployment database ID is required.');
  }
  if (!Array.isArray(settings.routes) || !settings.routes.some((route) => route.pattern === host && route.custom_domain === true)) {
    throw new Error('The admin custom-domain route is required.');
  }
  return {
    ...base,
    main: '../src/index.ts',
    workers_dev: false,
    preview_urls: false,
    vars: { ...base.vars, ADMIN_HOST: host, ACCESS_TEAM_DOMAIN: vars.ACCESS_TEAM_DOMAIN,
      ACCESS_AUD: vars.ACCESS_AUD, ADMIN_EMAIL: vars.ADMIN_EMAIL },
    routes: settings.routes,
    d1_databases: [{ ...base.d1_databases[0], database_id: settings.database_id }],
  };
}

export async function readDeploymentSettings(env = process.env) {
  const settingsPath = env.DEPLOYMENT_SETTINGS_PATH || resolve(root, '.deployment/settings.json');
  try {
    const input = env.DEPLOYMENT_SETTINGS_JSON ?? await readFile(settingsPath, 'utf8');
    return JSON.parse(input);
  }
  catch { throw new Error('Private deployment settings are missing or invalid. See deployment.example.json.'); }
}

/** Build logs must not re-publish values removed from source configuration. */
export function redactDeploymentOutput(output, config) {
  const privateValues = [config.vars.ADMIN_HOST, config.vars.ACCESS_TEAM_DOMAIN,
    config.vars.ACCESS_AUD, config.vars.ADMIN_EMAIL, config.d1_databases[0].database_id,
    ...config.routes.flatMap((route) => [route.pattern, route.zone_name])]
    .filter(Boolean).sort((a, b) => b.length - a.length);
  let redacted = output;
  for (const value of privateValues) redacted = redacted.replaceAll(value, '[private]');
  // Wrangler abbreviates long binding values, so full-value matching alone
  // would leave part of the Access audience visible in its bindings table.
  redacted = redacted.replace(/\b(env\.(?:ADMIN_HOST|ACCESS_TEAM_DOMAIN|ACCESS_AUD|ADMIN_EMAIL))\s+\("[^"]*"\)/g,
    '$1 ("[private]")');
  // Cloudflare account IDs can also appear in API-error URLs.
  return redacted.replace(/\b[a-f0-9]{32}\b/gi, '[account-id]');
}

async function main() {
  const settings = await readDeploymentSettings();
  const base = JSON.parse(await readFile(resolve(root, 'wrangler.jsonc'), 'utf8'));
  const config = buildDeploymentConfig(base, settings);
  const configPath = resolve(root, '.deployment/wrangler.jsonc');
  await mkdir(dirname(configPath), { recursive: true, mode: 0o700 });
  await writeFile(configPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--prepare-only') {
    console.log('Private deployment configuration prepared.');
    return;
  }
  if (!['deploy', 'tail', 'd1'].includes(args[0]) && !(args[0] === 'versions' && args[1] === 'upload')) {
    throw new Error('Unsupported deployment command.');
  }
  const childEnv = { ...process.env };
  delete childEnv.DEPLOYMENT_SETTINGS_JSON;
  const tail = args[0] === 'tail';
  const child = spawnSync(process.execPath, [resolve(root, 'node_modules/wrangler/bin/wrangler.js'),
    ...args, '--config', configPath], { cwd: root, env: childEnv,
    stdio: tail ? 'inherit' : ['inherit', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (!tail) {
    if (child.stdout) process.stdout.write(redactDeploymentOutput(child.stdout, config));
    if (child.stderr) process.stderr.write(redactDeploymentOutput(child.stderr, config));
  }
  if (child.error) throw new Error('Wrangler could not start.');
  process.exitCode = child.status ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
