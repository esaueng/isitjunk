import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildDeploymentConfig, readDeploymentSettings, redactDeploymentOutput } from '../scripts/deployment.mjs';

const base = JSON.parse(readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
const settings = {
  vars: {
    ADMIN_HOST: 'admin.worker.test',
    ACCESS_TEAM_DOMAIN: 'test-team.cloudflareaccess.com',
    ACCESS_AUD: 'a'.repeat(64),
    ADMIN_EMAIL: 'operator@worker.test',
  },
  database_id: '11111111-2222-3333-4444-555555555555',
  routes: [{ pattern: 'admin.worker.test', custom_domain: true }],
};

describe('private deployment configuration', () => {
  it('loads private build settings without requiring a developer-local file', async () => {
    const result = await readDeploymentSettings({
      DEPLOYMENT_SETTINGS_JSON: JSON.stringify(settings),
      DEPLOYMENT_SETTINGS_PATH: '/nonexistent/private-deployment-settings.json',
    });
    expect(buildDeploymentConfig(base, result).d1_databases[0].database_id).toBe(settings.database_id);
  });

  it('rejects invalid build secrets without echoing their contents or falling back to a local file', async () => {
    await expect(readDeploymentSettings({ DEPLOYMENT_SETTINGS_JSON: '{private-invalid-value' }))
      .rejects.toThrow('Private deployment settings are missing or invalid. See deployment.example.json.');
  });

  it('redacts split-out private settings and account identifiers from Wrangler output', () => {
    const config = buildDeploymentConfig(base, settings);
    const accountId = '0123456789abcdef'.repeat(2);
    const output = `${Object.values(settings.vars).join('\n')}\nDB: ${settings.database_id}\nAPI /accounts/${accountId}/workers/scripts/isitjunk-email failed: 10181`;
    const redacted = redactDeploymentOutput(output, config);
    for (const value of [...Object.values(settings.vars), settings.database_id, accountId]) {
      expect(redacted.includes(value)).toBe(false);
    }
    expect(redacted).toContain('failed: 10181');
  });

  it('redacts abbreviated private binding values in Wrangler build logs', () => {
    const config = buildDeploymentConfig(base, settings);
    const abbreviated = settings.vars.ACCESS_AUD.slice(0, 36);
    const output = `env.ACCESS_AUD ("${abbreviated}...") Environment Variable`;
    expect(redactDeploymentOutput(output, config)).toBe('env.ACCESS_AUD ("[private]") Environment Variable');
  });

  it('rejects the public example instead of deploying placeholder settings', () => {
    const example = JSON.parse(readFileSync(new URL('../deployment.example.json', import.meta.url), 'utf8'));
    expect(() => buildDeploymentConfig(base, example)).toThrow();
  });

  it.each([
    undefined,
    { ...settings, database_id: base.d1_databases[0].database_id },
    { ...settings, database_id: '-'.repeat(36) },
    { ...settings, routes: [] },
    { ...settings, routes: [{ pattern: settings.vars.ADMIN_HOST, custom_domain: false }] },
    { ...settings, vars: { ...settings.vars, ACCESS_AUD: '' } },
  ])('fails closed for missing or invalid deployment settings %#', (invalid) => {
    expect(() => buildDeploymentConfig(base, invalid)).toThrow();
  });

  it('preserves runtime bindings while preventing private settings from enabling preview hosts', () => {
    const result = buildDeploymentConfig(base, {
      ...settings, workers_dev: true, preview_urls: true,
      vars: { ...settings.vars, MAX_ANALYSES_PER_DAY: '0', UNREVIEWED_SETTING: 'ignored' },
    });
    expect(result.workers_dev).toBe(false);
    expect(result.preview_urls).toBe(false);
    expect(result.main).toBe('../src/index.ts');
    expect(result.vars).toEqual({ ...base.vars, ...settings.vars });
    expect(result.send_email).toEqual(base.send_email);
    expect(result.d1_databases[0]).toEqual({ ...base.d1_databases[0], database_id: settings.database_id });
    expect(result.routes).toEqual(settings.routes);
  });
});
