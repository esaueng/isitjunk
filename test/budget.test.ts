import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { reserveAnalysis } from '../src/budget';
import { maxAnalysesPerDay } from '../src/config';
import { recordAnalysis, resetStats } from '../src/stats';
import { makeEnv } from './helpers';

const databases: DatabaseSync[] = [];
afterEach(() => { databases.forEach((db) => db.close()); databases.length = 0; vi.restoreAllMocks(); });

/** Execute the production SQL in real SQLite, not a regex imitation of admission. */
function database() {
  const sqlite = new DatabaseSync(':memory:');
  databases.push(sqlite);
  function prepare(sql: string, args: SQLInputValue[] = []) {
    return {
      bind: (...bound: SQLInputValue[]) => prepare(sql, bound),
      async run() {
        const result = sqlite.prepare(sql).run(...args);
        return { success: true, meta: { changes: Number(result.changes) }, results: [] };
      },
    };
  }
  const db = { prepare, batch: (statements: ReturnType<typeof prepare>[]) => Promise.all(statements.map((s) => s.run())) };
  return { sqlite, env: makeEnv({ DB: db as unknown as D1Database }) };
}

describe('atomic analysis admission', () => {
  it('admits exactly the daily allowance under concurrent reservations', async () => {
    const { sqlite, env } = database();
    const now = new Date('2026-09-14T12:00:00Z');
    const results = await Promise.all(Array.from({ length: 50 }, () => reserveAnalysis(env, 3, now)));
    expect(results.filter(Boolean)).toHaveLength(3);
    expect(sqlite.prepare('SELECT started FROM analysis_budget').get()?.started).toBe(3);
  });

  it('does not replenish reservations when verdict statistics are reset; a new UTC day gets its own allowance', async () => {
    const { env } = database();
    const today = new Date('2026-09-14T23:59:59Z');
    expect(await reserveAnalysis(env, 1, today)).toBe(true);
    await recordAnalysis(env, 'Uncertain', today);
    await resetStats(env);
    expect(await reserveAnalysis(env, 1, today)).toBe(false);
    expect(await reserveAnalysis(env, 1, new Date('2026-09-15T00:00:00Z'))).toBe(true);
  });

  it('fails closed without storage or when a write fails', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(await reserveAnalysis(makeEnv({ DB: undefined }), 2)).toBe(false);
    const { sqlite, env } = database();
    sqlite.exec('CREATE TABLE analysis_budget (wrong_column TEXT)');
    expect(await reserveAnalysis(env, 2)).toBe(false);
  });

  it.each(['0', '-1', 'NaN', '1.5', 'Infinity'])('does not disable the budget for malformed setting %s', (value) => {
    expect(() => maxAnalysesPerDay(makeEnv({ MAX_ANALYSES_PER_DAY: value }))).toThrow();
  });

  it('uses a finite default when the override is absent', () => {
    expect(maxAnalysesPerDay(makeEnv())).toBe(200);
  });
});
