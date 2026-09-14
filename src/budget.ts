import type { Env } from './types';

/** Only UTC day and aggregate admitted attempts are stored, never message identifiers. */
export const BUDGET_SCHEMA = `CREATE TABLE IF NOT EXISTS analysis_budget (
  day TEXT PRIMARY KEY,
  started INTEGER NOT NULL DEFAULT 0 CHECK (started >= 0)
)`;

/** One SQL write reserves admission before either paid call; failures are not refunded. */
export async function reserveAnalysis(env: Env, limit: number, now = new Date()): Promise<boolean> {
  if (!env.DB || !Number.isSafeInteger(limit) || limit <= 0) return false;
  try {
    const day = now.toISOString().slice(0, 10);
    const schema = await env.DB.prepare(BUDGET_SCHEMA).run();
    if (!schema.success) return false;
    const result = await env.DB.prepare(`INSERT INTO analysis_budget (day, started)
      VALUES (?, 1)
      ON CONFLICT(day) DO UPDATE SET started = started + 1
      WHERE started < ?`).bind(day, limit).run();
    return result.success && result.meta.changes === 1;
  } catch {
    console.error('Analysis budget unavailable; skipping analysis.');
    return false;
  }
}
