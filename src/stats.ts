/**
 * Aggregate analysis tallies, stored in Cloudflare D1.
 *
 * The service persists only aggregate counters — lifetime and UTC-day integer
 * counters. No email content, addresses, subjects, scores, or per-message
 * history is ever written (see README). budget.ts owns separate admission counts.
 *
 * D1 is used instead of KV so a completed analysis increments lifetime and
 * daily totals in one transactional batch, avoiding the read-modify-write race
 * KV would have under concurrency.
 */
import type { DailyStatsRecord, Env, StatsRecord, StatsSnapshot } from './types';

export const ZERO_STATS: StatsRecord = {
  total_processed: 0,
  total_junk: 0,
  total_notjunk: 0,
  total_uncertain: 0,
};

/** The single stats row's primary key (one-row table). */
const ROW_ID = 1;
export const DEFAULT_HISTORY_DAYS = 30;
const MAX_HISTORY_DAYS = 90;

/** Does this Worker instance have the D1 binding needed to persist counters? */
export function statsStorageConfigured(env: Env): boolean {
  return Boolean(env.DB);
}

/** Coerce a value to a finite, non-negative integer (0 on failure). */
function toCount(value: unknown): number {
  const n = typeof value === 'string' ? Number(value) : (value as number);
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

/** Normalise an arbitrary (untrusted) stored value into a safe StatsRecord. */
export function normalizeStats(
  raw: Partial<Record<keyof StatsRecord, unknown>> | null | undefined,
): StatsRecord {
  return {
    total_processed: toCount(raw?.total_processed),
    total_junk: toCount(raw?.total_junk),
    total_notjunk: toCount(raw?.total_notjunk),
    total_uncertain: toCount(raw?.total_uncertain),
  };
}

/**
 * Decide which classification bucket a label increments.
 * Faithful to the n8n "Code in JavaScript" node:
 *   starts with "No"  → total_notjunk
 *   starts with "Yes" → total_junk
 *   otherwise         → total_uncertain   (incl. "Uncertain" and missing labels)
 */
export function bucketFor(label: string | null | undefined): keyof StatsRecord {
  const value = label ?? '';
  if (value.startsWith('No')) return 'total_notjunk';
  if (value.startsWith('Yes')) return 'total_junk';
  return 'total_uncertain';
}

/**
 * Module-level guard so the schema bootstrap runs at most once per isolate
 * rather than on every request.
 */
let schemaReady = false;

/**
 * Ensure the stats table AND its single row exist. Self-heals a fresh, empty D1
 * (so the service works even if schema.sql was never applied) and is idempotent.
 * Guarded so it issues its two statements only once per isolate.
 */
async function ensureSchema(db: D1Database): Promise<void> {
  if (schemaReady) return;
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS stats (
       id              INTEGER PRIMARY KEY,
       total_processed INTEGER NOT NULL DEFAULT 0,
       total_junk      INTEGER NOT NULL DEFAULT 0,
       total_notjunk   INTEGER NOT NULL DEFAULT 0,
       total_uncertain INTEGER NOT NULL DEFAULT 0
     )`,
  ).run();
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS stats_daily (
       day             TEXT PRIMARY KEY,
       total_processed INTEGER NOT NULL DEFAULT 0,
       total_junk      INTEGER NOT NULL DEFAULT 0,
       total_notjunk   INTEGER NOT NULL DEFAULT 0,
       total_uncertain INTEGER NOT NULL DEFAULT 0
     )`,
  ).run();
  await db.prepare(
    `INSERT OR IGNORE INTO stats
       (id, total_processed, total_junk, total_notjunk, total_uncertain)
     VALUES (?, 0, 0, 0, 0)`,
  )
    .bind(ROW_ID)
    .run();
  schemaReady = true;
}

/** Read the current tallies from D1 (zeroed if unset or if no store is bound). */
export async function readStats(env: Env): Promise<StatsRecord> {
  const db = env.DB;
  if (!db) return ZERO_STATS; // no store configured — stats disabled
  await ensureSchema(db);
  const row = await db
    .prepare(
      `SELECT total_processed, total_junk, total_notjunk, total_uncertain
         FROM stats WHERE id = ?`,
    )
    .bind(ROW_ID)
    .first<Partial<Record<keyof StatsRecord, unknown>>>();
  return normalizeStats(row);
}

/** Read a bounded UTC-day trend, oldest to newest, with aggregate values only. */
export async function readDailyStats(env: Env, days = DEFAULT_HISTORY_DAYS): Promise<DailyStatsRecord[]> {
  const db = env.DB;
  if (!db) return [];
  await ensureSchema(db);
  const limit = Number.isFinite(days) ? Math.min(Math.max(Math.floor(days), 1), MAX_HISTORY_DAYS) : DEFAULT_HISTORY_DAYS;
  const result = await db
    .prepare(
      `SELECT day, total_processed, total_junk, total_notjunk, total_uncertain
         FROM stats_daily
        ORDER BY day DESC
        LIMIT ?`,
    )
    .bind(limit)
    .all<Partial<Record<keyof DailyStatsRecord, unknown>>>();
  return (result.results ?? [])
    .map(normalizeDailyStats)
    .filter((row): row is DailyStatsRecord => row !== null)
    .reverse();
}

/** Read the backward-compatible lifetime fields plus a bounded daily history. */
export async function readStatsSnapshot(env: Env, days = DEFAULT_HISTORY_DAYS): Promise<StatsSnapshot> {
  const totals = await readStats(env);
  const history = await readDailyStats(env, days);
  return { ...totals, history };
}

/**
 * Increment exactly one classification bucket AND total_processed for a
 * completed analysis, then update its UTC-day bucket in the same D1 batch.
 */
export async function recordAnalysis(
  env: Env,
  label: string | null | undefined,
  now: Date = new Date(),
): Promise<void> {
  const db = env.DB;
  if (!db) return; // no store configured — stats disabled, nothing to record
  await ensureSchema(db);
  // `bucket` is a keyof StatsRecord (one of the four fixed column names), never
  // user input, so interpolating it is safe. total_processed always increments.
  const bucket = bucketFor(label);
  const day = utcDay(now);
  const dailyValues = {
    total_junk: bucket === 'total_junk' ? 1 : 0,
    total_notjunk: bucket === 'total_notjunk' ? 1 : 0,
    total_uncertain: bucket === 'total_uncertain' ? 1 : 0,
  };
  await db.batch([
    db.prepare(
      `UPDATE stats
          SET total_processed = total_processed + 1,
              ${bucket} = ${bucket} + 1
        WHERE id = ?`,
    )
      .bind(ROW_ID),
    db.prepare(
      `INSERT INTO stats_daily
         (day, total_processed, total_junk, total_notjunk, total_uncertain)
       VALUES (?, 1, ?, ?, ?)
       ON CONFLICT(day) DO UPDATE SET
         total_processed = total_processed + 1,
         ${bucket} = ${bucket} + 1`,
    ).bind(day, dailyValues.total_junk, dailyValues.total_notjunk, dailyValues.total_uncertain),
  ]);
}

/** Reset all counters to zero. No-op (returns zeros) when no store is bound. */
export async function resetStats(env: Env): Promise<StatsRecord> {
  const db = env.DB;
  if (!db) return ZERO_STATS;
  await ensureSchema(db);
  await db.batch([
    db.prepare(
      `UPDATE stats
          SET total_processed = 0, total_junk = 0, total_notjunk = 0, total_uncertain = 0
        WHERE id = ?`,
    )
      .bind(ROW_ID),
    db.prepare('DELETE FROM stats_daily'),
  ]);
  return ZERO_STATS;
}

function normalizeDailyStats(
  raw: Partial<Record<keyof DailyStatsRecord, unknown>>,
): DailyStatsRecord | null {
  const day = typeof raw.day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(raw.day) ? raw.day : null;
  return day ? { day, ...normalizeStats(raw) } : null;
}

function utcDay(value: Date): string {
  const time = value.getTime();
  if (!Number.isFinite(time)) throw new Error('Invalid analysis timestamp');
  return value.toISOString().slice(0, 10);
}
