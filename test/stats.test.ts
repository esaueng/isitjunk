import { describe, it, expect } from 'vitest';
import {
  ZERO_STATS,
  bucketFor,
  normalizeStats,
  readDailyStats,
  readStats,
  readStatsSnapshot,
  recordAnalysis,
  resetStats,
  statsStorageConfigured,
} from '../src/stats';
import { fakeD1, makeEnv } from './helpers';

describe('bucketFor', () => {
  it('maps "No…" to not-junk, "Yes…" to junk, else uncertain', () => {
    expect(bucketFor('No, Not Junk')).toBe('total_notjunk');
    expect(bucketFor("Yes, it's Junk")).toBe('total_junk');
    expect(bucketFor('Uncertain')).toBe('total_uncertain');
    expect(bucketFor(null)).toBe('total_uncertain');
    expect(bucketFor('')).toBe('total_uncertain');
  });
});

describe('normalizeStats', () => {
  it('coerces missing/negative/non-numeric values to safe integers', () => {
    expect(normalizeStats(null)).toEqual(ZERO_STATS);
    expect(
      normalizeStats({ total_processed: '5', total_junk: -3, total_notjunk: 2.9, total_uncertain: 'x' }),
    ).toEqual({ total_processed: 5, total_junk: 0, total_notjunk: 2, total_uncertain: 0 });
  });
});

describe('recordAnalysis (D1)', () => {
  it('reports whether the D1 stats store is configured', () => {
    expect(statsStorageConfigured(makeEnv())).toBe(true);
    expect(statsStorageConfigured(makeEnv({ DB: undefined }))).toBe(false);
  });

  it('increments exactly one bucket plus total_processed', async () => {
    const { db, peek, peekDaily } = fakeD1();
    const env = makeEnv({ DB: db });

    await recordAnalysis(env, "Yes, it's Junk", new Date('2026-07-18T23:59:59Z'));
    await recordAnalysis(env, 'No, Not Junk', new Date('2026-07-19T00:00:00Z'));
    await recordAnalysis(env, 'Uncertain', new Date('2026-07-19T12:00:00Z'));
    await recordAnalysis(env, "Yes, it's Junk", new Date('2026-07-19T23:59:59Z'));

    expect(peek()).toMatchObject({
      total_processed: 4,
      total_junk: 2,
      total_notjunk: 1,
      total_uncertain: 1,
    });
    expect(peekDaily()).toEqual([
      { day: '2026-07-18', total_processed: 1, total_junk: 1, total_notjunk: 0, total_uncertain: 0 },
      { day: '2026-07-19', total_processed: 3, total_junk: 1, total_notjunk: 1, total_uncertain: 1 },
    ]);
  });

  it('returns bounded daily history oldest to newest and keeps lifetime fields compatible', async () => {
    const { db } = fakeD1();
    const env = makeEnv({ DB: db });
    await recordAnalysis(env, "Yes, it's Junk", new Date('2026-07-17T12:00:00Z'));
    await recordAnalysis(env, 'No, Not Junk', new Date('2026-07-18T12:00:00Z'));
    await recordAnalysis(env, 'Uncertain', new Date('2026-07-19T12:00:00Z'));

    expect((await readDailyStats(env, 2)).map((row) => row.day)).toEqual(['2026-07-18', '2026-07-19']);
    await expect(readStatsSnapshot(env, 2)).resolves.toMatchObject({
      total_processed: 3,
      history: [
        { day: '2026-07-18', total_processed: 1 },
        { day: '2026-07-19', total_processed: 1 },
      ],
    });
  });

  it('reads zeros before any analysis', async () => {
    const env = makeEnv();
    expect(await readStats(env)).toEqual(ZERO_STATS);
  });

  it('self-heals on a fresh DB (records without a pre-seeded row)', async () => {
    const { db, peek } = fakeD1(); // no seed: table/row absent
    const env = makeEnv({ DB: db });
    await recordAnalysis(env, "Yes, it's Junk");
    expect(peek()).toMatchObject({ total_processed: 1, total_junk: 1 });
  });

  it('is a no-op (zeros, no throw) when no store is bound', async () => {
    const env = makeEnv({ DB: undefined });
    await expect(recordAnalysis(env, "Yes, it's Junk")).resolves.toBeUndefined();
    expect(await readStats(env)).toEqual(ZERO_STATS);
    expect(await resetStats(env)).toEqual(ZERO_STATS);
  });

  it('resets all counters to zero', async () => {
    const { db, peek, peekDaily } = fakeD1({ total_processed: 9, total_junk: 4, total_notjunk: 3, total_uncertain: 2 });
    const env = makeEnv({ DB: db });
    await recordAnalysis(env, 'Uncertain', new Date('2026-07-19T12:00:00Z'));
    expect(await resetStats(env)).toEqual(ZERO_STATS);
    expect(peek()).toMatchObject(ZERO_STATS);
    expect(peekDaily()).toEqual([]);
  });
});
