/**
 * Test helpers: a minimal in-memory D1 fake and an Env factory.
 *
 * The fake interprets only the lifetime/daily SQL and batch shapes stats.ts
 * emits. It is intentionally small — enough to exercise the stats and admin
 * code paths without a real database.
 */
import type { Env } from '../src/types';

type Row = {
  id: number;
  total_processed: number;
  total_junk: number;
  total_notjunk: number;
  total_uncertain: number;
};

type DailyRow = Omit<Row, 'id'> & { day: string };

export function fakeD1(seed?: Partial<Omit<Row, 'id'>>) {
  let row: Row | null = seed
    ? { id: 1, total_processed: 0, total_junk: 0, total_notjunk: 0, total_uncertain: 0, ...seed }
    : null;
  const daily = new Map<string, DailyRow>();
  const admitted = new Map<string, number>();

  function exec(sql: string, args: unknown[]): Row | DailyRow[] | null {
    if (/INSERT\s+OR\s+IGNORE\s+INTO\s+stats\b/i.test(sql)) {
      if (!row) row = { id: 1, total_processed: 0, total_junk: 0, total_notjunk: 0, total_uncertain: 0 };
      return null;
    }
    if (/INSERT\s+INTO\s+stats_daily/i.test(sql)) {
      const day = String(args[0]);
      const existing = daily.get(day);
      const bucket = sql.match(/ON\s+CONFLICT[\s\S]*?(total_(?:junk|notjunk|uncertain))\s*=\s*\1\s*\+\s*1/i)?.[1] as
        | 'total_junk'
        | 'total_notjunk'
        | 'total_uncertain'
        | undefined;
      if (existing) {
        existing.total_processed += 1;
        if (bucket) existing[bucket] += 1;
      } else {
        daily.set(day, {
          day,
          total_processed: 1,
          total_junk: Number(args[1]) || 0,
          total_notjunk: Number(args[2]) || 0,
          total_uncertain: Number(args[3]) || 0,
        });
      }
      return null;
    }
    if (/^\s*SELECT[\s\S]+FROM\s+stats_daily\s+WHERE\s+day\s*=\s*\?/i.test(sql)) {
      const found = daily.get(String(args[0]));
      return found ? [{ ...found }] : [];
    }
    if (/^\s*SELECT[\s\S]+FROM\s+stats_daily/i.test(sql)) {
      const limit = Number(args[0]) || 30;
      return [...daily.values()]
        .sort((a, b) => b.day.localeCompare(a.day))
        .slice(0, limit)
        .map((value) => ({ ...value }));
    }
    if (/^\s*SELECT[\s\S]+FROM\s+stats\b/i.test(sql)) {
      return row ? { ...row } : null;
    }
    if (/^\s*UPDATE\s+stats\b/i.test(sql)) {
      if (!row) row = { id: 1, total_processed: 0, total_junk: 0, total_notjunk: 0, total_uncertain: 0 };
      // Reset: `col = 0`
      const resets = [...sql.matchAll(/(\w+)\s*=\s*0\b/g)].map((m) => m[1]);
      for (const c of resets) if (c in row) (row as Record<string, number>)[c] = 0;
      // Increment: `col = col + 1`
      const incs = [...sql.matchAll(/(\w+)\s*=\s*\1\s*\+\s*1/g)].map((m) => m[1]);
      for (const c of incs) if (c in row) (row as Record<string, number>)[c] += 1;
      return null;
    }
    if (/^\s*DELETE\s+FROM\s+stats_daily/i.test(sql)) {
      daily.clear();
      return null;
    }
    return null;
  }

  function statement(sql: string, args: unknown[] = []) {
    return {
      bind(...bound: unknown[]) {
        return statement(sql, bound);
      },
      async run() {
        if (/INSERT INTO analysis_budget/i.test(sql)) {
          const day = String(args[0]);
          const count = admitted.get(day) ?? 0;
          const changes = count < Number(args[1]) ? 1 : 0;
          if (changes) admitted.set(day, count + 1);
          return { success: true, meta: { changes }, results: [] };
        }
        exec(sql, args);
        return { success: true, meta: {}, results: [], error: undefined };
      },
      async first<T = unknown>(): Promise<T | null> {
        const result = exec(sql, args);
        return (Array.isArray(result) ? result[0] : result) as T | null;
      },
      async all<T = Record<string, unknown>>() {
        const result = exec(sql, args);
        const results = Array.isArray(result) ? result : result ? [result] : [];
        return { success: true, results: results as T[], meta: {} };
      },
    };
  }

  const db = {
    prepare(sql: string) {
      return statement(sql);
    },
    async batch(statements: Array<{ run(): Promise<unknown> }>) {
      return Promise.all(statements.map((prepared) => prepared.run()));
    },
  };

  return {
    db: db as unknown as Env['DB'],
    peekBudget: () => Object.fromEntries(admitted),
    peek: () => (row ? { ...row } : null),
    peekDaily: () => [...daily.values()].sort((a, b) => a.day.localeCompare(b.day)).map((value) => ({ ...value })),
  };
}

/** Build an Env with a fake D1 and overridable fields. */
export function makeEnv(overrides: Partial<Env> = {}): Env {
  const { db } = fakeD1();
  return {
    DB: db,
    OPENROUTER_API_KEY: 'sk-or-test',
    ACCESS_TEAM_DOMAIN: 'test.cloudflareaccess.com',
    ACCESS_AUD: 'admin-audience',
    ADMIN_HOST: 'admin.example.com',
    ADMIN_EMAIL: 'admin@example.com',
    ...overrides,
  };
}
