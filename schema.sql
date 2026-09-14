-- D1 schema for isitjunk-email.
--
-- A single lifetime row plus UTC-day verdict and admission rows hold the only data this
-- service persists. No message-level data is ever stored.
--
-- Apply locally:   npm run db:init:local
-- Apply remotely:  npm run db:init:remote (uses ignored private deployment settings)

CREATE TABLE IF NOT EXISTS stats (
  id              INTEGER PRIMARY KEY,
  total_processed INTEGER NOT NULL DEFAULT 0,
  total_junk      INTEGER NOT NULL DEFAULT 0,
  total_notjunk   INTEGER NOT NULL DEFAULT 0,
  total_uncertain INTEGER NOT NULL DEFAULT 0
);

-- Seed the single row. The Worker also self-heals this via INSERT OR IGNORE.
INSERT OR IGNORE INTO stats (id, total_processed, total_junk, total_notjunk, total_uncertain)
VALUES (1, 0, 0, 0, 0);

CREATE TABLE IF NOT EXISTS stats_daily (
  day             TEXT PRIMARY KEY,
  total_processed INTEGER NOT NULL DEFAULT 0,
  total_junk      INTEGER NOT NULL DEFAULT 0,
  total_notjunk   INTEGER NOT NULL DEFAULT 0,
  total_uncertain INTEGER NOT NULL DEFAULT 0
);

-- Admission attempts are independent of resettable verdict statistics.
CREATE TABLE IF NOT EXISTS analysis_budget (
  day TEXT PRIMARY KEY,
  started INTEGER NOT NULL DEFAULT 0 CHECK (started >= 0)
);
