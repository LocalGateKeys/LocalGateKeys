-- Browser checkout claims (audit L-2). D1 arbitrates which order a claim
-- belongs to; the licences themselves stay in KV (LICENSES).
--
-- claim      PRIMARY KEY: one order per claim. The Worker inserts with
--            ON CONFLICT DO NOTHING and reads the row back, so the first
--            order to insert wins atomically and a duplicate delivery of the
--            same order reads back its own row (idempotent).
-- order_key  UNIQUE: an order binds at most one claim.
CREATE TABLE IF NOT EXISTS claims (
  claim TEXT PRIMARY KEY,
  order_key TEXT NOT NULL UNIQUE,
  licence_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
