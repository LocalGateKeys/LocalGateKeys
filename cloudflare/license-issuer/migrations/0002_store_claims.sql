-- Store purchases (App Store, Google Play) that were given a desktop licence.
-- One licence per original purchase: the App Store originalTransactionId or
-- the Play orderId is the primary key, so a repeat claim (Restore, reinstall,
-- a second device) reads back the same licence.
--
-- revoked      1 once a refund or revocation arrived. A refund that arrives
--              before any claim inserts a row with no licence, so a later
--              claim answers 403 instead of issuing.
-- licence_id   NULL only for such a refund-before-claim row.
CREATE TABLE IF NOT EXISTS appstore_claims (
  original_id TEXT PRIMARY KEY,
  licence_id TEXT,
  licence_text TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS play_claims (
  original_id TEXT PRIMARY KEY,
  licence_id TEXT,
  licence_text TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
