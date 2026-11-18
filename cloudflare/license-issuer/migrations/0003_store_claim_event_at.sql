-- When the last revoke / reinstate applied to a store purchase happened (ms
-- since the epoch: the refund date, or the signed date of a REFUND_REVERSED).
-- An older event that arrives later (a retried REFUND after its reversal) is
-- ignored. NULL for rows written before this column and for unrefunded claims.
ALTER TABLE appstore_claims ADD COLUMN event_at INTEGER;
ALTER TABLE play_claims ADD COLUMN event_at INTEGER;
