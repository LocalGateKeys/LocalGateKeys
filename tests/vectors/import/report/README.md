# Import undo vectors (contract section 6.1)

`undo.json`: undo the journal against `current_records` at `now`. `digest(record)` = lower-hex
SHA-256 of `canon(record)`. `expected_after_undo` lists live records in `current_records` order
(a restored record gets `updated_at = now`); trashed ids move to Recently deleted.
