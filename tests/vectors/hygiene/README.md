# Clean-up sweep vectors (contract section 3)

- `duplicates.json`: `findings(records, now, today)` = `expected` (all finding types). Types come in
  the order `same_login, same_account_other_password, same_site, same_item, not_changed_2y,
  expired`; groups of one type are ordered by their id lists; ids inside a group by `updated_at`
  desc, then id. An empty username can still be a `same_login` (same origin and password); it never
  makes a `same_site`.
- `expired.json`: the ids of the `expired` finding.
- `merge.json`: `merge(keeper, other, now)` = `expected`, or `error`. When the keeper has no notes the
  other's notes are taken as they are (no leading blank line). Fields neither side has stay absent.
  Web logins: `scope.urls` = the keeper's URL rows then the other's, deduplicated by `(url, match)`
  (rows = `scope.urls`, or `[{url: scope.origin, match: "exact_origin"}]` when there are none);
  `scope.origin` stays the keeper's; when nothing is added `scope` is left as the keeper had it.
