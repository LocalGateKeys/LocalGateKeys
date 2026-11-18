# Privacy proof vectors (contract section 5, version 2)

Generated with Python's Ed25519 (deterministic) and device A of `tests/vectors/sync/identities.json`
(TEST ONLY keys). Signed bytes = UTF-8 `localgatekeys|privacy-proof|v2|` + `canon(D)`, where D is the
whole document with only `signature.value` removed (so `signature.alg`, `device_id` and `public_key`
are signed). Fingerprint = first 8 bytes of SHA-256 of the raw public key, hex.

- `signed.json`: `unsigned_document`, `signed_body` (D), `signed_bytes_hex`, `signature`,
  `fingerprint`, and the full `signed_document` (verifies `valid`).
- `unsigned.json`: `document` with `signature: null` verifies `unsigned`.
- `rejected/*.json`: raw proof files; each verifies `invalid`: tampered fact, signed without the
  prefix, duplicate key, extra top-level key, a version-1 file signed with the version-1 rule,
  version 3, `device_id` changed after signing, and signed bytes that leave out `signature`
  (the version-1 rule with the v2 prefix).
