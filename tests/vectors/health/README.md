# Health vectors: port contract

`site_cases.json` is read by the Python test (`tests/test_health_site_cases.py`), the Swift test
(`ios/LGKCore/Tests/LGKCoreTests/VaultHealthSiteCasesTests.swift`) and the Kotlin test
(`android/app/src/test/.../security/VaultHealthSiteCasesTest.kt`). Every port must give the `expected` ids exactly.

- Registrable domain: Public Suffix List INCLUDING the private section (so `github.io` is a suffix and
  `someone.github.io` is its own site) with the default `*` rule (an unlisted suffix is its last label, so
  `shop.test` gives `shop.test`). Multi-label suffixes count (`www.login.example.co.uk` gives `example.co.uk`).
- `sites` keys and `passkey_domains` values are already registrable domains: they are looked up as given and are not
  normalised again.
- Loopback (never `http` findings): `localhost` and `*.localhost`, `127.0.0.0/8`, `::1`.
- Scheme and host compare case-insensitively (`HTTP://Shop.Test:8080/` is plain http on `shop.test`). Any port other
  than the scheme default is kept and does not change the result.
- A URL that does not parse as an http(s) URL is ignored: it adds no host and no finding.
- `no_2fa`: a login with no TOTP whose site supports `totp`. `passkey`: a login whose site supports `passkey` while
  no passkey item exists for that registrable domain. `http`: a login with any plain-http, non-loopback URL.
