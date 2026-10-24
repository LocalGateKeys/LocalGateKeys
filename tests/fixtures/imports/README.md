# Import fixtures

Anonymised sample exports used by `tests/test_import_fixtures.py`. Every value
is invented: example.com/.test domains, the RFC 6238 demo TOTP secret
`JBSWY3DPEHPK3PXP` and the public test card numbers 4111 1111 1111 1111 and
5555 5555 5555 4444. The column names and JSON keys follow each vendor's
documented export format so the tests catch mapping regressions.

| File / folder | Source app and export option |
| --- | --- |
| `onepassword/export.data` | 1Password 8, *Export > 1PUX* (the zip is built by the tests) |
| `onepassword.csv` | 1Password 8, *Export > CSV* |
| `bitwarden.json` | Bitwarden, *Export vault > .json* |
| `bitwarden_protected.json` | Bitwarden, *Export vault > .json (Encrypted) > Password protected*; password `fixture export password` |
| `bitwarden_account_restricted.json` | Bitwarden, *.json (Encrypted) > Account restricted* (must be refused) |
| `bitwarden.csv` | Bitwarden, *Export vault > .csv* |
| `lastpass.csv` | LastPass, *Advanced options > Export* |
| `chrome.csv` | Chrome / Edge / Brave, *Passwords > Export passwords* |
| `edge_legacy.csv` | Older Edge / Chrome export without the `note` column |
| `firefox.csv` | Firefox, *Passwords > ... > Export passwords* |
| `safari.csv` | Safari, *File > Export > Passwords* |
| `keepassxc.csv` | KeePassXC, *Database > Export > CSV* |
| `keepass2.csv` | KeePass 2, *File > Export > KeePass CSV (1.x)* |
| `keepass.xml` | KeePass 2, *File > Export > KeePass XML (2.x)* |
| `protonpass/Proton Pass/data.json` | Proton Pass, *Settings > Export* without PGP (the zip is built by the tests) |
| `protonpass.csv` | Proton Pass, *Settings > Export > CSV* |
| `dashlane/*.csv` | Dashlane, *Settings > Export data > CSV* (the zip is built by the tests) |
