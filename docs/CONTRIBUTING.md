# Contributing

LocalGateKeys is a Windows local-first password manager written in Python
(Tk desktop app, Chromium native-messaging host) with a Manifest V3 browser
extension. This page is the development loop; the security model is in
[../SECURITY.md](../SECURITY.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Prerequisites

- Windows 10/11 (the desktop, named-pipe and Windows Hello code paths only run here)
- Python 3.12 or newer (CI runs 3.12 and 3.13)
- Node.js 20+ for the browser-extension tests
- Inno Setup 6 only if you build the installer

## Set up

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
```

Every third-party package comes from the hash-pinned lock; the project itself is
installed editable without dependencies so the lock stays authoritative.
`scripts\run_tests.ps1` does the same two steps before running pytest.

## The loop

| Step | Command | Notes |
|---|---|---|
| Lint | `.\.venv\Scripts\python.exe -m ruff check src tests scripts` | Rules `E F B S UP I W`; per-file ignores in `pyproject.toml`. Do not bulk-format `src/` in a PR that also changes behavior. |
| Types | `.\.venv\Scripts\python.exe -m mypy` | Strict on `vault`, `protocol`, `native_host`, `origin`, `pipe_transport`, `sync`; lenient elsewhere. Advisory in CI until clean. |
| Tests | `.\scripts\run_tests.ps1` or `.\.venv\Scripts\python.exe -m pytest` | `-p no:cacheprovider` is set in `pyproject.toml`; temp files go to `.pytest-tmp/` (absolute, gitignored). |
| Fuzz | `pytest -m fuzz` / skip with `-m "not fuzz"` | Seeded mutation fuzzing of the vault, backup, transfer, IPC frame and otpauth-migration parsers (~20 s, part of the default run). `LGK_FUZZ_ITERATIONS` scales it. |
| Coverage | `.\scripts\run_tests.ps1 -Coverage` | Writes `coverage.xml`; config under `[tool.coverage]`. |
| Extension | `npm ci` then `npm test` | `node --test` over `tests\*.cjs` and `tests\extension\*.test.cjs` (jsdom is the only dev dependency; nothing from `node_modules` ships). Plus `node --check browser-extension\*.js`. |
| Build smoke | `.\scripts\build_personal_installer.ps1 -SkipInstaller -OutputRoot ci-build` | Freezes both executables, runs `--check-build`, writes SBOM and manifest; no Inno Setup needed. |

Rules of thumb:

- Parsers of untrusted input raise only their module's documented error type
  (`VaultError`, `BackupError`, `TransferError`, `ProtocolError`, `TotpError`).
  The fuzz tests enforce this; when you fix an entry in `KNOWN_ISSUES`
  (`tests/fuzz/test_parsers_fuzz.py`), delete it in the same change.
- Never add a global keyboard hook, screen capture, process injection or
  clipboard polling. `tests/test_no_capture_primitives.py` and
  `scripts/verify_offline_release.ps1` scan for these.
- Tests must not touch `%LOCALAPPDATA%\LocalGateKeys` or a real browser
  profile; use `tmp_path`/`workspace_tmp` from `tests/conftest.py`.
- Windows-only tests are marked with `skipif(os.name != "nt")`; keep the
  portable core (vault, protocol, origin, totp, transfer, backup) runnable on Linux.

## Dependencies

Change ranges in `pyproject.toml`, then regenerate the locks on the oldest
supported interpreter:

```powershell
.\scripts\update_locks.ps1            # keep current pins where still valid
.\scripts\update_locks.ps1 -Upgrade   # move every package to its newest allowed version
```

Commit `pyproject.toml` and both `requirements*.lock.txt` together. Dependabot
opens weekly PRs for pip, npm and GitHub Actions.

## Pull requests

- One topic per PR; include the test that demonstrates the change.
- CI must be green: ruff, pytest on 3.12 and 3.13, Node tests, build smoke.
  mypy is advisory for now; do not add new errors to the strict modules.
- Add a line to `CHANGELOG.md` under *Unreleased*.
- Security-relevant changes (crypto, IPC, native host, extension messaging)
  need a note in `SECURITY.md` or `docs/ARCHITECTURE.md` explaining the
  threat-model impact.

## Releasing

Follow [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
