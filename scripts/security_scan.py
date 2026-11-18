#!/usr/bin/env python3
"""Dependency and source security scanners with one shared ignore list.

  python scripts/security_scan.py                 # pip-audit, npm audit, bandit
  python scripts/security_scan.py --only pip,bandit
  python scripts/security_scan.py --offline       # skip the steps that need the network

Steps (the same ones run by scripts/ci_local.ps1 and the CI "security" job):
  pip     pip-audit on requirements.lock.txt, requirements-dev.lock.txt and
          requirements-build.lock.txt (hash-pinned, so no resolver run). pip-audit
          reports no severity, so every known vulnerability not in the ignore
          list fails the step.
  npm     npm audit --audit-level=high for each npm project that has a lockfile.
          Production dependencies only (--omit=dev), except projects marked
          "bundled" below, whose devDependencies are compiled into shipped output.
  bandit  bandit -ll over src/localvault. HIGH severity fails; MEDIUM is listed
          but advisory (the codebase is on the ruff S rules for those).

Accepted findings go in scripts/security_ignore.txt, one per line:
  <pip|npm|bandit> <id> <reason, required>
where <id> is a vulnerability id or alias (PYSEC-..., GHSA-..., CVE-...) for pip
and npm, and a bandit test id (B324) or test id plus file (B324:src/localvault/x.py).
Exit code 0 only when nothing unignored is at or above the gating severity.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IGNORE_FILE = ROOT / "scripts" / "security_ignore.txt"
PIP_LOCKS = ["requirements.lock.txt", "requirements-dev.lock.txt", "requirements-build.lock.txt"]
# (directory, bundled). "bundled": devDependencies end up in the shipped output
# (the web UI is compiled by vite/svelte into src/localvault/assets/ui), so they
# are audited too. The extension (browser-extension/) and website/ have no
# package.json and no npm dependencies, so there is nothing to audit there.
NPM_PROJECTS = [
    (".", False),
    ("webui", True),
    ("cloudflare/license-issuer", False),
    ("cloudflare/update-feed", False),
]
GATING_NPM = {"high", "critical"}


def load_ignores() -> dict[str, dict[str, str]]:
    ignores: dict[str, dict[str, str]] = {"pip": {}, "npm": {}, "bandit": {}}
    if not IGNORE_FILE.exists():
        return ignores
    for number, raw in enumerate(IGNORE_FILE.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or parts[0] not in ignores:
            raise SystemExit(f"{IGNORE_FILE.name}:{number}: expected '<pip|npm|bandit> <id> <reason>', got: {raw!r}")
        ignores[parts[0]][parts[1].upper()] = parts[2]
    return ignores


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def scan_pip(ignores: dict[str, str]) -> tuple[int, list[str]]:
    failures: list[str] = []
    for lock in PIP_LOCKS:
        proc = run([sys.executable, "-m", "pip_audit", "-r", lock, "--require-hashes", "--disable-pip",
                    "--progress-spinner", "off", "--format", "json"], ROOT)
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            failures.append(f"{lock}: pip-audit did not return JSON (exit {proc.returncode}): {proc.stderr.strip()[-300:]}")
            continue
        checked = 0
        for dep in data.get("dependencies", []):
            checked += 1
            for vuln in dep.get("vulns", []):
                ids = {vuln["id"].upper(), *(a.upper() for a in vuln.get("aliases", []))}
                hit = ids & ignores.keys()
                if hit:
                    print(f"  ignored  {lock}: {dep['name']} {dep['version']} {vuln['id']} ({ignores[next(iter(hit))]})")
                    continue
                fixes = ", ".join(vuln.get("fix_versions", [])) or "none"
                failures.append(f"{lock}: {dep['name']} {dep['version']} {vuln['id']} (fix: {fixes})")
        print(f"  {lock}: {checked} packages checked")
    return len(failures), failures


def scan_npm(ignores: dict[str, str]) -> tuple[int, list[str]]:
    npm = shutil.which("npm")
    if not npm:
        return 1, ["npm was not found on PATH"]
    failures: list[str] = []
    for rel, bundled in NPM_PROJECTS:
        directory = ROOT / rel
        if not (directory / "package-lock.json").exists():
            print(f"  {rel}: no package-lock.json, skipped")
            continue
        cmd = [npm, "audit", "--json", "--audit-level=high"]
        if not bundled:
            cmd.append("--omit=dev")
        proc = run(cmd, directory)
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            failures.append(f"{rel}: npm audit did not return JSON (exit {proc.returncode}): {proc.stderr.strip()[-300:]}")
            continue
        if "error" in data:
            failures.append(f"{rel}: npm audit error: {data['error'].get('summary', data['error'])}")
            continue
        found = 0
        vulns = data.get("vulnerabilities", {})
        # A package flagged only "via" other packages inherits their findings: it is
        # accepted when every package it comes through is accepted (all the way down).
        accepted: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, vuln in vulns.items():
                if name in accepted:
                    continue
                via = vuln.get("via", [])
                if any(isinstance(v, dict) and not v.get("url") for v in via):
                    continue
                own = {v["url"].rsplit("/", 1)[-1].upper() for v in via if isinstance(v, dict)}
                inherited = {v for v in via if isinstance(v, str)}
                if (own or inherited) and own <= ignores.keys() and inherited <= accepted:
                    accepted.add(name)
                    changed = True
        for name, vuln in vulns.items():
            if vuln.get("severity") not in GATING_NPM:
                continue
            advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
            ids = {a["url"].rsplit("/", 1)[-1].upper() for a in advisories if a.get("url")}
            if name in accepted:
                print(f"  ignored  {rel}: {name} ({', '.join(sorted(ids)) or 'via accepted findings'})")
                continue
            if ids and ids <= ignores.keys():
                print(f"  ignored  {rel}: {name} ({', '.join(sorted(ids))})")
                continue
            found += 1
            failures.append(f"{rel}: {name} {vuln['severity']} {', '.join(sorted(ids)) or 'via ' + ', '.join(map(str, vuln.get('via', [])))}")
        scope = "all dependencies" if bundled else "production dependencies"
        print(f"  {rel}: {found} high/critical in {scope}")
    return len(failures), failures


def scan_bandit(ignores: dict[str, str]) -> tuple[int, list[str]]:
    proc = run([sys.executable, "-m", "bandit", "-r", "src/localvault", "-ll", "-q", "-f", "json"], ROOT)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return 1, [f"bandit did not return JSON (exit {proc.returncode}): {proc.stderr.strip()[-300:]}"]
    failures: list[str] = []
    medium = 0
    seen: set[tuple[str, str, int]] = set()
    for issue in data.get("results", []):
        path = issue["filename"].replace("\\", "/")
        key = (issue["test_id"], path, issue["line_number"])
        if key in seen:
            continue
        seen.add(key)
        test = issue["test_id"].upper()
        reason = ignores.get(test) or ignores.get(f"{test}:{path}".upper())
        label = f"{issue['test_id']} {path}:{issue['line_number']} {issue['issue_text'][:90]}"
        if reason:
            print(f"  ignored  {label} ({reason})")
        elif issue["issue_severity"] == "HIGH":
            failures.append(label)
        else:
            medium += 1
            print(f"  advisory (medium) {label}")
    print(f"  bandit: {len(failures)} high, {medium} medium (advisory)")
    return len(failures), failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", default="", help="comma-separated: pip, npm, bandit (default: all)")
    parser.add_argument("--offline", action="store_true", help="run only the steps that need no network (bandit)")
    args = parser.parse_args()
    wanted = {s.strip() for s in args.only.split(",") if s.strip()} or {"pip", "npm", "bandit"}
    unknown = wanted - {"pip", "npm", "bandit"}
    if unknown:
        raise SystemExit(f"Unknown step(s): {', '.join(sorted(unknown))}")
    if args.offline:
        wanted &= {"bandit"}
    ignores = load_ignores()
    total = 0
    for name, fn in (("pip", scan_pip), ("npm", scan_npm), ("bandit", scan_bandit)):
        if name not in wanted:
            continue
        print(f"== {name}")
        count, failures = fn(ignores[name])
        for failure in failures:
            print(f"  FAIL {failure}")
        total += count
    print(f"\n{'security scan FAILED' if total else 'security scan clean'}: {total} unignored finding(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
