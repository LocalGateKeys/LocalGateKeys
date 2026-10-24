#!/usr/bin/env bash
# The CI "swift" job (.github/workflows/ci.yml) on the Mac: the LGKCore package
# tests, then the app's test scheme on the newest available iPhone simulator.
# Usage: scripts/ci_local_mac.sh [--core-only]
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== swift test (LGKCore)"
swift test --package-path ios/LGKCore

[ "${1:-}" = "--core-only" ] && exit 0

echo "=== xcodegen"
command -v xcodegen >/dev/null || { echo "xcodegen missing: brew install xcodegen"; exit 1; }
(cd ios && xcodegen generate)

udid="$(xcrun simctl list devices available -j | python3 -c '
import json, re, sys
devices = json.load(sys.stdin)["devices"]
def version(runtime):
    m = re.search(r"iOS-(\d+)-(\d+)", runtime)
    return (int(m.group(1)), int(m.group(2))) if m else None
for runtime in sorted((r for r in devices if version(r)), key=version, reverse=True):
    phones = [d for d in devices[runtime] if d.get("isAvailable") and d["name"].startswith("iPhone")]
    if phones:
        print(phones[0]["udid"]); print(runtime, phones[0]["name"], file=sys.stderr); break
')"
[ -n "$udid" ] || { echo "No available iPhone simulator"; exit 1; }

echo "=== xcodebuild test (LocalGateKeys scheme)"
set -o pipefail
xcodebuild test -project ios/LocalGateKeys.xcodeproj -scheme LocalGateKeys \
  -destination "id=$udid" CODE_SIGNING_ALLOWED=NO
