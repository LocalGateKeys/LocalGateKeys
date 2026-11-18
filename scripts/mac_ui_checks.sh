#!/usr/bin/env bash
# Mac app UI checks (ios/MacUITests). The app is built with a separate bundle prefix, so the app under test has its
# own container and Keychain and never opens the installed LocalGateKeys' vault. Needs macOS automation mode
# (`sudo automationmodetool enable-automationmode-without-authentication`, once).
# Usage: scripts/mac_ui_checks.sh [test class or class/test ...]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../ios"
ONLY=()
for t in "${@:-MacChecksUITests}"; do ONLY+=("-only-testing:LocalGateKeysMacUITests/$t"); done
OUT="$(mktemp -d)"
# LGK_MAC_UI_DD=<folder> reuses one derived-data folder between runs (faster rebuilds); the default is a fresh one.
DD="${LGK_MAC_UI_DD:-$OUT/dd}"
# The app groups are team-prefixed here (`<TEAM>.app.localgatekeys.uitest.localgatekeys`), not `group.…`: the uitest
# App IDs' provisioning profile carries no App Groups (they are not registered in the developer portal), and macOS then
# keeps a `group.…` suite's UserDefaults in memory only, so every setting was back to its default after a relaunch.
# Team-prefixed groups need no profile entry on the Mac. The shipping build keeps its registered `group.…` ids.
TEST_RUNNER_LGK_MAC_UI_CHECKS=1 xcodebuild test -project LocalGateKeys.xcodeproj -scheme LocalGateKeysMacUITests \
  -destination 'platform=macOS' -derivedDataPath "$DD" -resultBundlePath "$OUT/result.xcresult" \
  BUNDLE_PREFIX=app.localgatekeys.uitest -allowProvisioningUpdates \
  'LGK_APP_GROUP=$(TeamIdentifierPrefix)$(BUNDLE_PREFIX).localgatekeys' \
  'LGK_SAFARI_APP_GROUP=$(TeamIdentifierPrefix)$(BUNDLE_PREFIX).localgatekeys.safari' \
  "${ONLY[@]}" >"$OUT/test.log" 2>&1 || true
grep -E "Test Case .* (passed|failed|skipped)|error:|MAC-CHECK" "$OUT/test.log" | sed 's/^/  /' || true
if grep -q "Timed out while enabling automation mode" "$OUT/test.log"; then
  echo "FAILED: macOS automation mode is off. Run once: sudo automationmodetool enable-automationmode-without-authentication"
  exit 1
fi
grep -q "TEST SUCCEEDED" "$OUT/test.log" && echo "PASSED" || { echo "FAILED (log: $OUT/test.log)"; exit 1; }
echo "Screenshots: $OUT/result.xcresult"
echo "Log: $OUT/test.log"
