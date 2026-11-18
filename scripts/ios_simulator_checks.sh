#!/usr/bin/env bash
# Simulator checks that need Face ID matched from the Mac while the UI tests wait (PENDING sub-plan 06):
#   ShortcutsCopyCodeUITests: Shortcuts "Copy code" offers only the pinned code; then the clipboard must hold a code.
#   WidgetCodesUITests: the "Pinned codes" widget on the home screen shows the app's code and changes every 30 s.
#   SafariShieldUITests: on the local page (scripts/safari_test_page, served here over HTTPS on 127.0.0.1:$LGK_SAFARI_PORT, default 8765), the saved
#     site gets the save prompt and its lookalike 1oginlab.localhost the "Is this the right site?" guard.
#   SafariToolbarUITests: the extension's toolbar popup on the same page (site, hint, waiting count, per-site switch).
#   SafariFillMarkerUITests: on the same page, a saved login typed by hand gets the save prompt, the same login filled
#     by LocalGateKeys AutoFill gets none, and after the marker's 20 seconds a typed one gets it again.
# Usage: scripts/ios_simulator_checks.sh [simulator-udid] [test class...]
# Environment: LGK_SAFARI_PORT (default 8765) when that port is taken on this Mac; LGK_DERIVED_DATA to reuse a build.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../ios"
UDID="${1:-$(xcrun simctl list devices booted | grep -m1 -oE 'iPhone[^(]*\(([0-9A-F-]{36})\)' | grep -oE '[0-9A-F-]{36}')}"
[ -n "$UDID" ] || { echo "No booted iPhone simulator"; exit 1; }
shift || true
CLASSES=("${@:-ShortcutsCopyCodeUITests WidgetCodesUITests SafariShieldUITests SafariToolbarUITests SafariFillMarkerUITests}")
OUT="$(mktemp -d)"
PORT="${LGK_SAFARI_PORT:-8765}"
DD="${LGK_DERIVED_DATA:-$OUT/dd}"
echo "Logs and screenshots: $OUT"
xcrun simctl spawn "$UDID" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit.enrollmentChanged
( while true; do xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit_Sim.pearl.match; sleep 2; done ) &
LOOP=$!
# The app and the extension accept http only on localhost itself, so the test page is served over HTTPS with a
# throwaway test CA that only this simulator trusts.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=LocalGateKeys UI test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$OUT/ca.key" -out "$OUT/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=loginlab.localhost" -keyout "$OUT/site.key" -out "$OUT/site.csr" >/dev/null 2>&1
printf "subjectAltName=DNS:loginlab.localhost,DNS:1oginlab.localhost\nextendedKeyUsage=serverAuth\n" >"$OUT/site.ext"
openssl x509 -req -in "$OUT/site.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial -days 2 \
  -extfile "$OUT/site.ext" -out "$OUT/site.pem" >/dev/null 2>&1
xcrun simctl keychain "$UDID" add-root-cert "$OUT/ca.pem"
python3 "$HERE/safari_test_page/serve.py" "$OUT/site.pem" "$OUT/site.key" "$PORT" >"$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $LOOP $SERVER 2>/dev/null || true' EXIT
STATUS=0
# One run per class: the app clears a copied code after the clipboard expiry, so the clipboard is checked right
# after the Shortcuts test.
for c in ${CLASSES[@]}; do
  echo -n "not-a-code" | xcrun simctl pbcopy "$UDID"
  if ! TEST_RUNNER_LGK_FACEID_LOOP=1 TEST_RUNNER_LGK_SAFARI_PORT="$PORT" xcodebuild test -project LocalGateKeys.xcodeproj -scheme LocalGateKeysUITests \
      -destination "id=$UDID" -derivedDataPath "$DD" -resultBundlePath "$OUT/$c.xcresult" \
      "-only-testing:LocalGateKeysUITests/$c" >"$OUT/$c.log" 2>&1; then
    grep -E 'error:' "$OUT/$c.log" || tail -20 "$OUT/$c.log"; echo "FAILED: $c (log: $OUT/$c.log)"; STATUS=1; continue
  fi
  if [ "$c" = ShortcutsCopyCodeUITests ]; then
    CLIP="$(xcrun simctl pbpaste "$UDID")"
    if [[ "$CLIP" =~ ^[0-9]{6,8}$ ]]; then
      echo "PASSED: $c (only the pinned code offered; the clipboard holds a ${#CLIP}-digit code)"
    else
      echo "FAILED: $c: the clipboard does not hold a code after Copy code"; STATUS=1
    fi
  else
    echo "PASSED: $c"
  fi
done
echo "Logs and screenshots: $OUT"
exit $STATUS
