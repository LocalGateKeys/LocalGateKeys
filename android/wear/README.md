# LocalGateKeys Wear OS tile (sub-plan 06, task 7)

Not built: waits for an owner decision on Play services in the phone app (2026-11-08).

To build it again: add `include(":wear")` to `android/settings.gradle.kts`, restore the phone-side Data Layer pieces
from commit 787fe29c and regenerate the Gradle verification metadata.
