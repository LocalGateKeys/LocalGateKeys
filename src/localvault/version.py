"""Component versions shared by the agent and native bridge."""
APP_VERSION = "0.4.10"
PROTOCOL_VERSION = 2
RELEASE_ID = "024"
BRIDGE_CONFIG_VERSION = 7
# Date (UTC, YYYY-MM-DD) this build was cut. The signed update check refuses a
# release manifest published more than 400 days before this date so that a
# frozen or replayed feed cannot hide newer releases indefinitely. Bump it
# together with APP_VERSION on every release.
BUILD_DATE = "2026-10-30"
