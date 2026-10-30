"""Manual, metadata-only release checks backed by a signed release manifest.

The feed at ``RELEASE_FEED_URL`` serves a *signed bundle*::

    {"manifest": {...}, "signature": {"alg": "Ed25519", "key_id": "...", "signature": "<base64>"}}

The signature is an Ed25519 signature over the canonical JSON of ``manifest``
(sorted keys, no whitespace, UTF-8). Only keys embedded in ``PUBLISHER_KEYS``
are trusted. The client verifies the signature, the manifest schema, an
anti-freeze window relative to the build date, and a monotonically increasing
``sequence`` persisted in the application data directory (rollback protection).

The client never downloads or executes anything. The only action it can take is
opening the HTTPS ``notes_url`` of the last *verified* manifest in a browser,
and only after the user clicks the button in the update-available dialog.

``RELEASE_FEED_URL`` points at the Cloudflare-hosted feed and ``PUBLISHER_KEYS``
holds the release key, so checks are live. See docs/UPDATES.md for the
publisher workflow.
See docs/UPDATES.md for the publisher workflow.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import json
import re
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import config, distribution
from .version import APP_VERSION, BUILD_DATE
from .i18n import t

# Fixed HTTPS URL of the signed bundle, served by the Cloudflare Worker in
# cloudflare/update-feed. Compiled into every client: never change it casually
# (see docs/UPDATES.md, "Hosting on Cloudflare"). 0.4.0 shipped with the
# lgk-updates.<account>.workers.dev address, switched off on 2026-10-24.
RELEASE_FEED_URL = "https://updates.localgatekeys.app/stable.json"
# Signed licence revocation list, served next to the release feed (same origin).
REVOCATIONS_URL = urljoin(RELEASE_FEED_URL, "/revocations.json")

# Trusted publisher Ed25519 public keys: {key_id: base64(raw 32-byte key)}.
# key_id is the first 8 bytes of SHA-256 over the raw public key, as hex.
# Generate with ``scripts/sign_release_manifest.py keygen`` on an offline
# machine and paste the printed values here. More than one entry may be
# present during key rotation. With no trusted key every check fails closed and
# the UI reports that update checks are not configured.
PUBLISHER_KEYS: dict[str, str] = {
    # Release key in use since 0.4.4 (2026-10-23); private half held offline by the
    # publisher (keygen --print-key). 0.4.0-0.4.3 trusted 2c85b99e44279161, which signed
    # the 0.4.0 feed; its private half was then lost.
    "6a892769c82386b3": "wQv4rd+J5MvV2EhSe8rovFFw+jeAWyq2tyfe9fXBwlM=",
}

REQUEST_TIMEOUT_SECONDS = 3.0
USER_AGENT = f"LocalGateKeys/{APP_VERSION}"
# Offline reminder: a build older than this many days (from BUILD_DATE) asks
# the user, without any network use, whether to check for updates. Declining
# snoozes the question for REMINDER_SNOOZE_DAYS.
STALE_BUILD_DAYS = 90
REMINDER_SNOOZE_DAYS = 30
MAX_MANIFEST_BYTES = 65536
# The revocation list is its own signed file; 10,000 ids of 31 characters need
# roughly 400 KB, so it gets a larger (still bounded) read limit.
MAX_REVOCATIONS_BYTES = 1024 * 1024
MAX_REVOCATION_IDS = 10000
# A manifest published more than this many days before BUILD_DATE is stale.
MAX_MANIFEST_AGE_DAYS = 400

MANIFEST_FORMAT = "localgatekeys-release-manifest"
MANIFEST_FORMAT_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
UPDATE_STATE_FILENAME = "update-state.json"
REVOCATIONS_FILENAME = "revocations.json"
# Kept next to ``license.lgklicense`` (see :func:`revocation_memory_path`).
REVOCATION_MEMORY_FILENAME = "license.revocations"
REVOCATIONS_FORMAT_VERSION = 1

_MANIFEST_FIELDS = frozenset(
    {
        "format",
        "version",
        "app_version",
        "published",
        "min_supported_version",
        "notes_url",
        "artifacts",
        "sequence",
    }
)
_ARTIFACT_FIELDS = frozenset({"name", "sha256", "size", "url"})
_SIGNATURE_FIELDS = frozenset({"alg", "key_id", "signature"})
_BUNDLE_FIELDS = frozenset({"manifest", "signature"})
_REVOCATION_FIELDS = frozenset({"format", "published", "revoked"})
_LICENSE_ID_PATTERN = re.compile(r"^lgk_[0-9A-HJKMNP-TV-Z]{26}$")

_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")
_ARTIFACT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Static, URL-free message used for every verification failure so that the UI
# never reveals feed contents or hosting details.
_VERIFY_FAILED = "updates.theReleaseManifestCouldNot"


class UpdateCheckError(ValueError):
    """A configured update feed could not be checked safely.

    ``str(error)`` is always a static message safe to show in the UI. The
    optional ``reason`` is a short diagnostic for logs and tests; it never
    contains feed data or URLs either.
    """

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ReleaseConfiguration:
    feed_url: str
    publisher_keys: Mapping[str, ed25519.Ed25519PublicKey]


@dataclass(frozen=True)
class UpdateResult:
    current_version: str
    latest_version: str
    notes_url: str = ""
    min_supported_version: str = "0.0.0"
    sequence: int = 0
    published: str = ""

    @property
    def is_newer(self) -> bool:
        return _parse_version(self.latest_version) > _parse_version(self.current_version)

    @property
    def is_unsupported(self) -> bool:
        """True when the publisher no longer supports the running version."""
        return _parse_version(self.current_version) < _parse_version(self.min_supported_version)


# The last manifest that passed every check in this process. ``open_release_page``
# opens only this verified notes_url; nothing from an unverified feed is kept.
_LAST_VERIFIED: UpdateResult | None = None


def release_configuration() -> ReleaseConfiguration | None:
    """Return the validated fixed configuration, or ``None`` until it exists.

    Both a feed URL and at least one trusted publisher key are required; with
    either missing the check is "not configured" and nothing touches the network.
    MSIX builds (Store or sideloaded) are never configured: the package is
    updated by the Store, see :func:`managed_update_channel`.
    """
    if not distribution.self_update_enabled():
        return None
    if not RELEASE_FEED_URL or not PUBLISHER_KEYS:
        return None
    return ReleaseConfiguration(
        feed_url=_validate_https_url(RELEASE_FEED_URL, configuration=True),
        publisher_keys=_load_publisher_keys(PUBLISHER_KEYS, verify_key_ids=True),
    )


def managed_update_channel() -> str | None:
    """Who updates this build when it is not the in-app check, or ``None``.

    The UI shows this instead of "not configured" for MSIX builds.
    """
    current = distribution.channel()
    if current == distribution.CHANNEL_STORE:
        return "Microsoft Store"
    if current == distribution.CHANNEL_SIDELOAD:
        return "the MSIX package it was installed from"
    return None


def build_age_days(today: date | None = None) -> int:
    """Days since this build was cut (``BUILD_DATE``); never negative."""
    today = today or datetime.now(UTC).date()
    return max(0, (today - date.fromisoformat(BUILD_DATE)).days)


def update_reminder_due(snoozed_until: str, today: date | None = None) -> bool:
    """Whether to remind the user that this build is old. Uses no network.

    ``snoozed_until`` is the ISO date stored when the user last declined; an
    empty or unreadable value means "not snoozed".
    """
    today = today or datetime.now(UTC).date()
    if build_age_days(today) < STALE_BUILD_DAYS:
        return False
    try:
        return today >= date.fromisoformat(snoozed_until)
    except (TypeError, ValueError):
        return True


def reminder_snooze_date(today: date | None = None) -> str:
    """ISO date to store when the user declines the reminder."""
    today = today or datetime.now(UTC).date()
    return (today + timedelta(days=REMINDER_SNOOZE_DAYS)).isoformat()


def update_state_path() -> Path:
    """Location of the persisted rollback-protection state (last sequence)."""
    return config.data_dir() / UPDATE_STATE_FILENAME


def check_for_updates(
    *,
    current_version: str = APP_VERSION,
    opener_factory: Callable[..., object] | None = None,
) -> UpdateResult | None:
    """Fetch, verify and compare the signed release manifest, if configured.

    Callers must gate this function on the user's strict-offline setting: with
    it on, call only after the user explicitly agreed to this one check. The
    function sends only an HTTP GET for the fixed feed URL. The only data it
    persists is the highest verified manifest ``sequence`` (rollback
    protection); feed contents are never written to disk.
    """
    global _LAST_VERIFIED
    config_ = release_configuration()
    if config_ is None:
        return None
    _LAST_VERIFIED = None
    _parse_version(current_version)
    raw = _fetch_feed(config_.feed_url, opener_factory)
    manifest = _verify_bundle(raw, config_.publisher_keys)
    _enforce_freshness(manifest["published"])
    _enforce_sequence(manifest["sequence"])
    result = UpdateResult(
        current_version=current_version,
        latest_version=manifest["app_version"],
        notes_url=manifest["notes_url"],
        min_supported_version=manifest["min_supported_version"],
        sequence=manifest["sequence"],
        published=manifest["published"],
    )
    _LAST_VERIFIED = result
    return result


def open_release_page() -> bool:
    """Open the HTTPS release notes page of the last verified manifest."""
    result = _LAST_VERIFIED
    if result is None:
        raise UpdateCheckError(t("updates.noVerifiedReleaseInformationIs"))
    url = _validate_https_url(result.notes_url)
    try:
        return bool(webbrowser.open(url, new=2))
    except (OSError, webbrowser.Error) as exc:
        raise UpdateCheckError(t("updates.theReleasePageCouldNot")) from exc


def canonical_json(value: object) -> bytes:
    """Canonical form signed by the publisher: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def _fetch_feed(
    feed_url: str,
    opener_factory: Callable[..., object] | None,
    max_bytes: int = MAX_MANIFEST_BYTES,
) -> bytes:
    opener_builder = opener_factory or urllib.request.build_opener
    origin = _origin(feed_url)
    opener = opener_builder(_SameOriginRedirectHandler(origin))
    # feed_url has already been validated as a fixed HTTPS URL.
    request = urllib.request.Request(  # noqa: S310
        feed_url,
        # Cloudflare rejects urllib's default "Python-urllib/x.y" agent as a
        # bot (error 1010), so identify as the app. Only the version is sent.
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        method="GET",
    )
    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
        with response:
            status = getattr(response, "status", None)
            if status is None:
                status = response.getcode()
            if status != 200:
                raise UpdateCheckError(t("updates.theReleaseFeedReturnedAn"))
            headers = getattr(response, "headers", {})
            content_length = headers.get("Content-Length") if hasattr(headers, "get") else None
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except (TypeError, ValueError) as exc:
                    raise UpdateCheckError(
                        t("updates.theReleaseManifestHasInvalid")
                    ) from exc
                if declared_size < 0:
                    raise UpdateCheckError(t("updates.theReleaseManifestHasInvalid"))
                if declared_size > max_bytes:
                    raise UpdateCheckError(t("updates.theReleaseManifestIsToo2"))
            raw = response.read(max_bytes + 1)
    except UpdateCheckError:
        raise
    except urllib.error.HTTPError as exc:
        # The host answered, so this is not a connectivity problem.
        exc.close()
        if exc.code == 404:
            raise UpdateCheckError(t("updates.noReleaseHasBeenPublished")) from exc
        raise UpdateCheckError(t("updates.theReleaseFeedReturnedAn")) from exc
    except (OSError, urllib.error.URLError, TimeoutError, http.client.HTTPException) as exc:
        raise UpdateCheckError(t("updates.theReleaseFeedCouldNot2")) from exc

    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise UpdateCheckError(t("updates.theReleaseManifestIsToo"))
    return raw


# ---------------------------------------------------------------------------
# Signature and schema verification
# ---------------------------------------------------------------------------


def _verify_bundle(
    raw: bytes, publisher_keys: Mapping[str, ed25519.Ed25519PublicKey]
) -> dict[str, object]:
    """Return the validated manifest after its signature checks out."""
    manifest = _verify_signed(raw, publisher_keys)
    validate_manifest(manifest)
    return manifest


def _verify_signed(
    raw: bytes, keys: Mapping[str, ed25519.Ed25519PublicKey]
) -> dict[str, object]:
    """Check the signed-bundle envelope and signature; return the unvalidated manifest."""
    publisher_keys = keys
    try:
        bundle = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, UpdateCheckError, RecursionError) as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="invalid-json") from exc
    if type(bundle) is not dict or set(bundle) != _BUNDLE_FIELDS:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="bundle-shape")
    manifest = bundle["manifest"]
    signature_block = bundle["signature"]
    if type(manifest) is not dict or type(signature_block) is not dict:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="bundle-shape")
    if set(signature_block) != _SIGNATURE_FIELDS:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="signature-shape")
    if signature_block["alg"] != SIGNATURE_ALGORITHM:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="signature-alg")
    key_id = signature_block["key_id"]
    if not isinstance(key_id, str) or key_id not in publisher_keys:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="unknown-key")
    signature = signature_block["signature"]
    if not isinstance(signature, str):
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="signature-encoding")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="signature-encoding") from exc
    if len(signature_bytes) != 64:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="signature-length")
    try:
        message = canonical_json(manifest)
    except (TypeError, ValueError) as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="canonicalisation") from exc
    try:
        publisher_keys[key_id].verify(signature_bytes, message)
    except InvalidSignature as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="bad-signature") from exc
    return manifest


def validate_manifest(manifest: object) -> None:
    """Enforce the exact manifest schema; raise ``UpdateCheckError`` otherwise."""
    if type(manifest) is not dict or set(manifest) != _MANIFEST_FIELDS:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="manifest-shape")
    if manifest["format"] != MANIFEST_FORMAT:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="manifest-format")
    if not _is_int(manifest["version"]) or manifest["version"] != MANIFEST_FORMAT_VERSION:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="manifest-version")
    _parse_version(manifest["app_version"], reason="app_version")
    _parse_version(manifest["min_supported_version"], reason="min_supported_version")
    _parse_published(manifest["published"])
    _validate_https_url(manifest["notes_url"], reason="notes_url")
    if not _is_int(manifest["sequence"]) or manifest["sequence"] < 0:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="sequence")
    artifacts = manifest["artifacts"]
    if type(artifacts) is not list:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="artifacts")
    for artifact in artifacts:
        if type(artifact) is not dict or set(artifact) != _ARTIFACT_FIELDS:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="artifact-shape")
        name = artifact["name"]
        if not isinstance(name, str) or _ARTIFACT_NAME_PATTERN.fullmatch(name) is None:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="artifact-name")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="artifact-sha256")
        if not _is_int(artifact["size"]) or artifact["size"] < 0:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="artifact-size")
        _validate_https_url(artifact["url"], reason="artifact-url")


def validate_revocations(manifest: object) -> None:
    """Enforce the exact revocation-list schema; raise ``UpdateCheckError`` otherwise."""
    if type(manifest) is not dict or set(manifest) != _REVOCATION_FIELDS:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="revocations-shape")
    if not _is_int(manifest["format"]) or manifest["format"] != REVOCATIONS_FORMAT_VERSION:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="revocations-format")
    _parse_published(manifest["published"])
    revoked = manifest["revoked"]
    if type(revoked) is not list or len(revoked) > MAX_REVOCATION_IDS:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="revocations-list")
    for license_id in revoked:
        if not isinstance(license_id, str) or _LICENSE_ID_PATTERN.fullmatch(license_id) is None:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="revocations-id")


def revocation_cache_path() -> Path:
    """Location of the verified revocation bundle cached for offline use."""
    return config.data_dir() / REVOCATIONS_FILENAME


def revocation_memory_path() -> Path:
    """Second copy of the newest verified revocation bundle, kept next to the licence file.

    Deleting ``revocations.json`` alone must not un-revoke a licence: this copy
    (still publisher-signed, so it cannot be edited, only removed) keeps every
    revocation this device has seen in force. Only a newer signed list replaces it.
    """
    return config.data_dir() / REVOCATION_MEMORY_FILENAME


def revocation_keys() -> dict[str, ed25519.Ed25519PublicKey] | None:
    """Publisher keys that verify revocation lists, or ``None`` when none are configured.

    Unlike :func:`release_configuration` this does not depend on the distribution
    channel: Store and sideloaded MSIX builds verify revocations too.
    """
    if not PUBLISHER_KEYS:
        return None
    return _load_publisher_keys(PUBLISHER_KEYS, verify_key_ids=True)


def revocation_feed_url() -> str | None:
    """HTTPS URL of the signed revocation list, or ``None`` when not configured."""
    if not RELEASE_FEED_URL or not PUBLISHER_KEYS:
        return None
    return urljoin(_validate_https_url(RELEASE_FEED_URL, configuration=True), "/revocations.json")


def _verified_revocations(raw: bytes, keys: Mapping[str, ed25519.Ed25519PublicKey]) -> dict:
    manifest = _verify_signed(raw, keys)
    validate_revocations(manifest)
    return manifest


def _load_verified(path: Path, keys: Mapping[str, ed25519.Ed25519PublicKey]) -> dict | None:
    try:
        return _verified_revocations(path.read_bytes(), keys)
    except (OSError, ValueError):
        return None


def _newest(*manifests: dict | None) -> dict | None:
    best: dict | None = None
    for manifest in manifests:
        if manifest is None:
            continue
        if best is None or _parse_published(manifest["published"]) > _parse_published(best["published"]):
            best = manifest
    return best


def cached_revocations() -> frozenset[str]:
    """Revoked licence ids from the newest verified local list, re-verified on every load.

    Both the cache (``revocations.json``) and its copy next to the licence are
    read; the newer signed list wins. When the cache is missing but the copy is
    there, the copy's revocations stay in force (the list cannot be refreshed,
    but nothing is un-revoked). When neither verifies the set is empty.
    """
    try:
        keys = revocation_keys()
        if keys is None:
            return frozenset()
        cache = _load_verified(revocation_cache_path(), keys)
        memory = _load_verified(revocation_memory_path(), keys)
        newest = _newest(memory, cache)
        if newest is None:
            return frozenset()
        if cache is not None and (
            memory is None or _parse_published(cache["published"]) > _parse_published(memory["published"])
        ):
            # Self-heal: a cache from before the copy existed (or a newer one) is copied next to the licence.
            try:
                config.atomic_write_json(revocation_memory_path(), json.loads(revocation_cache_path().read_bytes()))
            except (OSError, ValueError):  # noqa: S110 - retried at the next load
                pass
        return frozenset(newest["revoked"])
    except (OSError, ValueError):
        return frozenset()


def fetch_revocations(
    *, opener_factory: Callable[..., object] | None = None
) -> frozenset[str]:
    """Fetch, verify and cache the signed revocation list; return the revoked ids.

    On any failure (unreachable, bad signature, stale replay) the existing
    cache is left untouched and ``UpdateCheckError`` is raised. Does nothing
    when no feed or publisher key is configured. Runs on every distribution
    channel (MSIX builds included); callers gate it on strict offline mode.
    """
    url = revocation_feed_url()
    keys = revocation_keys()
    if url is None or keys is None:
        return frozenset()
    raw = _fetch_feed(url, opener_factory, MAX_REVOCATIONS_BYTES)
    manifest = _verified_revocations(raw, keys)
    # Replay protection: an older list must not replace a newer cached (or remembered) one.
    newest = _newest(_load_verified(revocation_cache_path(), keys), _load_verified(revocation_memory_path(), keys))
    if newest is not None and _parse_published(manifest["published"]) < _parse_published(newest["published"]):
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="revocations-rollback")
    value = json.loads(raw.decode("utf-8"))
    try:
        config.atomic_write_json(revocation_memory_path(), value)
        config.atomic_write_json(revocation_cache_path(), value)
    except OSError as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="state-write") from exc
    return frozenset(manifest["revoked"])


def _enforce_freshness(published: str) -> None:
    """Reject a manifest published long before this build (anti-freeze)."""
    published_at = _parse_published(published)
    build_day = date.fromisoformat(BUILD_DATE)
    build_at = datetime(build_day.year, build_day.month, build_day.day, tzinfo=UTC)
    if published_at < build_at - timedelta(days=MAX_MANIFEST_AGE_DAYS):
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="stale-manifest")


def _enforce_sequence(sequence: int) -> None:
    """Reject a manifest older than the highest one already verified (rollback)."""
    path = update_state_path()
    last_sequence = _read_last_sequence(path)
    if last_sequence is not None and sequence < last_sequence:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="sequence-rollback")
    if last_sequence is None or sequence > last_sequence:
        try:
            config.atomic_write_json(path, {"last_sequence": sequence})
        except OSError as exc:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="state-write") from exc


def _read_last_sequence(path: Path) -> int | None:
    try:
        state = config.read_json(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        # Unreadable state cannot be trusted either way; it is replaced on success.
        return None
    value = state.get("last_sequence")
    if not _is_int(value) or value < 0:
        return None
    return value


def _load_publisher_keys(
    keys: Mapping[str, str], *, verify_key_ids: bool
) -> dict[str, ed25519.Ed25519PublicKey]:
    import hashlib

    loaded: dict[str, ed25519.Ed25519PublicKey] = {}
    for key_id, encoded in keys.items():
        if not isinstance(key_id, str) or _KEY_ID_PATTERN.fullmatch(key_id) is None:
            raise UpdateCheckError("The embedded publisher key configuration is invalid.")
        if not isinstance(encoded, str):
            raise UpdateCheckError("The embedded publisher key configuration is invalid.")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UpdateCheckError("The embedded publisher key configuration is invalid.") from exc
        if len(raw) != 32:
            raise UpdateCheckError("The embedded publisher key configuration is invalid.")
        if verify_key_ids and hashlib.sha256(raw).digest()[:8].hex() != key_id:
            raise UpdateCheckError("The embedded publisher key configuration is invalid.")
        try:
            loaded[key_id] = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise UpdateCheckError("The embedded publisher key configuration is invalid.") from exc
    return loaded


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------


def _is_int(value: object) -> bool:
    return type(value) is int


def _parse_version(value: object, *, reason: str | None = None) -> tuple[int, int, int]:
    match = _VERSION_PATTERN.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        if reason is not None:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason=reason)
        raise UpdateCheckError("The release version must use the x.y.z format.")
    return tuple(int(part) for part in match.groups())


def _parse_published(value: object) -> datetime:
    """Parse an RFC 3339 timestamp with an explicit offset into UTC."""
    if not isinstance(value, str) or len(value) > 64:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="published")
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="published") from exc
    if "T" not in value or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise UpdateCheckError(t(_VERIFY_FAILED), reason="published")
    return parsed.astimezone(UTC)


def _validate_https_url(
    value: object, *, configuration: bool = False, reason: str | None = None
) -> str:
    def fail(message: str) -> UpdateCheckError:
        if configuration:
            return UpdateCheckError(message)
        return UpdateCheckError(t(_VERIFY_FAILED), reason=reason or "url")

    if not isinstance(value, str) or not value or len(value) > 2048:
        raise fail("The release URL configuration is invalid.")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise fail("Release URLs must be fixed HTTPS URLs without credentials or fragments.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise fail("The release URL configuration is invalid.") from exc
    if port == 0:
        raise fail("The release URL configuration is invalid.")
    return value


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(_validate_https_url(value, configuration=True))
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise UpdateCheckError("The release URL configuration is invalid.") from exc
    return (parsed.scheme.lower(), parsed.hostname.lower(), port)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateCheckError(t(_VERIFY_FAILED), reason="duplicate-field")
        result[key] = value
    return result


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int]) -> None:
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        if _origin(target) != self.allowed_origin:
            raise UpdateCheckError("The release feed redirected to a different origin.")
        return super().redirect_request(req, fp, code, msg, headers, target)
