"""Offline Pro licence: Ed25519-signed bundle verification, storage and status.

A licence problem never blocks start, unlock or vault access; ``status`` never
raises for bad on-disk data and only maps it to a state.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import enum
import hashlib
import json
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import config
from .updates import UpdateCheckError, _parse_published, _unique_object, canonical_json
from .version import APP_VERSION, BUILD_DATE
from .i18n import t

_log = logging.getLogger(__name__)

# key_id -> base64 raw 32-byte Ed25519 public key. Empty in development builds.
LICENSE_KEYS: dict[str, str] = {"9f76e21ed03c0482": "+H6c6pxA/QATXXY1RPGEcX85HpRXXKYL/Xrzkwa2OgY="}

# Licence ids revoked at build time. Checked on every build, offline and on every
# distribution channel (Store and sideloaded MSIX included), in addition to the
# signed revocation list cached from the release feed. To revoke a licence in
# the next release, add its id (``lgk_`` + 26 Crockford base32 characters, as in
# revocations.json) here and to the signed list; never remove an id that shipped.
REVOKED_LICENSE_IDS: frozenset[str] = frozenset()

PASTE_PREFIX = "LGK1-"
LICENSE_FILE_NAME = "license.lgklicense"
# Written when the user removes the licence, so the vault copy is cleared at the
# next unlock instead of silently restoring the licence that was just removed.
REMOVED_MARKER_NAME = "license.removed"

_BUNDLE_FIELDS = {"license", "signature"}
_LICENSE_FIELDS = {
    "format",
    "license_id",
    "edition",
    "name",
    "email",
    "issued_at",
    "updates_until",
}
_SIGNATURE_FIELDS = {"alg", "key_id", "signature"}
_KEY_ID_PATTERN = re.compile(r"[0-9a-f]{16}")
_DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")


FREE_ITEM_LIMIT = 4
LIFETIME_UNTIL = dt.date(9999, 12, 31)
_VAULT_LICENSE_KEY = "license"


class Feature(enum.Enum):
    UNLIMITED_ITEMS = "unlimited_items"
    SYNC = "sync"
    TOTP = "totp"
    ATTACHMENTS = "attachments"


class LicenseError(ValueError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class License:
    license_id: str
    edition: str
    name: str
    email: str
    issued_at: dt.date
    updates_until: dt.date


State = Literal["unconfigured", "free", "pro", "expired_for_this_build", "revoked", "invalid"]


@dataclass(frozen=True)
class LicenseStatus:
    state: State
    license: License | None
    message: str

    @property
    def pro_enabled(self) -> bool:
        return self.state in ("pro", "unconfigured")


_DAMAGED_TEXT = (
    "licensing.theLicenceKeyLooksIncomplete"
)
_REASON_TEXT = {
    "bad-encoding": _DAMAGED_TEXT,
    "not-json": _DAMAGED_TEXT,
    "license-shape": _DAMAGED_TEXT,
    "duplicate-field": _DAMAGED_TEXT,
    "unknown-key": "licensing.thisLicenceWasIssuedFor",
    "bad-signature": "licensing.thisLicenceKeyIsNot",
}
_FALLBACK_TEXT = "licensing.theLicenceCouldNotBe"


def reason_text(reason: str) -> str:
    """User-facing text for a ``LicenseError.reason``."""
    return t(_REASON_TEXT.get(reason, _FALLBACK_TEXT))


def _fail(reason: str, message: str | None = None) -> LicenseError:
    return LicenseError(message or reason_text(reason), reason=reason)


def _loads(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_unique_object)
    except UpdateCheckError as exc:
        raise _fail("duplicate-field") from exc
    except (ValueError, RecursionError) as exc:
        raise _fail("not-json") from exc


def parse_license_text(text: str) -> dict:
    """Accept an ``LGK1-`` paste string (tolerating wrapping) or the JSON file text."""
    if not isinstance(text, str):
        raise _fail("not-text")
    stripped = text.strip().lstrip("﻿").strip()
    if stripped.startswith(PASTE_PREFIX):
        body = "".join(stripped[len(PASTE_PREFIX) :].split()).rstrip(".")
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError) as exc:
            raise _fail("bad-encoding") from exc
        value = _loads(decoded)
    else:
        value = _loads(stripped.rstrip("."))
    if not isinstance(value, dict):
        raise _fail("license-shape")
    return value


def encode_paste(bundle: dict) -> str:
    body = base64.urlsafe_b64encode(canonical_json(bundle)).decode("ascii").rstrip("=")
    return PASTE_PREFIX + body


def _date(value: object) -> dt.date:
    if not isinstance(value, str) or _DATE_PATTERN.fullmatch(value) is None:
        raise _fail("license-shape")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise _fail("license-shape") from exc


def verify_bundle(bundle: dict, keys: Mapping[str, str] | None = None) -> License:
    keys = LICENSE_KEYS if keys is None else keys
    if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_FIELDS:
        raise _fail("license-shape")
    lic, sig = bundle["license"], bundle["signature"]
    if not isinstance(lic, dict) or set(lic) != _LICENSE_FIELDS:
        raise _fail("license-shape")
    if not isinstance(sig, dict) or set(sig) != _SIGNATURE_FIELDS:
        raise _fail("license-shape")
    _check_signature(lic, sig, keys)

    if (
        isinstance(lic["format"], bool)
        or lic["format"] != 1
        or lic["edition"] != "pro"
    ):
        raise _fail("license-shape")
    for field in ("license_id", "name", "email"):
        if not isinstance(lic[field], str) or not lic[field]:
            raise _fail("license-shape")
    return License(
        license_id=lic["license_id"],
        edition=lic["edition"],
        name=lic["name"],
        email=lic["email"],
        issued_at=_date(lic["issued_at"]),
        updates_until=_date(lic["updates_until"]),
    )


def newer_format(bundle: object, keys: Mapping[str, str] | None = None) -> bool:
    """True for a correctly signed bundle whose licence ``format`` is newer than this build reads."""
    keys = LICENSE_KEYS if keys is None else keys
    if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_FIELDS:
        return False
    lic, sig = bundle["license"], bundle["signature"]
    if not isinstance(lic, dict) or not isinstance(sig, dict) or set(sig) != _SIGNATURE_FIELDS:
        return False
    fmt = lic.get("format")
    if isinstance(fmt, bool) or not isinstance(fmt, int) or fmt <= 1:
        return False
    try:
        _check_signature(lic, sig, keys)
    except (LicenseError, TypeError, ValueError, KeyError, AttributeError):
        return False
    return True


def _check_signature(lic: dict, sig: dict, keys: Mapping[str, str]) -> None:
    # Callers check the block's shape first; a block missing a field is still a
    # LicenseError here (never a KeyError) so no caller can leak a lookup error.
    if not isinstance(sig, dict) or set(sig) != _SIGNATURE_FIELDS:
        raise _fail("license-shape")
    if sig["alg"] != "Ed25519":
        raise _fail("bad-alg")
    key_id, encoded_sig = sig["key_id"], sig["signature"]
    if not isinstance(key_id, str) or _KEY_ID_PATTERN.fullmatch(key_id) is None:
        # Damaged, not newer: only a well-formed key id this build lacks is "unknown-key".
        raise _fail("license-shape")
    encoded_key = keys.get(key_id)
    if encoded_key is None:
        raise _fail("unknown-key")
    try:
        raw_key = base64.b64decode(encoded_key, validate=True)
        if len(raw_key) != 32 or hashlib.sha256(raw_key).digest()[:8].hex() != key_id:
            raise ValueError("bad key")
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise _fail("unknown-key") from exc
    try:
        if not isinstance(encoded_sig, str):
            raise ValueError("bad signature")
        raw_sig = base64.b64decode(encoded_sig, validate=True)
        if len(raw_sig) != 64:
            raise ValueError("bad signature")
        public_key.verify(raw_sig, canonical_json(lic))
    except (binascii.Error, ValueError, TypeError, InvalidSignature) as exc:
        raise _fail("bad-signature") from exc


def license_path() -> Path:
    return config.data_dir() / LICENSE_FILE_NAME


def _removed_marker_path() -> Path:
    return config.data_dir() / REMOVED_MARKER_NAME


def removal_pending() -> bool:
    """True after ``remove_license`` until a vault has dropped its copy."""
    try:
        return _removed_marker_path().exists()
    except OSError:
        return False


def install_license(text: str) -> License:
    bundle = parse_license_text(text)
    lic = verify_bundle(bundle)
    config.atomic_write_json(license_path(), bundle)
    try:
        _removed_marker_path().unlink(missing_ok=True)
    except OSError:
        # The licence is installed; a stale marker only keeps the vault copy
        # from being stored until it can be removed.
        _log.warning("Could not remove the licence removal marker", exc_info=True)
    return lic


def remove_license() -> None:
    config.atomic_write_json(_removed_marker_path(), {"removed": True})
    license_path().unlink(missing_ok=True)


def _cached_revoked_ids() -> frozenset[str]:
    """Every revoked licence id this build knows: built in, cached list, and the copy next to the licence.

    The built-in set applies even when the cached list cannot be read; a missing
    cache never un-revokes ids from the remembered signed copy (see
    ``updates.cached_revocations``).
    """
    try:
        from . import updates

        cached = updates.cached_revocations()
    except Exception:
        cached = frozenset()
    return REVOKED_LICENSE_IDS | cached


def covers(published: dt.date, lic: License) -> bool:
    return published <= lic.updates_until


def status(
    *,
    build_date: dt.date | None = None,
    revoked: Iterable[str] | None = None,
    keys: Mapping[str, str] | None = None,
) -> LicenseStatus:
    active_keys = LICENSE_KEYS if keys is None else keys
    if not active_keys:
        return LicenseStatus("unconfigured", None, t("licensing.licensingIsNotConfiguredIn"))
    try:
        path = license_path()
        if not path.exists():
            return LicenseStatus("free", None, t("licensing.noProLicenceIsInstalled"))
        lic = verify_bundle(parse_license_text(path.read_text(encoding="utf-8")), active_keys)
    except LicenseError as exc:
        return LicenseStatus("invalid", None, t("licensing.theInstalledLicenceIsNot", v1=reason_text(exc.reason)))
    except (OSError, ValueError):
        return LicenseStatus("invalid", None, t("licensing.theInstalledLicenceCouldNot"))
    revoked_ids = _cached_revoked_ids() if revoked is None else REVOKED_LICENSE_IDS | frozenset(revoked)
    if lic.license_id in revoked_ids:
        return LicenseStatus("revoked", lic, t("licenceView.thisLicenceHasBeenRevoked"))
    built = dt.date.fromisoformat(BUILD_DATE) if build_date is None else build_date
    if not covers(built, lic):
        return LicenseStatus(
            "expired_for_this_build",
            lic,
            t("licensing.yourLicenceCoversVersionsReleased", v1=lic.updates_until.isoformat()),
        )
    return LicenseStatus("pro", lic, t("licensing.proLicenceFor", name=lic.name))


def update_coverage_note(published_iso: str, st: LicenseStatus | None = None) -> str | None:
    """Warning text when a release is newer than an active licence's coverage."""
    try:
        published = _parse_published(published_iso).date()
    except UpdateCheckError:
        return None
    current = status() if st is None else st
    if current.state != "pro" or current.license is None:
        return None
    if covers(published, current.license):
        return None
    return (
        t("licensing.thisUpdateIsnTCovered", FREE_ITEM_LIMIT=FREE_ITEM_LIMIT, APP_VERSION=APP_VERSION)
    )


def is_pro(feature: Feature) -> bool:
    try:
        return status().pro_enabled
    except Exception:
        return False


def pro_features(st: LicenseStatus | None = None) -> frozenset[str]:
    """Values of the Pro-only ``Feature`` members this licence state allows.

    Free (and every unusable licence state) gets none; fails closed like
    ``item_limit``.  Existing data is never locked: callers only use this to
    refuse adding or changing what a feature stores.
    """
    try:
        current = status() if st is None else st
        return frozenset(f.value for f in Feature) if current.pro_enabled else frozenset()
    except Exception:
        return frozenset()


def item_limit(st: LicenseStatus | None = None) -> int | None:
    """Maximum live items for this licence state; ``None`` means unlimited."""
    try:
        current = status() if st is None else st
        return None if current.pro_enabled else FREE_ITEM_LIMIT
    except Exception:
        return FREE_ITEM_LIMIT


# --- encrypted copy of the licence inside the vault (survives backup/restore) ---------


def store_in_vault(session, bundle: dict) -> None:
    """Keep ``bundle`` as the vault's licence copy.

    The copy is checked before it touches the payload, and the previous value
    comes back if the save fails, so a rejected copy never lingers in memory.
    """
    from .vault import stored_license_ok

    try:
        value = json.loads(canonical_json(bundle)) if isinstance(bundle, dict) else None
    except (TypeError, ValueError):
        value = None
    if value is None or not stored_license_ok(value):
        raise _fail("license-shape")
    payload = session._require_typed_catalog()
    missing = object()
    previous = payload.get(_VAULT_LICENSE_KEY, missing)
    payload[_VAULT_LICENSE_KEY] = value
    try:
        session.save()
    except BaseException:
        if previous is missing:
            payload.pop(_VAULT_LICENSE_KEY, None)
        else:
            payload[_VAULT_LICENSE_KEY] = previous
        raise


def vault_copy(session) -> dict | None:
    try:
        value = session._require_typed_catalog().get(_VAULT_LICENSE_KEY)
    except Exception:
        return None
    return json.loads(canonical_json(value)) if isinstance(value, dict) else None


def clear_vault_copy(session) -> None:
    payload = session._require_typed_catalog()
    if _VAULT_LICENSE_KEY in payload:
        del payload[_VAULT_LICENSE_KEY]
        session.save()


def restore_file_from_vault(session) -> bool:
    """Write the licence file from the vault copy when the file is missing or unusable.

    Never replaces a valid licence file, and only writes a copy that verifies.
    """
    try:
        if not LICENSE_KEYS:
            return False
        bundle = vault_copy(session)
        if bundle is None:
            return False
        if status().state not in ("free", "invalid"):
            return False
        verify_bundle(bundle)
        config.atomic_write_json(license_path(), bundle)
        return True
    except Exception:
        return False


def installed_bundle() -> dict | None:
    """The installed licence bundle when it verifies and is not revoked, else ``None``."""
    try:
        if status().state not in ("pro", "expired_for_this_build"):
            return None
        return parse_license_text(license_path().read_text(encoding="utf-8"))
    except Exception:
        return None


def reconcile_vault_copy(session) -> None:
    """Keep the licence file and the vault's encrypted copy in step.

    Runs after unlock and after a licence install or removal while unlocked:

    * a pending removal (marker kept until the next install) drops this vault's
      copy and restores nothing;
    * otherwise a missing or unusable file is restored from the vault copy, and
      a valid installed licence is copied into the vault when it differs.

    Never raises: a licence problem never blocks unlock or vault access.
    """
    try:
        if not LICENSE_KEYS:
            return
        if removal_pending():
            # The marker stays until a licence is installed again: every profile's
            # vault drops its copy on unlock, so no profile restores a removed licence.
            clear_vault_copy(session)
            return
        restore_file_from_vault(session)
        bundle = installed_bundle()
        if bundle is None:
            return
        current = vault_copy(session)
        if current is None or canonical_json(current) != canonical_json(bundle):
            store_in_vault(session, bundle)
    except Exception:
        return


# --- the licence carried between devices by sync --------------------------------------


def sync_state_id(license_id: str) -> str:
    """Sync state id of a licence: ``"lic:"`` + the first 32 hex digits of sha256(license_id)."""
    return "lic:" + hashlib.sha256(license_id.encode("utf-8")).hexdigest()[:32]


def adopt_synced_license(session, bundles: Iterable[dict]) -> License | None:
    """Install the first synced bundle that makes this device Pro; ``None`` when none did.

    Only when licensing is configured, no removal is pending (the user removed
    the licence on this PC) and the installed licence is not already Pro.  A
    candidate must verify, must not be revoked and must cover this build.  The
    licence file is written first, then the vault copy (``session`` unlocked;
    pass ``None`` to skip it).  Never raises.
    """
    try:
        if not LICENSE_KEYS or removal_pending():
            return None
        if status().state == "pro":
            return None
        revoked = _cached_revoked_ids()
        built = dt.date.fromisoformat(BUILD_DATE)
        for bundle in bundles:
            try:
                lic = verify_bundle(bundle)
            except LicenseError:
                continue
            if lic.license_id in revoked or not covers(built, lic):
                continue
            value = json.loads(canonical_json(bundle))
            config.atomic_write_json(license_path(), value)
            if session is not None and getattr(session, "is_unlocked", False):
                try:
                    store_in_vault(session, value)
                except Exception:
                    _log.warning("Synced licence was installed but not copied into the vault", exc_info=True)
            return lic
    except Exception:
        _log.warning("Synced licence could not be installed", exc_info=True)
    return None
