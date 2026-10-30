from __future__ import annotations

import base64
import binascii
import io
import json
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import atomic_write_json, data_dir, read_json
from .i18n import t

PROFILES_VERSION = 1
DEFAULT_COLORS = ("#28C7FA", "#7C5CFC", "#34D399", "#F59E0B", "#F472B6", "#60A5FA")

# Profile details are shown while a vault is locked, so the optional image is
# deliberately a small, self-contained value in the non-secret profile index.
# Source bytes may be larger than the retained image, but are never stored.
PROFILE_PHOTO_MAX_SOURCE_BYTES = 4 * 1024 * 1024
PROFILE_PHOTO_MAX_DIMENSION = 1024
PROFILE_PHOTO_MAX_PIXELS = 1024 * 1024
PROFILE_PHOTO_MAX_DIMENSION_STORED = 256
PROFILE_PHOTO_MAX_STORED_BYTES = 256 * 1024
_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{3}(?:[0-9A-Fa-f]{3})?$")
_PHOTO_UNSET = object()

try:  # Pillow is part of the Windows product dependency set.
    from PIL import Image, ImageOps
except ImportError:  # pragma: no cover - exercised only in minimal installs.
    Image = None  # type: ignore[assignment]
    ImageOps = None  # type: ignore[assignment]


class ProfileError(Exception):
    pass


CAMERA_UNLOCK_BLOCKS_DELETE = (
    "Camera verification is set up for this profile. Open the profile and remove camera verification "
    "first (Unlocking; this re-encrypts the vault under a new key and replaces any recovery phrase), "
    "then remove the profile.")


@dataclass(frozen=True)
class ProfileRecord:
    id: str
    name: str
    color: str
    created_at: int
    last_used_at: int
    # Base64-encoded, metadata-free PNG.  It is optional for v1 rows created
    # before profile editing was introduced.
    photo_data: str | None = None

    @property
    def photo(self) -> str | None:
        """Compatibility alias for callers that call the value ``photo``."""

        return self.photo_data

    @property
    def display_name(self) -> str:
        """UI-facing alias for the profile's non-secret name."""

        return self.name

    @property
    def accent_color(self) -> str:
        """UI-facing alias for the profile's accent color."""

        return self.color


class ProfileManager:
    """Manages LocalGateKeys profiles inside one Windows account.

    Profile names and colors are intentionally non-secret so a chooser can be
    displayed while vaults are locked. Credentials, targets, settings that can
    reveal security posture, and trusted bindings stay inside each profile dir.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or data_dir()).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "profiles.json"
        self._ensure_index()

    def _ensure_index(self) -> None:
        if self.index_path.exists():
            try:
                raw = read_json(self.index_path)
                if int(raw.get("version", 0)) == PROFILES_VERSION and isinstance(raw.get("profiles"), list):
                    return
            except (OSError, ValueError, json.JSONDecodeError):
                pass
            raise ProfileError("Profile index is damaged or unsupported")
        self._write_index({"version": PROFILES_VERSION, "active_profile_id": None, "profiles": []})

    def _read_index(self) -> dict[str, Any]:
        self._ensure_index()
        raw = read_json(self.index_path)
        if int(raw.get("version", 0)) != PROFILES_VERSION or not isinstance(raw.get("profiles"), list):
            raise ProfileError("Profile index is damaged or unsupported")
        return raw

    def _write_index(self, value: dict[str, Any]) -> None:
        atomic_write_json(self.index_path, value)

    def list_profiles(self) -> list[ProfileRecord]:
        rows = self._read_index()["profiles"]
        result: list[ProfileRecord] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                result.append(
                    ProfileRecord(
                        id=str(row["id"]),
                        name=str(row["name"]),
                        color=_safe_profile_color(row.get("color")),
                        created_at=int(row.get("created_at", 0)),
                        last_used_at=int(row.get("last_used_at", 0)),
                        photo_data=_safe_stored_photo(_photo_value_from_row(row)),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(result, key=lambda item: (-item.last_used_at, item.name.casefold()))

    def active_profile(self) -> ProfileRecord | None:
        raw = self._read_index()
        wanted = raw.get("active_profile_id")
        if not wanted:
            return None
        return next((item for item in self.list_profiles() if item.id == wanted), None)

    def create_profile(self, name: str, color: str | None = None) -> ProfileRecord:
        name = _validate_profile_name(name)
        raw = self._read_index()
        profiles = raw["profiles"]
        if any(str(item.get("name", "")).casefold() == name.casefold() for item in profiles if isinstance(item, dict)):
            raise ProfileError("A profile with that name already exists")
        now = int(time.time())
        profile_id = str(uuid.uuid4())
        chosen_color = _validate_profile_color(color) if color is not None else DEFAULT_COLORS[len(profiles) % len(DEFAULT_COLORS)]
        record = ProfileRecord(profile_id, name, chosen_color, now, now)
        profiles.append(_record_to_row(record))
        self.profile_dir(profile_id).mkdir(parents=True, exist_ok=True)
        if not raw.get("active_profile_id"):
            raw["active_profile_id"] = profile_id
        self._write_index(raw)
        return record

    def allocate_restore_profile(self, name: str, color: str | None = None) -> ProfileRecord:
        """Reserve identity and a fresh directory path without changing the index.

        Backup restore publishes encrypted profile data before that profile is
        visible in the chooser.  Keeping allocation separate from registration
        means failed restores cannot leave empty or half-restored profile rows.
        """

        name = _validate_profile_name(name)
        raw = self._read_index()
        profiles = raw["profiles"]
        if any(str(item.get("name", "")).casefold() == name.casefold()
               for item in profiles if isinstance(item, dict)):
            raise ProfileError("A profile with that name already exists")
        chosen_color = _validate_profile_color(color) if color is not None else DEFAULT_COLORS[len(profiles) % len(DEFAULT_COLORS)]
        profiles_root = self.root / "Profiles"
        if _is_reparse_point(profiles_root):
            raise ProfileError("Profile storage must be a regular local directory")
        try:
            profiles_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ProfileError("Profile storage is unavailable") from exc
        if _is_reparse_point(profiles_root) or not profiles_root.is_dir():
            raise ProfileError("Profile storage must be a regular local directory")
        for _ in range(4):
            profile_id = str(uuid.uuid4())
            destination = profiles_root / profile_id
            if not destination.exists() and not _is_reparse_point(destination):
                now = int(time.time())
                return ProfileRecord(profile_id, name, chosen_color, now, now)
        raise ProfileError("Could not reserve a new profile location")

    def restore_profile_path(self, record: ProfileRecord, *, require_absent: bool = True) -> Path:
        """Return a validated directory for a pending or completed restore."""

        if not isinstance(record, ProfileRecord):
            raise ProfileError("Restore profile is malformed")
        try:
            canonical_id = str(uuid.UUID(record.id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ProfileError("Restore profile ID is malformed") from exc
        if canonical_id != record.id:
            raise ProfileError("Restore profile ID is malformed")
        profiles_root = self.root / "Profiles"
        if _is_reparse_point(profiles_root) or not profiles_root.is_dir():
            raise ProfileError("Profile storage must be a regular local directory")
        destination = profiles_root / canonical_id
        if _is_reparse_point(destination) or (require_absent and destination.exists()):
            raise ProfileError("The new profile location is no longer available")
        try:
            if destination.resolve(strict=False).parent != profiles_root.resolve():
                raise ProfileError("Restore profile must stay inside profile storage")
        except OSError as exc:
            raise ProfileError("Restore profile location is unavailable") from exc
        return destination

    def register_restored_profile(self, record: ProfileRecord) -> ProfileRecord:
        """Add a fully restored profile to the index without activating it."""

        name = _validate_profile_name(record.name if isinstance(record, ProfileRecord) else "")
        color = _validate_profile_color(record.color)
        destination = self.restore_profile_path(record, require_absent=False)
        # The restore has already published its files.  Never create, move, or
        # delete that folder here: index failures must leave recovery data intact.
        if _is_reparse_point(destination) or not destination.is_dir():
            raise ProfileError("Restored profile data is missing or unsafe")
        vault = destination / "vault.json"
        if _is_reparse_point(vault) or not vault.is_file():
            raise ProfileError("Restored profile does not contain a safe vault")
        settings = destination / "settings.json"
        if _is_reparse_point(settings) or (settings.exists() and not settings.is_file()):
            raise ProfileError("Restored profile settings are unsafe")

        raw = self._read_index()
        profiles = raw["profiles"]
        if any(str(item.get("id", "")) == record.id for item in profiles if isinstance(item, dict)):
            raise ProfileError("A profile with that ID already exists")
        if any(str(item.get("name", "")).casefold() == name.casefold()
               for item in profiles if isinstance(item, dict)):
            raise ProfileError("A profile with that name already exists")
        registered = ProfileRecord(record.id, name, color, int(record.created_at), int(record.last_used_at),
                                   _safe_stored_photo(record.photo_data))
        profiles.append(_record_to_row(registered))
        if not raw.get("active_profile_id"):
            raw["active_profile_id"] = registered.id
        self._write_index(raw)
        return registered

    def ensure_profile(self) -> ProfileRecord:
        active = self.active_profile()
        if active:
            return active
        profiles = self.list_profiles()
        if profiles:
            self.set_active(profiles[0].id)
            return profiles[0]
        created = self.create_profile("My profile")
        self.set_active(created.id)
        return created

    def set_active(self, profile_id: str) -> ProfileRecord:
        raw = self._read_index()
        now = int(time.time())
        found: dict[str, Any] | None = None
        for item in raw["profiles"]:
            if isinstance(item, dict) and str(item.get("id")) == profile_id:
                item["last_used_at"] = now
                found = item
                break
        if found is None:
            raise ProfileError("Unknown profile")
        raw["active_profile_id"] = profile_id
        self._write_index(raw)
        return ProfileRecord(
            id=str(found["id"]),
            name=str(found["name"]),
            color=_safe_profile_color(found.get("color")),
            created_at=int(found.get("created_at", 0)),
            last_used_at=now,
            photo_data=_safe_stored_photo(_photo_value_from_row(found)),
        )

    def rename_profile(self, profile_id: str, new_name: str) -> ProfileRecord:
        new_name = _validate_profile_name(new_name)
        raw = self._read_index()
        for item in raw["profiles"]:
            if isinstance(item, dict) and str(item.get("id")) != profile_id and str(item.get("name", "")).casefold() == new_name.casefold():
                raise ProfileError("A profile with that name already exists")
        for item in raw["profiles"]:
            if isinstance(item, dict) and str(item.get("id")) == profile_id:
                item["name"] = new_name
                self._write_index(raw)
                # Editing metadata must not count as using a profile.  In
                # particular, renaming the active profile preserves its
                # last_used_at value and does not rewrite active_profile_id.
                return _record_from_row(item)
        raise ProfileError("Unknown profile")

    def update_profile(
        self,
        profile_id: str,
        *,
        name: str | None = None,
        color: str | None = None,
        photo: bytes | bytearray | memoryview | str | Path | None | object = _PHOTO_UNSET,
        photo_data: bytes | bytearray | memoryview | str | Path | None | object = _PHOTO_UNSET,
        remove_photo: bool = False,
    ) -> ProfileRecord:
        """Update non-secret profile details atomically.

        ``photo`` and ``photo_data`` accept raw PNG/JPEG bytes, a local source
        path, or the base64 value returned by this manager.  The source is
        decoded, bounded, normalized to a metadata-free PNG, and only then
        written to ``profiles.json``.  Pass ``None`` or ``remove_photo=True``
        to remove an existing photo.  No active-profile or usage fields are
        changed by this method.
        """

        if photo is not _PHOTO_UNSET and photo_data is not _PHOTO_UNSET:
            raise ProfileError("Choose one photo value")
        if remove_photo and (photo is not _PHOTO_UNSET or photo_data is not _PHOTO_UNSET):
            raise ProfileError("Choose a photo or remove it, not both")

        normalized_name = _validate_profile_name(name) if name is not None else None
        normalized_color = _validate_profile_color(color) if color is not None else None
        photo_value: str | None | object = _PHOTO_UNSET
        source = photo if photo is not _PHOTO_UNSET else photo_data
        if remove_photo or source is None:
            photo_value = None
        elif source is not _PHOTO_UNSET:
            photo_value = _normalize_profile_photo(source)

        raw = self._read_index()
        rows = [row for row in raw["profiles"] if isinstance(row, dict)]
        for row in rows:
            if str(row.get("id")) != profile_id:
                continue
            if normalized_name is not None:
                if any(
                    str(other.get("id")) != profile_id
                    and str(other.get("name", "")).casefold() == normalized_name.casefold()
                    for other in rows
                ):
                    raise ProfileError("A profile with that name already exists")
                row["name"] = normalized_name
            if normalized_color is not None:
                row["color"] = normalized_color
            if photo_value is not _PHOTO_UNSET:
                if photo_value is None:
                    row.pop("photo_data", None)
                    row.pop("photo", None)
                else:
                    row["photo_data"] = photo_value
                    row.pop("photo", None)
            self._write_index(raw)
            return _record_from_row(row)
        raise ProfileError("Unknown profile")

    def set_profile_photo(
        self, profile_id: str, source: bytes | bytearray | memoryview | str | Path | None
    ) -> ProfileRecord:
        """Set or clear a profile photo without changing any other metadata."""

        return self.update_profile(profile_id, photo=source)

    def remove_profile_photo(self, profile_id: str) -> ProfileRecord:
        return self.update_profile(profile_id, remove_photo=True)

    def camera_unlock_blocks_delete(self, profile_id: str) -> bool:
        """True when the profile has a camera-unlock sidecar, so :meth:`delete_profile` will refuse it."""
        from .face_unlock import envelope_path as face_envelope_path

        return face_envelope_path(self.root / "Profiles" / profile_id / "vault.json").exists()

    def delete_profile(self, profile_id: str) -> None:
        raw = self._read_index()
        rows = [item for item in raw["profiles"] if isinstance(item, dict)]
        if len(rows) <= 1:
            raise ProfileError("Create another profile before deleting the only profile")
        match = next((item for item in rows if str(item.get("id")) == profile_id), None)
        if match is None:
            raise ProfileError("Unknown profile")

        # Archive rather than irreversible deletion. The archive is still local and
        # contains only already-encrypted vault data plus profile settings.
        source = self.profile_dir(profile_id)
        if source.exists():
            # The camera-unlock sidecar opens the vault with nothing more than
            # this Windows account (DPAPI).  Removing it alone would leave any
            # earlier copy of it opening the archived vault, so a profile with
            # camera unlock is refused until camera verification is removed in
            # the app, which rotates the data key and, when there is one,
            # replaces the recovery phrase (L-4).
            if self.camera_unlock_blocks_delete(profile_id):
                raise ProfileError(CAMERA_UNLOCK_BLOCKS_DELETE)
            archive_root = self.root / "DeletedProfiles"
            archive_root.mkdir(parents=True, exist_ok=True)
            destination = archive_root / f"{int(time.time())}-{profile_id}"
            shutil.move(str(source), str(destination))
        raw["profiles"] = [item for item in rows if str(item.get("id")) != profile_id]
        if raw.get("active_profile_id") == profile_id:
            replacement = str(raw["profiles"][0]["id"])
            raw["active_profile_id"] = replacement
        self._write_index(raw)

    def profile_dir(self, profile_id: str | None = None) -> Path:
        pid = profile_id or self.ensure_profile().id
        path = self.root / "Profiles" / pid
        path.mkdir(parents=True, exist_ok=True)
        return path

    def vault_path(self, profile_id: str | None = None) -> Path:
        return self.profile_dir(profile_id) / "vault.json"

    def settings_path(self, profile_id: str | None = None) -> Path:
        return self.profile_dir(profile_id) / "settings.json"

    def backups_dir(self, profile_id: str | None = None) -> Path:
        path = self.profile_dir(profile_id) / "Backups"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def trusted_apps_path(self, profile_id: str | None = None) -> Path:
        return self.profile_dir(profile_id) / "trusted-apps.json"


def _is_reparse_point(path: Path) -> bool:
    """Fail closed for symlinks and Windows junctions/reparse points."""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _validate_profile_name(value: str) -> str:
    if not isinstance(value, str):
        raise ProfileError(t("profiles.err.nameText"))
    cleaned = value.strip()
    if not cleaned:
        raise ProfileError(t("profiles.err.nameEmpty"))
    if len(cleaned) > 80:
        raise ProfileError(t("profiles.err.nameTooLong"))
    if any(ord(ch) < 32 for ch in cleaned):
        raise ProfileError(t("profiles.err.nameControl"))
    return cleaned


def _validate_profile_color(value: str) -> str:
    if not isinstance(value, str):
        raise ProfileError("Profile accent must be text")
    cleaned = value.strip()
    if not _COLOR_RE.fullmatch(cleaned):
        raise ProfileError("Profile accent must be a hex color such as #28C7FA")
    return cleaned


def _safe_profile_color(value: Any) -> str:
    try:
        return _validate_profile_color(str(value))
    except ProfileError:
        return DEFAULT_COLORS[0]


def _record_to_row(record: ProfileRecord) -> dict[str, Any]:
    row = asdict(record)
    if row.get("photo_data") is None:
        row.pop("photo_data", None)
    return row


def _record_from_row(row: dict[str, Any]) -> ProfileRecord:
    return ProfileRecord(
        id=str(row["id"]),
        name=str(row["name"]),
        color=_safe_profile_color(row.get("color")),
        created_at=int(row.get("created_at", 0)),
        last_used_at=int(row.get("last_used_at", 0)),
        photo_data=_safe_stored_photo(_photo_value_from_row(row)),
    )


def _photo_value_from_row(row: dict[str, Any]) -> Any:
    """Read the additive v1 field and tolerate an early ``photo`` spelling."""

    return row.get("photo_data", row.get("photo"))


def _safe_stored_photo(value: Any) -> str | None:
    """Return a valid retained photo or quietly hide malformed old data."""

    if not isinstance(value, str) or not value:
        return None
    max_encoded = ((PROFILE_PHOTO_MAX_STORED_BYTES + 2) // 3) * 4
    if len(value) > max_encoded:
        return None
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
        if not decoded or len(decoded) > PROFILE_PHOTO_MAX_STORED_BYTES:
            return None
        normalized = _normalize_profile_photo(decoded)
        normalized_bytes = base64.b64decode(normalized.encode("ascii"), validate=True)
        # Existing rows are not rewritten during a read, so preserving a
        # valid value avoids needless index churn while still validating it.
        return value if normalized_bytes == decoded else normalized
    except (ProfileError, ValueError, binascii.Error, UnicodeError):
        return None


def _photo_source_bytes(source: bytes | bytearray | memoryview | str | Path) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif isinstance(source, Path):
        data = _read_photo_path(source)
    elif isinstance(source, str):
        candidate = Path(source)
        try:
            is_path = candidate.is_file()
        except OSError:
            is_path = False
        if is_path:
            data = _read_photo_path(candidate)
        else:
            encoded = source.split(",", 1)[1] if source.startswith("data:") and "," in source else source
            try:
                data = base64.b64decode(encoded.encode("ascii"), validate=True)
            except (ValueError, binascii.Error, UnicodeError) as exc:
                raise ProfileError("Profile photo must be a PNG or JPEG image") from exc
    else:
        raise ProfileError("Profile photo must be image bytes or a local file")
    if not data or len(data) > PROFILE_PHOTO_MAX_SOURCE_BYTES:
        raise ProfileError("Profile photo is empty or too large")
    return data


def _read_photo_path(path: Path) -> bytes:
    try:
        if not path.is_file() or path.stat().st_size > PROFILE_PHOTO_MAX_SOURCE_BYTES:
            raise ProfileError("Profile photo is empty or too large")
        data = path.read_bytes()
    except OSError as exc:
        raise ProfileError("Profile photo could not be read") from exc
    if not data:
        raise ProfileError("Profile photo is empty or too large")
    return data


def _normalize_profile_photo(source: bytes | bytearray | memoryview | str | Path) -> str:
    """Decode and normalize a user-selected PNG/JPEG into inline PNG base64."""

    if Image is None:
        raise ProfileError("Photo editing is unavailable because image support is not installed")
    data = _photo_source_bytes(source)
    try:
        with Image.open(io.BytesIO(data)) as opened:
            if opened.format not in {"PNG", "JPEG"}:
                raise ProfileError("Profile photo must be a PNG or JPEG image")
            if int(getattr(opened, "n_frames", 1)) != 1:
                raise ProfileError("Animated profile photos are not supported")
            width, height = (int(opened.width), int(opened.height))
            if (
                width < 1
                or height < 1
                or width > PROFILE_PHOTO_MAX_DIMENSION
                or height > PROFILE_PHOTO_MAX_DIMENSION
                or width * height > PROFILE_PHOTO_MAX_PIXELS
            ):
                raise ProfileError("Profile photo dimensions are too large")
            # exif_transpose reads orientation but the new image below drops
            # all source metadata before writing the retained value.
            oriented = ImageOps.exif_transpose(opened) if ImageOps is not None else opened.copy()
            oriented.load()
            rgba = oriented.convert("RGBA")
            rgba.thumbnail(
                (PROFILE_PHOTO_MAX_DIMENSION_STORED, PROFILE_PHOTO_MAX_DIMENSION_STORED),
                Image.Resampling.LANCZOS,
            )
            normalized = Image.new("RGBA", rgba.size)
            normalized.paste(rgba, (0, 0), rgba)
            output = io.BytesIO()
            normalized.save(output, format="PNG", optimize=True)
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError("Profile photo is not a valid PNG or JPEG image") from exc
    encoded = output.getvalue()
    if len(encoded) > PROFILE_PHOTO_MAX_STORED_BYTES:
        raise ProfileError("Profile photo is too large after normalization")
    return base64.b64encode(encoded).decode("ascii")


def normalize_profile_photo(source: bytes | bytearray | memoryview | str | Path) -> str:
    """Public preview/helper API used by profile editors before Save."""

    return _normalize_profile_photo(source)
