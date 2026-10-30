from __future__ import annotations

import json
import logging
import os
import time
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BRAND_NAME = "LocalGateKeys"
SLOGAN = "Your Keys. Your Control."
APP_DIR_NAME = "LocalGateKeys"
LEGACY_APP_DIR_NAME = "LocalVaultPrototype"
NATIVE_HOST_NAME = "com.localgatekeys.app"
# Unpacked/developer build: derived from the "key" in browser-extension/manifest.json.
EXTENSION_ID = "hojebpmbiibhbhhkohgongojilojijmb"
# Store-published builds get an ID assigned by each store (the store package
# has no "key"). PLACEHOLDERS: fill in from the Chrome Web Store / Edge
# Add-ons dashboards once the listings exist.
# An empty string means "not assigned yet" and is ignored.
# Chrome Web Store item ID (Developer Dashboard draft, 2026-10-28).
CHROME_WEB_STORE_EXTENSION_ID = "fcilinmkccknaoeobcdnploacggajbdg"
# Edge Add-ons CRX ID of product 33132488-a8ea-462f-96e9-033555cc47af (Partner Center, 2026-10-19).
EDGE_ADDONS_EXTENSION_ID = "oclkjglnfefdmhddgicmbadaoehakbjj"


def _is_chromium_extension_id(value: str) -> bool:
    return len(value) == 32 and all("a" <= ch <= "p" for ch in value)


def chromium_extension_ids(
    store_ids: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Every Chromium extension ID the native host may serve, dev ID first."""

    if store_ids is None:
        store_ids = (CHROME_WEB_STORE_EXTENSION_ID, EDGE_ADDONS_EXTENSION_ID)
    ids = [EXTENSION_ID]
    for value in store_ids:
        if not value:
            continue
        if not _is_chromium_extension_id(value):
            raise ValueError(f"Invalid store extension ID: {value!r}")
        if value not in ids:
            ids.append(value)
    return tuple(ids)


def chromium_extension_origins(extension_ids: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """``allowed_origins`` entries for the Chromium native-messaging manifest."""

    return tuple(f"chrome-extension://{value}/" for value in (extension_ids or chromium_extension_ids()))


def extension_caller_origins(extension_ids: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """Caller origins the native host accepts in argv[1], for every listed ID."""

    return tuple(
        origin
        for value in (extension_ids or chromium_extension_ids())
        for origin in (f"chrome-extension://{value}/", f"extension://{value}/")
    )


CHROMIUM_EXTENSION_IDS = chromium_extension_ids()
EXTENSION_ORIGINS = extension_caller_origins(CHROMIUM_EXTENSION_IDS)

# Which of the IDs above a build actually trusts (audit 2026-10-18, M6).
#
# The developer ID is derived from the public "key" committed in
# browser-extension/manifest.json, so any unpacked extension can claim it.
# Frozen builds (the Inno Setup installer and the MSIX / Store package) trust
# only the store-assigned IDs, unless
#   * the developer opts in with an empty file named
#     DEVELOPER_EXTENSION_OPT_IN in the data directory, or
#   * a store ID is still an unassigned placeholder: the Chromium manifest is
#     shared by Chrome and Edge, so until both listings exist the developer
#     ID stays allowed (reported in install.json and the native-host log).
# Source runs (repository and from-source installs) always trust it.
# MAIN CAVEAT: a store ID is derived from a public key too (it is in every
# installed CRX), so this narrows the list but does not make an ID a proof of
# origin; loading any unpacked extension still needs Developer mode.
DEVELOPER_EXTENSION_OPT_IN = "allow-developer-extension"
DEV_ID_DEVELOPER_INSTALL = "developer_install"
DEV_ID_OPT_IN = "developer_opt_in"
DEV_ID_STORE_ID_UNASSIGNED = "store_id_unassigned"


@dataclass(frozen=True)
class ExtensionTrust:
    chromium_ids: tuple[str, ...]
    # Why the developer ID is trusted, or None when it is not.
    developer_id_reason: str | None
    # Store listings whose ID is still an empty placeholder.
    missing_store_ids: tuple[str, ...]

    def caller_origins(self) -> tuple[str, ...]:
        return tuple(origin for value in self.chromium_ids
                     for origin in (f"chrome-extension://{value}/", f"extension://{value}/"))

    def manifest_origins(self) -> tuple[str, ...]:
        return tuple(f"chrome-extension://{value}/" for value in self.chromium_ids)


def is_developer_install() -> bool:
    """Source runs (repository or from-source install); never a frozen build."""

    import sys

    return not getattr(sys, "frozen", False)


def developer_extension_opted_in() -> bool:
    try:
        return (data_dir() / DEVELOPER_EXTENSION_OPT_IN).is_file()
    except OSError:
        return False


def extension_trust(*, developer: bool | None = None, opted_in: bool | None = None) -> ExtensionTrust:
    """The Chromium extension IDs this build's native host serves."""

    store = (("chrome_web_store", CHROME_WEB_STORE_EXTENSION_ID), ("edge_addons", EDGE_ADDONS_EXTENSION_ID))
    missing = tuple(name for name, value in store if not value)
    every = chromium_extension_ids(tuple(value for _name, value in store))
    if developer is None:
        developer = is_developer_install()
    reason: str | None = None
    if developer:
        reason = DEV_ID_DEVELOPER_INSTALL
    elif developer_extension_opted_in() if opted_in is None else opted_in:
        reason = DEV_ID_OPT_IN
    elif missing:
        reason = DEV_ID_STORE_ID_UNASSIGNED
    ids = every if reason else tuple(value for value in every if value != EXTENSION_ID)
    return ExtensionTrust(ids, reason, missing)

_atomic_write_fault: Callable[[str, Path], None] | None = None


@contextmanager
def atomic_write_faults(hook: Callable[[str, Path], None] | None) -> Iterator[None]:
    """Install a scoped fault hook for E02 publication tests.

    The hook is intentionally process-local and never enabled by product code.
    It can raise at ``before_replace`` or ``after_replace`` to exercise the
    journal/restart paths without broad filesystem deletion.
    """
    global _atomic_write_fault
    previous = _atomic_write_fault
    _atomic_write_fault = hook
    try:
        yield
    finally:
        _atomic_write_fault = previous


def _fault(stage: str, path: Path) -> None:
    if _atomic_write_fault is not None:
        _atomic_write_fault(stage, path)


def _local_appdata() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))


# Written into a LOCALGATEKEYS_DATA_DIR folder the app itself created: only such
# a folder (or the default one) has its ACL replaced (R-3).
OWNED_MARKER = ".localgatekeys-owned"


def _data_root() -> tuple[Path, bool]:
    """The data folder and whether it is a LOCALGATEKEYS_DATA_DIR override."""
    override = os.environ.get("LOCALGATEKEYS_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve(), True
    if os.name == "nt":
        return _local_appdata() / APP_DIR_NAME, False
    return _local_appdata() / "localgatekeys", False


def data_dir() -> Path:
    """The data folder, created owner-only when missing.

    No ACL rewrite of an existing folder happens here: every browser message
    starts a new native-host process, and rewriting the whole tree's ACL on
    each one was slow and raced the app's atomic saves (R-2). The main app
    calls ``secure_data_dir_once`` at startup instead.
    """
    root, override = _data_root()
    if not root.is_dir():
        root.mkdir(parents=True, exist_ok=True)
        if override:
            try:
                (root / OWNED_MARKER).write_text("LocalGateKeys created this folder.\n", encoding="utf-8")
            except OSError:
                pass
        # A folder just created is empty: the owner-only ACL is cheap here and races nothing.
        _restrict_data_dir(root)
    _restrict_path(root, is_dir=True)
    return root


def _acl_may_be_replaced(root: Path, override: bool) -> bool:
    """The default folder, or an override folder this app created (it holds the marker)."""
    return not override or (root / OWNED_MARKER).is_file()


def secure_data_dir_once() -> bool:
    """Main app startup only: give an existing data folder the owner-only ACL (I-24).

    Never called from the native host or the pipe helpers. Skips a folder the
    app did not create (a LOCALGATEKEYS_DATA_DIR pointed at an existing
    folder, R-3) and a folder whose DACL already is the owner-only protected
    one, so a normal start does not rewrite every file's ACL. Returns True
    when the ACL was (re)applied.
    """
    if os.name != "nt":
        return False
    root, override = _data_root()
    if not root.is_dir() or not _acl_may_be_replaced(root, override):
        return False
    try:
        if has_owner_only_acl(root):
            return False
    except Exception:  # noqa: BLE001 - unreadable: try to apply it
        pass
    return _restrict_data_dir(root)


def _restrict_data_dir(path: Path) -> bool:
    """Give the data folder an owner-only ACL on Windows, new or existing.

    chmod cannot express a Windows ACL, so a folder created outside the
    installer (portable run, a custom LOCALGATEKEYS_DATA_DIR) would otherwise
    inherit whatever its parent grants, and an existing folder keeps whatever
    it was given. The new DACL is protected (nothing inherited from the
    parent) and allows only the current user and SYSTEM, for the folder and
    everything created in it. Best-effort: on failure the current ACL stays,
    as before, and startup continues.
    """
    if os.name != "nt":
        return False
    try:
        apply_owner_only_acl(path)
        return True
    except Exception:  # noqa: BLE001 - best-effort; the current ACL stays
        logging.getLogger(__name__).warning("Could not apply the owner-only ACL to the data folder.")
        return False


def _owner_only_sids() -> tuple[Any, Any]:
    import win32api  # type: ignore[import-not-found]
    import win32security  # type: ignore[import-not-found]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        win32api.CloseHandle(token)
    return user, win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)


def has_owner_only_acl(path: Path) -> bool:
    """Whether ``path``'s DACL already is the protected user + SYSTEM one ``apply_owner_only_acl`` writes."""
    import ntsecuritycon as con  # type: ignore[import-not-found]
    import win32security  # type: ignore[import-not-found]

    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if not control & win32security.SE_DACL_PROTECTED:
        return False
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return False
    user, system = _owner_only_sids()
    expected = {str(user), str(system)}
    inherit = con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE
    seen: set[str] = set()
    for index in range(dacl.GetAceCount()):
        (ace_type, flags), mask, sid = dacl.GetAce(index)
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or str(sid) not in expected:
            return False
        if mask != con.FILE_ALL_ACCESS or flags & inherit != inherit:
            return False
        seen.add(str(sid))
    return seen == expected


def apply_owner_only_acl(path: Path) -> None:
    """Replace ``path``'s DACL with a protected one: full control for the current user and SYSTEM only."""
    import ntsecuritycon as con  # type: ignore[import-not-found]
    import win32security  # type: ignore[import-not-found]

    user, system = _owner_only_sids()
    inherit = con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE
    dacl = win32security.ACL()
    for sid in (user, system):
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, con.FILE_ALL_ACCESS, sid)
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


def legacy_data_dir() -> Path:
    if os.name == "nt":
        return _local_appdata() / LEGACY_APP_DIR_NAME
    return _local_appdata() / "localvault-prototype"


def profiles_dir() -> Path:
    path = data_dir() / "Profiles"
    path.mkdir(parents=True, exist_ok=True)
    _restrict_path(path, is_dir=True)
    return path


def vault_path() -> Path:
    """Legacy single-profile vault path.

    New code should obtain a profile-specific vault path from ProfileManager.
    This remains for backwards compatibility with tests and migration tooling.
    """

    return data_dir() / "vault.json"


def agent_state_path() -> Path:
    return data_dir() / "agent-state.json"


def install_config_path() -> Path:
    return data_dir() / "install.json"


def _restrict_path(path: Path, *, is_dir: bool = False) -> None:
    """Apply best-effort owner-only POSIX permissions.

    Windows profile ACLs are handled by the installer, and a data folder this
    app uses gets an owner-only ACL (``_restrict_data_dir``).
    chmod on Windows is not a complete ACL mechanism, so failure is
    intentionally non-fatal.
    """

    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if is_dir else 0))
    except OSError:
        pass


REPLACE_RETRY_SECONDS = 1.5


def replace_with_retry(source: Path, target: Path) -> None:
    """``os.replace`` that rides out a brief Windows sharing refusal (antivirus, indexer, backup tools)."""
    deadline = time.monotonic() + REPLACE_RETRY_SECONDS
    delay = 0.02
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if os.name != "nt" or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.2)


def atomic_write_json(path: Path, value: Any) -> None:
    """Owner-only unique temporary file; failed writes never replace the target."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    fd, name = tempfile.mkstemp(prefix=".lgk-", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_path(temp)
        _fault("before_replace", path)
        replace_with_retry(temp, path)
        _fault("after_replace", path)
        _restrict_path(path)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value
