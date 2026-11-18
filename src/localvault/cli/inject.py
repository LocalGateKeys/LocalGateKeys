"""``lgk inject``: fill ``{{ lgk://... }}`` in a template and write the result private to the current user."""
from __future__ import annotations

import os
import re
import tempfile

from .main import EXIT_USAGE, CliError, Forward, resolve_refs

PLACEHOLDER = re.compile(r"\{\{\s*(lgk://[^\s}]+)\s*\}\}")


def _private_dacl():  # pragma: no cover - Windows only
    import ntsecuritycon as con  # type: ignore[import-not-found]
    import win32api  # type: ignore[import-not-found]
    import win32security  # type: ignore[import-not-found]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        win32api.CloseHandle(token)
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
    return dacl


def restrict_to_current_user(path: str) -> None:
    """Windows: a protected DACL with full control for this user only. Elsewhere: mode 0600."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import win32security  # type: ignore[import-not-found]

    dacl = _private_dacl()
    win32security.SetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)


def _create_private_windows(folder: str, data: bytes) -> str:
    """Create ``.lgk-*`` with the private DACL set at creation (no sharing), write ``data`` and return the path.

    The DACL is part of CreateFile, so no other account can open the file in the moment before it is restricted.
    """
    import pywintypes  # type: ignore[import-not-found]
    import win32con  # type: ignore[import-not-found]
    import win32file  # type: ignore[import-not-found]
    import win32security  # type: ignore[import-not-found]

    attributes = win32security.SECURITY_ATTRIBUTES()
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, _private_dacl(), 0)
    descriptor.SetSecurityDescriptorControl(win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
    attributes.SECURITY_DESCRIPTOR = descriptor
    for _ in range(100):
        path = os.path.join(folder, ".lgk-" + os.urandom(8).hex())
        try:
            handle = win32file.CreateFile(
                path, win32con.GENERIC_WRITE, 0, attributes, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
        except pywintypes.error as error:
            if error.winerror in (80, 183):  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS: try another name
                continue
            raise OSError(error.winerror, error.strerror) from None
        try:
            try:
                win32file.WriteFile(handle, data)
            except pywintypes.error as error:
                raise OSError(error.winerror, error.strerror) from None
        except BaseException:
            handle.Close()
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        handle.Close()
        return path
    raise OSError("no free temporary name")


def render(template: str, forward: Forward) -> str:
    values = resolve_refs(forward, PLACEHOLDER.findall(template))
    return PLACEHOLDER.sub(lambda match: values[match.group(1)], template)


def inject_file(template_path: str, output_path: str, forward: Forward, *, force: bool = False) -> None:
    if os.path.lexists(output_path) and not force:
        raise CliError(EXIT_USAGE, "The output file already exists. Use --force to replace it.")
    try:
        with open(template_path, encoding="utf-8", newline="") as handle:
            template = handle.read()
    except (OSError, UnicodeError):
        raise CliError(EXIT_USAGE, "The template could not be read.") from None
    text = render(template, forward)
    folder = os.path.dirname(os.path.abspath(output_path))
    try:
        if os.name == "nt":
            temporary = _create_private_windows(folder, text.encode("utf-8"))
        else:
            descriptor, temporary = tempfile.mkstemp(prefix=".lgk-", dir=folder)
    except OSError:
        raise CliError(EXIT_USAGE, "The output folder is not writable.") from None
    try:
        if os.name != "nt":
            os.close(descriptor)
            restrict_to_current_user(temporary)  # before any secret reaches the file
            with open(temporary, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
        os.replace(temporary, output_path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
