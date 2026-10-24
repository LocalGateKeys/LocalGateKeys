from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .winpaths import system32, windows_powershell


def file_sha256(path: str) -> str:
    """Return an uppercase SHA-256 fingerprint for an executable file."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest().upper()


def authenticode_info(exe_path: str) -> dict[str, Any] | None:
    """Return best-effort Authenticode metadata without trusting it as policy.

    The prototype stores the signer thumbprint to detect obvious executable
    substitution. A production build should call WinVerifyTrust directly and
    define a publisher/update policy.

    PowerShell is launched by its absolute System32 path (never by bare name,
    which Windows resolves through the app and current directories first) with
    a module path limited to the in-box modules, so a planted ``powershell.exe``
    or a shadowing ``Microsoft.PowerShell.Security`` module cannot forge the
    signer that native-host and desktop-fill pins rely on.
    """

    if os.name != "nt":
        return None
    path = str(Path(exe_path).resolve())
    script = (
        "$s=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath $env:LOCALVAULT_SIGNATURE_TARGET;"
        "[pscustomobject]@{"
        "Status=[string]$s.Status;"
        "StatusMessage=[string]$s.StatusMessage;"
        "Subject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
        "Thumbprint=if($s.SignerCertificate){[string]$s.SignerCertificate.Thumbprint}else{''}"
        "}|ConvertTo-Json -Compress"
    )
    try:
        child_environment = os.environ.copy()
        child_environment["LOCALVAULT_SIGNATURE_TARGET"] = path
        child_environment["PSModulePath"] = system32(os.path.join("WindowsPowerShell", "v1.0", "Modules"))
        result = subprocess.run(
            [
                windows_powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
            env=child_environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            return None
        return {
            "status": str(value.get("Status", "")),
            "status_message": str(value.get("StatusMessage", "")),
            "subject": str(value.get("Subject", "")),
            "thumbprint": str(value.get("Thumbprint", "")).upper(),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
