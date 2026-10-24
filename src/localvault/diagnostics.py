"""Local connection diagnostics. Exported reports deliberately omit paths and identities."""
from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Any

from .config import EXTENSION_ID, NATIVE_HOST_NAME, install_config_path, read_json
from .version import APP_VERSION, PROTOCOL_VERSION


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest().upper()


def collect(*, extension_version: str = '', extension_seen: float = 0) -> dict[str, Any]:
    report: dict[str, Any] = {
        'report_version': 1, 'app_version': APP_VERSION, 'protocol_version': PROTOCOL_VERSION,
        'windows': os.name == 'nt', 'python_version': '.'.join(map(str, sys.version_info[:3])),
        'agent_running': True, 'extension_seen_this_run': bool(extension_seen),
        'extension_recent': bool(extension_seen and time.monotonic() - extension_seen < 120),
        'extension_version': extension_version if extension_version.replace('.', '').isdigit() else 'unknown',
        'registration': {}, 'native_host_exists': False, 'native_host_hash_matches': False,
        'configured': False, 'mode': 'repository',
    }
    try:
        config = read_json(install_config_path())
        report['configured'] = True
        report['mode'] = 'repository' if config.get('mode') == 'repository' else 'installed'
        host = Path(str(config.get('native_host_path', '')))
        report['native_host_exists'] = host.is_file()
        report['native_host_hash_matches'] = host.is_file() and _hash(host) == str(config.get('native_host_sha256', '')).upper()
    except (OSError, ValueError, TypeError):
        pass
    if os.name == 'nt':
        import winreg
        for browser, subkey in [('Chrome', 'Google\\Chrome'), ('Edge', 'Microsoft\\Edge')]:
            status = 'not_registered'
            try:
                keypath = f'Software\\{subkey}\\NativeMessagingHosts\\{NATIVE_HOST_NAME}'
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath) as key:
                    manifest = Path(winreg.QueryValue(key, None))
                data = read_json(manifest)
                if not Path(str(data.get('path', ''))).is_file():
                    status = 'launcher_missing'
                elif data.get('name') != NATIVE_HOST_NAME or f'chrome-extension://{EXTENSION_ID}/' not in data.get('allowed_origins', []):
                    status = 'manifest_mismatch'
                else:
                    status = 'ready'
            except FileNotFoundError:
                status = 'not_registered_or_manifest_missing'
            except (OSError, ValueError, TypeError):
                status = 'invalid_registration'
            report['registration'][browser] = status
    return report


def display_location() -> str:
    """Shown locally only; never included in the shareable diagnostics object."""
    return str(Path(__file__).resolve().parents[2])
