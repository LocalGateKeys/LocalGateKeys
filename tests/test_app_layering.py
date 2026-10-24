"""Stage 0 layering: modules in localvault.app (and other Tk-free core) import without tkinter."""

from __future__ import annotations

import subprocess
import sys

APP_MODULES = [
    "localvault.app.catalog", "localvault.app.ui_port", "localvault.clipboard_guard",
    "localvault.app.unlock_backoff", "localvault.app.licence_view", "localvault.app.recovery_center",
    "localvault.app.transfer_controller", "localvault.app.workspace_center", "localvault.app.sync_view",
    "localvault.web.bus", "localvault.api.result", "localvault.web.ui_port", "localvault.app.controller", "localvault.api.bridge",
    "localvault.app.presentation", "localvault.app.home", "localvault.app.secrets",
    "localvault.app.login_editor", "localvault.app.tools", "localvault.app.typed", "localvault.app.typed_schema", "localvault.app.documents", "localvault.app.trash", "localvault.app.trash_restore",
    "localvault.app.login_extras", "localvault.app.security", "localvault.app.health", "localvault.app.master", "localvault.app.recovery", "localvault.app.schedule", "localvault.app.lockmodes", "localvault.app.face_capture", "localvault.app.unlock_methods", "localvault.app.settings", "localvault.app.licence", "localvault.app.updates", "localvault.app.profiles", "localvault.app.connections", "localvault.app.sync", "localvault.app.import_export", "localvault.app.transfer_web", "localvault.app.workspace", "localvault.app.onboarding", "localvault.app.startup", "localvault.web.host", "localvault.app.desktop",
]


def test_app_modules_import_without_tkinter():
    code = "import sys; sys.modules['tkinter'] = None\n" + "\n".join(f"import {m}" for m in APP_MODULES)
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


