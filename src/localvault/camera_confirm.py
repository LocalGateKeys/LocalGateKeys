"""Retired camera-presence compatibility shim.

Frames from an ordinary camera are not identity or liveness verification. This
old API must never authorize an operation. The UI now uses password-first unlock
with an explicitly enrolled, optional Windows Hello key-protection route.
"""
from __future__ import annotations

from typing import Any


def confirm_camera_presence(parent: Any, title: str = "Camera confirmation") -> bool:
    """Fail closed for callers left over from the retired webcam preview feature."""
    return False
