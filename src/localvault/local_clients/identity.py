"""Identify a local client process: its image, signer and the terminal or IDE it runs in (Windows)."""
from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

from ..browser_ancestry import (ProcessInfo, authenticode_organisation, windows_process_lookup)

# Images that stand for "the window the user typed the command in". Windows Terminal hosts all its tabs in one
# process, so one Windows Terminal instance is one session. (conhost.exe is the console app's child, never an
# ancestor, so it is not listed.) Without any of these, the session is the program explorer.exe launched.
TERMINAL_IMAGES = frozenset({"windowsterminal.exe", "mintty.exe", "code.exe", "idea64.exe", "pycharm64.exe"})
FALLBACK_IMAGE = "explorer.exe"
MAX_CHAIN = 32


@dataclass(frozen=True)
class ClientIdentity:
    pid: int
    image: str
    parent_chain: tuple[ProcessInfo, ...]
    signer: str | None
    session_key: tuple[int, int]

    @property
    def program(self) -> str:
        return os.path.basename(self.image.replace("\\", "/")) or "?"

    @property
    def label(self) -> str:
        """For prompts: the program name, with its signer when known, else its full path."""
        if self.signer:
            return f"{self.program} ({self.signer})"
        return self.image or self.program

    @property
    def host_name(self) -> str:
        """The terminal or IDE the client runs in (its image name); the program itself when there is none."""
        for info in self.parent_chain:
            if (info.pid, info.created) == self.session_key:
                return os.path.basename(info.image.replace("\\", "/")) or self.program
        return self.program


def _base(image: str) -> str:
    return os.path.basename(image.replace("\\", "/")).lower()


def identify(pid: int, lookup: Callable[[int], ProcessInfo | None] | None = None,
             signer: Callable[[str], str | None] | None = None) -> ClientIdentity:
    """Walk the parent chain of ``pid``. Fails closed: an unknown process gets an empty image (never remembered).

    As in ``verify_browser_ancestry``, a parent created after its child is a recycled PID and ends the chain.
    """
    try:
        if lookup is None:
            lookup = windows_process_lookup()
        signer = signer or authenticode_organisation
        current = lookup(int(pid))
    except Exception:  # noqa: BLE001 - unreadable process table: unknown client
        return ClientIdentity(int(pid), "", (), None, (int(pid), 0))
    if current is None:
        return ClientIdentity(int(pid), "", (), None, (int(pid), 0))
    chain: list[ProcessInfo] = []
    seen = {current.pid}
    child = current
    while len(chain) < MAX_CHAIN and child.parent_pid > 0 and child.parent_pid not in seen:
        try:
            parent = lookup(child.parent_pid)
        except Exception:  # noqa: BLE001
            break
        if parent is None or parent.created <= 0 or parent.created >= child.created:
            break
        chain.append(parent)
        seen.add(parent.pid)
        child = parent
    session = next((p for p in chain if _base(p.image) in TERMINAL_IMAGES), None)
    if session is None:
        # The top-level program the user launched: the direct child of explorer.exe in the chain.
        for index, ancestor in enumerate(chain):
            if _base(ancestor.image) == FALLBACK_IMAGE:
                session = chain[index - 1] if index > 0 else current
                break
    key = (session.pid, session.created) if session else (current.pid, current.created)
    try:
        organisation = signer(current.image) if current.image else None
    except Exception:  # noqa: BLE001
        organisation = None
    return ClientIdentity(current.pid, current.image, tuple(chain), organisation, key)
