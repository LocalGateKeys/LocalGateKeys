"""In-memory witness state for one unlock session (2026-10-29 review fix).

A LAN exchange must not save the vault on every request (C1), so the stored
``peer_generations`` can lag behind what this device has already checked.  The
highest generation seen from each peer is kept here for the lifetime of the
unlocked session and is what every check and every published witness uses;
the stored value catches up when ``lan_sync.apply_witness`` saves (a new peer,
a new capability or suspicion, or a rise at most once per
``SAVE_INTERVAL_SECONDS`` per peer), when a folder run saves its state, and
when ``lan_sync.flush_witness`` runs at the end of the service.

The memory is bound to the session object (weakly) and to the group id and
device id it was filled for; a different group or device starts empty.
"""
from __future__ import annotations

import threading
import time
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: A peer's risen generation is saved at most this often during a session (seconds).
SAVE_INTERVAL_SECONDS = 600

#: Monotonic clock (tests replace it).
monotonic: Callable[[], float] = time.monotonic


@dataclass
class WitnessMemory:
    group_id: str
    device_id: str
    generations: dict[str, int] = field(default_factory=dict)
    #: Monotonic time of the last save that stored each peer's generation.
    saved_at: dict[str, float] = field(default_factory=dict)
    #: Consecutive ``bad-view`` refusals of a format-2 view, per peer.
    refusals: dict[str, int] = field(default_factory=dict)


_lock = threading.Lock()
_by_session: weakref.WeakKeyDictionary[Any, WitnessMemory] = weakref.WeakKeyDictionary()


def memory(session: Any, group_id: str, device_id: str) -> WitnessMemory | None:
    """The memory of *session* for this group and device (created empty), or None if it cannot be kept."""
    with _lock:
        try:
            mem = _by_session.get(session)
        except TypeError:
            return None  # not weak-referenceable: every rise is saved at once (no throttle)
        if mem is None or mem.group_id != group_id or mem.device_id != device_id:
            mem = WitnessMemory(group_id, device_id)
            try:
                _by_session[session] = mem
            except TypeError:
                return None
        return mem


def merged(stored: Mapping[str, int], mem: WitnessMemory | None) -> dict[str, int]:
    """*stored* raised to the remembered generations (never lowered)."""
    out = dict(stored)
    if mem is not None:
        for dev, gen in mem.generations.items():
            if gen > out.get(dev, -1):
                out[dev] = gen
    return out


__all__ = ["SAVE_INTERVAL_SECONDS", "WitnessMemory", "memory", "merged"]
