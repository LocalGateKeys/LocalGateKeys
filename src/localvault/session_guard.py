"""Revocable, profile-scoped sessions and short-lived browser permissions.

Tokens are opaque random capabilities, never derived from a vault/master key.
They bind asynchronous work to the person and unlock session that initiated it.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class StaleSession(RuntimeError):
    pass

@dataclass(frozen=True)
class Lease:
    profile_id: str
    revision: int
    token: str

class SessionGuard:
    def __init__(self, profile_id: str, *, monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self._lock = threading.RLock()
        self._mono, self._wall = monotonic, wall_clock
        self.profile_id = profile_id
        self.revision = 0
        self._token = ""
        self._started_mono = self._started_wall = 0.0
        self.max_seconds = 0
        self._grants: dict[str, dict[str, Any]] = {}

    def stamp(self) -> tuple[str, int]:
        with self._lock:
            return self.profile_id, self.revision

    def invalidate(self, profile_id: str | None = None) -> None:
        with self._lock:
            self.revision += 1
            self._token = ""
            self._grants.clear()
            if profile_id is not None:
                self.profile_id = profile_id

    def open(self, max_seconds: int) -> Lease:
        with self._lock:
            self.invalidate()
            self._token = secrets.token_urlsafe(32)
            self._started_mono, self._started_wall = self._mono(), self._wall()
            self.max_seconds = max(0, int(max_seconds))
            return self.lease()

    def age(self) -> float:
        return max(0.0, self._mono() - self._started_mono, self._wall() - self._started_wall)

    def expired(self) -> bool:
        with self._lock:
            return bool(self._token and self.max_seconds and self.age() >= self.max_seconds)

    def lease(self) -> Lease:
        with self._lock:
            if not self._token or self.expired():
                raise StaleSession("The vault session is locked or has expired. Click Fill again.")
            return Lease(self.profile_id, self.revision, self._token)

    def valid(self, lease: Lease) -> bool:
        with self._lock:
            return bool(self._token and not self.expired() and
                        lease.profile_id == self.profile_id and lease.revision == self.revision and
                        secrets.compare_digest(lease.token, self._token))

    def require(self, lease: Lease) -> None:
        if not self.valid(lease):
            raise StaleSession("Profile/session changed. The pending action was cancelled.")

    def set_max_seconds(self, max_seconds: int) -> None:
        """Change the open session's total limit now (0: no limit).

        The limit still counts from the unlock, so a lower value can expire
        the session at once; the next auto-lock tick then locks the vault.
        """
        with self._lock:
            self.max_seconds = max(0, int(max_seconds))

    def remaining(self) -> int | None:
        with self._lock:
            if not self._token or not self.max_seconds:
                return None
            return max(0, int(self.max_seconds - self.age()))

    # A grant names what it may release: a login grant (begin_browser) never
    # releases a 2FA code and a 2FA grant (begin_totp_browser) never releases
    # a password. Card and identity fills use their own one-use approvals.
    GRANT_KINDS = frozenset({"login", "totp", "card", "identity"})

    def grant(self, origin: str, context: str, entry_ids: list[str], *, ttl: int = 90,
              kind: str = "login") -> str:
        if kind not in self.GRANT_KINDS:
            raise ValueError("Unknown grant kind")
        with self._lock:
            lease = self.lease()
            now = self._mono()
            self._grants = {k: v for k, v in self._grants.items() if v["until"] > now}
            if len(self._grants) >= 128:
                self._grants.pop(next(iter(self._grants)))
            token = secrets.token_urlsafe(32)
            self._grants[token] = {"lease": lease, "origin": origin, "context": context,
                                   "ids": tuple(entry_ids), "until": now + ttl, "kind": kind,
                                   "released": False, "submitted": False}
            return token

    def permission(self, token: str, origin: str, context: str, entry_id: str | None = None,
                   *, release: bool = False, submit: bool = False, kind: str = "login") -> Lease:
        with self._lock:
            grant = self._grants.get(token)
            if (not grant or grant.get("kind") != kind or grant["until"] <= self._mono() or grant["origin"] != origin
                    or grant["context"] != context or (entry_id is not None and entry_id not in grant["ids"])):
                raise StaleSession("The fill request expired or changed destination. Click the icon again.")
            self.require(grant["lease"])
            if release:
                if grant["released"]:
                    raise StaleSession("This fill permission was already used.")
                grant["released"] = True
                grant["entry_id"] = entry_id
                # Allow a short final validation/submit window, not reuse for a later login.
                grant["until"] = min(grant["until"], self._mono() + 8)
            if submit:
                if (not grant["released"] or grant["submitted"] or grant.get("entry_id") != entry_id):
                    raise StaleSession("There is no unused sign-in permission.")
                grant["submitted"] = True
            return grant["lease"]

    def revoke_grant(self, token: str) -> None:
        with self._lock:
            self._grants.pop(token, None)

    def revoke_entry_grants(self, entry_id: str) -> int:
        """Drop every pending fill grant that names ``entry_id``; return the count."""
        with self._lock:
            stale = [token for token, grant in self._grants.items() if entry_id in grant.get("ids", ())]
            for token in stale:
                self._grants.pop(token, None)
            return len(stale)
