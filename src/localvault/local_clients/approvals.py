"""Ask the user before a local client gets a secret; remember an approval for ten minutes."""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .identity import ClientIdentity

_log = logging.getLogger(__name__)
REMEMBER_SECONDS = 600.0
QUEUE_TIMEOUT = 60.0


@dataclass(frozen=True)
class ApprovalRequest:
    kind: Literal["ssh_sign", "cli_read"]
    client: ClientIdentity
    item_id: str
    item_title: str
    detail: str


class Approvals:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._remembered: dict[tuple, float] = {}  # key -> expiry
        self._generation = 0
        self._queue: deque[object] = deque()

    @staticmethod
    def _key(req: ApprovalRequest) -> tuple:
        return (req.kind, req.client.image.lower(), req.client.session_key, req.item_id)

    def revoke_all(self) -> None:
        """Forget every remembered approval; an ask still open when this runs is denied."""
        with self._cond:
            self._remembered.clear()
            self._generation += 1

    def _remembered_ok(self, key: tuple, now: float) -> bool:
        expiry = self._remembered.get(key)
        if expiry is None:
            return False
        if now >= expiry:
            self._remembered.pop(key, None)
            return False
        return True

    def check_or_ask(self, req: ApprovalRequest, ask: Callable[[ApprovalRequest], tuple[bool, bool]],
                     now: float, *, queue_timeout: float = QUEUE_TIMEOUT) -> bool:
        return self.check_or_ask_many([req], lambda pending: ask(pending[0]), now, queue_timeout=queue_timeout)

    def check_or_ask_many(self, reqs: list[ApprovalRequest],
                          ask: Callable[[list[ApprovalRequest]], tuple[bool, bool]],
                          now: float, *, queue_timeout: float = QUEUE_TIMEOUT) -> bool:
        """One prompt for every request not already remembered (the CLI's ``resolve_many``); each is remembered
        on its own, so a later request for one of them alone does not ask again."""
        if not reqs:
            return False
        keyed = [(req, self._key(req)) for req in reqs]
        started = time.monotonic()  # ``now`` is the caller's clock at the call; waiting and asking move it on
        with self._cond:
            if all(self._remembered_ok(key, now) for _req, key in keyed):
                return True
            ticket = object()
            self._queue.append(ticket)
            deadline = time.monotonic() + queue_timeout
            try:
                while self._queue[0] is not ticket:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._leave(ticket)
                        return False
                    self._cond.wait(remaining)
                # The one asked before us may have remembered some of these very approvals.
                waited_now = now + (time.monotonic() - started)
                pending = [(req, key) for req, key in keyed if not self._remembered_ok(key, waited_now)]
                if not pending:
                    self._leave(ticket)
                    return True
                generation = self._generation
            except BaseException:
                self._leave(ticket)
                raise
        # Ask outside the lock so revoke_all() and other checks never wait on the user.
        allowed = remember = False
        try:
            allowed, remember = ask([req for req, _key in pending])
        except Exception:  # noqa: BLE001 - any prompt failure is a denial
            _log.debug("Local client approval prompt failed", exc_info=True)
            allowed = remember = False
        finally:
            with self._cond:
                if self._generation != generation:
                    allowed = remember = False  # locked or switched profile while the prompt was open
                if allowed is True and remember is True:
                    answered_now = now + (time.monotonic() - started)  # the prompt may have been open a long time
                    for req, key in pending:
                        if req.client.image:
                            self._remembered[key] = answered_now + REMEMBER_SECONDS
                self._leave(ticket)
        return allowed is True

    def _leave(self, ticket: object) -> None:
        try:
            self._queue.remove(ticket)
        except ValueError:
            # Expected failure for this optional step: fall back to the default behaviour.
            pass
        self._cond.notify_all()


_DEFAULT = Approvals()


def default_approvals() -> Approvals:
    return _DEFAULT
