"""Set up LocalGateKeys: the five-step setup guide shared by every platform (UX plan workstream 4).

Steps, adapted for Windows: 1 create vault (done by the time the vault is open), 2 unlock with
Windows Hello, 3 import, 4 check the recovery phrase (create it and retype three named words on the
show-once phrase card), 5 install the browser extension. Every step can be skipped, and the first
screen has **Skip setup**. Skipped steps stay on the "Finish setting up · 3 of 5" card at the top of
the vault until it is hidden; Settings has **Show setup again**.

Progress is per device and per profile: ``setup.json`` next to the vault, never synced. Only step
names and the hidden flag are stored, no secrets.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from ..api.result import ApiError
from ..i18n import t

STEPS = ("vault", "unlock", "import", "phrase", "browser")
LABELS = {"vault": "unlock.create", "unlock": "unlock.hello", "import": "home.importTitle",
          "phrase": "onboarding.checkYourRecoveryPhrase", "browser": "onboarding.installTheBrowserExtension"}
TEXT = {
    "vault": "onboarding.yourVaultIsCreatedAnd",
    "unlock": "onboarding.unlockWithYourFaceFingerprint",
    "import": "onboarding.bringLoginsOverFromA",
    "phrase": "onboarding.createARecoveryPhraseAnd",
    "browser": "onboarding.fillAndSaveLoginsIn",
}
PRIMARY = {"vault": "common.done", "unlock": "onboarding.setUpWindowsHello", "import": "home.import",
           "phrase": "onboarding.openRecoveryPhrase", "browser": "onboarding.testConnection"}
FORMAT = "localgatekeys-setup-v1"
FILE_NAME = "setup.json"


def _collect_report() -> dict[str, Any]:
    from ..bridge_diagnostics import collect_report

    return collect_report()


class SetupStore:
    """``setup.json``: {"format", "done": [...], "skipped": [...], "hidden": bool}. Local to this device."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        empty = {"done": [], "skipped": [], "hidden": False}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return empty
        except (OSError, ValueError):
            return empty  # a damaged file only restarts the guide
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            return empty
        done = [s for s in data.get("done", []) if s in STEPS] if isinstance(data.get("done"), list) else []
        skipped = [s for s in data.get("skipped", []) if s in STEPS and s not in done] \
            if isinstance(data.get("skipped"), list) else []
        return {"done": done, "skipped": skipped, "hidden": data.get("hidden") is True}

    def save(self, state: dict[str, Any]) -> None:
        data = {"format": FORMAT, "done": [s for s in STEPS if s in state["done"]],
                "skipped": [s for s in STEPS if s in state["skipped"]], "hidden": bool(state["hidden"])}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
            os.replace(temporary, self.path)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ApiError("invalid", t("onboarding.setupProgressCouldNotBe")) from None


class OnboardingWebService:
    def __init__(self, controller: Any, recovery: Any = None, *,
                 diagnostics: Callable[[], dict[str, Any]] = _collect_report,
                 apply_setting: Callable[[str, Any], Any] | None = None,
                 phrase_enrolled: Callable[[Path], bool] | None = None) -> None:
        self._controller = controller
        self._recovery = recovery
        self._diagnostics = diagnostics
        self._phrase_enrolled = phrase_enrolled or self._vault_phrase_enrolled
        self._message = ""
        self._connection: bool | None = None
        controller.on_lock.append(self._reset)

    @staticmethod
    def _vault_phrase_enrolled(path: Path) -> bool:
        from ..vault import recovery_phrase_enrolled

        try:
            return bool(recovery_phrase_enrolled(path))
        except Exception:  # noqa: BLE001 - unknown means not yet done
            return False

    def _reset(self) -> None:
        self._message = ""
        self._connection = None

    def _store(self) -> SetupStore:
        controller = self._controller
        if not controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        return SetupStore(Path(controller.session.path).parent / FILE_NAME)

    def _detected(self) -> set[str]:
        """Steps finished elsewhere in the app count as done here too."""
        found = {"vault"}
        hello = self._controller.offers.get("hello") if isinstance(getattr(self._controller, "offers", None), dict) \
            else None
        try:
            if hello is not None and hello():
                found.add("unlock")
        except Exception:  # noqa: BLE001, S110 - Windows Hello unavailable is a normal answer
            pass
        if self._phrase_enrolled(Path(self._controller.session.path)):
            found.add("phrase")
        return found

    def _state(self) -> tuple[SetupStore, dict[str, Any]]:
        store = self._store()
        state = store.load()
        detected = self._detected() - set(state["done"])
        if detected:
            state["done"] = [s for s in STEPS if s in state["done"] or s in detected]
            state["skipped"] = [s for s in state["skipped"] if s not in detected]
        return store, state

    @staticmethod
    def _current(state: dict[str, Any]) -> str | None:
        for step in STEPS:
            if step not in state["done"] and step not in state["skipped"]:
                return step
        return None

    def _view(self, state: dict[str, Any]) -> dict[str, Any]:
        current = self._current(state)
        done = len(state["done"])
        remaining = [s for s in STEPS if s not in state["done"]]
        return {
            "title": t("onboardingPage.title"),
            "subtitle": t("onboarding.fiveShortStepsSkipAny"),
            "steps": [{"key": s, "label": t(LABELS[s]), "text": t(TEXT[s]), "primary": t(PRIMARY[s]),
                       "state": "done" if s in state["done"] else "skipped" if s in state["skipped"]
                       else "current" if s == current else "todo"} for s in STEPS],
            "current": current, "done": done, "total": len(STEPS),
            "progress": f"{done} of {len(STEPS)}",
            "message": self._message,
            "complete": not remaining,
            "card": bool(remaining) and not state["hidden"],
            "hidden": state["hidden"],
        }

    def view(self) -> dict[str, Any]:
        store, state = self._state()
        return self._view(state)

    def card(self) -> dict[str, Any]:
        """The vault card: shown while a step is left and the card is not hidden."""
        view = self.view()
        return {"card": view["card"], "progress": view["progress"], "done": view["done"], "total": view["total"]}

    def test_connection(self) -> dict[str, Any]:
        """The browser-connection check, run as its own call (outside the vault lock): it can take seconds."""
        try:
            report = self._diagnostics()
        except Exception:  # noqa: BLE001 - an unavailable bridge is a normal answer here
            report = {}
        connection = report.get("connection", {}) if isinstance(report, dict) else {}
        self._connection = connection.get("status") == "connected"
        return {"connected": self._connection}

    @staticmethod
    def _step(value: Any) -> str:
        if value not in STEPS:
            raise ApiError("invalid", t("onboarding.unknownSetupStep"))
        return value

    def _mark(self, store: SetupStore, state: dict[str, Any], step: str) -> None:
        if step not in state["done"]:
            state["done"].append(step)
        state["skipped"] = [s for s in state["skipped"] if s != step]
        store.save(state)

    def perform(self, step: Any) -> dict[str, Any]:
        """Start (or confirm) one step. Steps done on another page return a ``route`` to open."""
        step = self._step(step)
        store, state = self._state()
        self._message = ""
        route = None
        if step == "vault":
            self._mark(store, state, step)
        elif step == "unlock":
            route = {"route": "hello", "params": {"startHello": True}}
        elif step == "import":
            self._mark(store, state, step)  # opening Import is the step; cancelling it there is the user's choice
            route = {"route": "import"}
        elif step == "phrase":
            if "phrase" not in state["done"]:
                route = {"route": "recovery", "params": {"initial": "phrase"}}
                self._message = t("onboarding.createThePhraseWriteIt")
        elif step == "browser":
            if self._connection is None:
                self.test_connection()  # the page normally ran it already, outside the vault lock
            connected, self._connection = self._connection, None
            if connected:
                self._mark(store, state, step)
            else:
                self._message = t("onboarding.theBrowserExtensionDidNot")
                route = None
        return {**self._view(state), **({"open": route} if route else {})}

    def skip(self, step: Any = None) -> dict[str, Any]:
        store, state = self._state()
        step = self._current(state) if step is None else self._step(step)
        if step is not None and step not in state["done"] and step not in state["skipped"]:
            state["skipped"].append(step)
            store.save(state)
        self._message = ""
        return self._view(state)

    def skip_all(self) -> dict[str, Any]:
        """**Skip setup** on the first screen: every step left goes to the card."""
        store, state = self._state()
        state["skipped"] = [s for s in STEPS if s not in state["done"]]
        store.save(state)
        self._message = ""
        return self._view(state)

    def hide(self) -> dict[str, Any]:
        store, state = self._state()
        state["hidden"] = True
        store.save(state)
        return self._view(state)

    def show_again(self) -> dict[str, Any]:
        """Settings › **Show setup again**: the card comes back and skipped steps are offered again."""
        store, state = self._state()
        state["hidden"] = False
        state["skipped"] = []
        store.save(state)
        self._message = ""
        return self._view(state)
