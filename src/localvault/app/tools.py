"""Password generator and command palette for the WebView UI (no UI toolkit)."""
from __future__ import annotations

import math
from typing import Any

from ..api.result import ApiError
from ..password_tools import (
    STRENGTH_LABELS,
    estimate_strength,
    generate_from_options,
    generate_username,
    load_wordlist,
    normalize_generator_options,
)
from ..shell.commands import COMMANDS, palette_results, registered_section_commands
from .setting_links import clipboard_result


class GeneratorService:
    def __init__(self, controller: Any) -> None:
        self._controller = controller

    def get(self) -> dict[str, Any]:
        options = normalize_generator_options(self._controller.settings.generator_preferences)
        return {"options": options.as_dict()}

    def generate(self, options: dict[str, Any]) -> dict[str, Any]:
        settings = self._controller.settings
        normalized = normalize_generator_options({**(settings.generator_preferences or {}), **dict(options or {})})
        try:
            value = generate_from_options(normalized)
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from None
        settings.generator_preferences = normalized.as_dict()
        try:
            settings.save()
        except Exception:  # noqa: BLE001, S110 - preferences are a convenience
            pass
        return {"value": value, "health": self._health(value, normalized), "options": normalized.as_dict()}

    @staticmethod
    def _health(value: str, options: Any) -> str:
        estimate = estimate_strength(value)
        label = STRENGTH_LABELS[max(0, min(4, estimate.score))]
        if options.mode == "passphrase":
            bits = round(options.words * math.log2(max(2, len(load_wordlist()))))
            return (f"{options.words} randomly selected words · about {bits} bits from the word list · "
                    f"{label}, {estimate.crack_time_display} to guess offline")
        return f"{label} · {estimate.crack_time_display} to guess offline · Local estimate, not a security guarantee"

    def username(self, style: str) -> dict[str, Any]:
        try:
            return {"value": generate_username("alias" if style == "alias" else "word")}
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from None

    def copy(self, value: str) -> dict[str, Any]:
        clipboard = self._controller.clipboard
        clipboard.copy(str(value))
        return clipboard_result("Generated password copied.", clipboard)


# Commands the classic window has but this window has no page for.
NOT_IN_WINDOW = frozenset({"safe-workspace", "typed-items"})

_NAVIGATE = {
    "generate-password": {"navigate": "generator"},
    "new-item": {"navigate": "new-item"},
    "settings": {"navigate": "settings"},
    "security-center": {"navigate": "security"},
    "change-master": {"navigate": "master"},
    "backup-now": {"navigate": "recovery", "initial": "create"},
    "backup-verify": {"navigate": "recovery", "initial": "verify"},
    "backup-restore": {"navigate": "recovery", "initial": "restore"},
    "recovery-kit": {"navigate": "recovery", "initial": "kit"},
}


class PaletteService:
    def __init__(self, controller: Any) -> None:
        self._controller = controller

    def _all_commands(self) -> dict[str, Any]:
        return {c.id: c for c in (*COMMANDS, *registered_section_commands())}

    def query(self, query: str, scope: str) -> dict[str, Any]:
        controller = self._controller
        unlocked = controller.is_unlocked()
        text = str(query or "").strip()
        scope = str(scope or "everything")
        collection_ids: set[str] | None = None
        if text.startswith(">"):
            scope, text = "actions", text[1:].strip()
        elif text.startswith("#"):
            scope, text = "items", f"tag:{text[1:].strip()}"
        elif text.startswith("@") and unlocked:
            needle = text[1:].strip().casefold()
            scope, text = "items", ""
            try:
                collection_ids = {str(c["id"]) for c in controller.session.collections.list()
                                  if needle in str(c.get("name", "")).casefold()}
            except Exception:  # noqa: BLE001
                collection_ids = set()
        summaries: list[Any] = []
        if unlocked:
            try:
                summaries = list(controller.session.item_service.all_metadata_summaries())
            except Exception:  # noqa: BLE001
                summaries = []
        if collection_ids is not None:
            matched = [s for s in summaries if set(map(str, getattr(s, "collection_ids", ()) or ())) & collection_ids]
            rows = [{"kind": "item", "title": str(getattr(s, "title", "")), "subtitle": "", "group": "Items",
                     "ref": self._ref(s)} for s in matched[:12]]
            return {"rows": rows}
        out = []
        for row in palette_results(text, summaries, unlocked=unlocked, scope=scope):
            if row.kind != "item" and row.ref.id in NOT_IN_WINDOW:
                continue  # no page for it in this window yet: don't offer a dead end
            entry = {"kind": row.kind, "title": row.title, "subtitle": row.subtitle, "group": row.group}
            if row.kind == "item":
                entry["ref"] = self._ref(row.ref)
            else:
                entry["command_id"] = row.ref.id
            out.append(entry)
        return {"rows": out}

    @staticmethod
    def _ref(summary: Any) -> dict[str, str]:
        kind = str(summary.kind)
        return {"source": "credential" if kind in ("web", "desktop") else "typed", "id": str(summary.id), "kind": kind}

    def run(self, command_id: str) -> dict[str, Any]:
        command = self._all_commands().get(str(command_id))
        if command is None:
            raise ApiError("not_found", "Unknown command.")
        if command.requires_unlock and not self._controller.is_unlocked():
            raise ApiError("locked", "Unlock this profile first.")
        if command.id == "lock-now":
            self._controller.lock()
            return {"done": "Vault locked."}
        if command.id == "emergency-lock":
            from .lockmodes import LockModes

            LockModes(self._controller).emergency_lock()
            return {"done": "Emergency lock."}
        if command.id in _NAVIGATE:
            return dict(_NAVIGATE[command.id])
        kwargs = dict(command.kwargs)
        if command.method == "settings_clicked" and "section" in kwargs:
            return {"navigate": "settings", "section": str(kwargs["section"])}
        return {"navigate": command.id}
