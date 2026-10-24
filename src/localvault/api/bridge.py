"""The object pywebview exposes to the page as ``window.pywebview.api``.

Only public methods are callable from JavaScript, so collaborators live in
underscore attributes. Every method validates its arguments, returns the
``api.result`` shape and never raises to the page.
"""
from __future__ import annotations

import webbrowser
from contextlib import ExitStack
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..secret_text import SecretText
from ..version import APP_VERSION
from .result import ApiError, fail, guarded, ok

MAX_PASSWORD_LENGTH = 1024


class WindowOps(Protocol):
    def minimize(self) -> None: ...

    def toggle_maximize(self) -> None: ...

    def close(self) -> None: ...


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ApiError("invalid", f"Invalid {name}.")
    return value


def _secret(value: Any, name: str, limit: int = MAX_PASSWORD_LENGTH) -> SecretText:
    """The master password as a wipeable ``SecretText``; the calling bridge method wipes it when it returns."""
    text = _text(value, name, limit)
    try:
        return SecretText.from_str(text)
    except ValueError:
        # Unencodable text (a lone surrogate): a fixed message that never echoes the value.
        raise ApiError("invalid", f"Invalid {name}.") from None


def _optional_text(value: Any, name: str, limit: int) -> str | None:
    return None if value is None else _text(value, name, limit)


def _ref(value: Any) -> dict[str, str]:
    """An item reference from the page: exactly {source, id, kind} as short strings."""
    if (not isinstance(value, dict) or set(value) != {"source", "id", "kind"}
            or value.get("source") not in ("credential", "typed")
            or not all(isinstance(value[k], str) and 0 < len(value[k]) <= 128 for k in ("id", "kind"))):
        raise ApiError("invalid", "Invalid item.")
    return {"source": value["source"], "id": value["id"], "kind": value["kind"]}


def _ids(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 5000 or not all(isinstance(v, str) and 0 < len(v) <= 128 for v in value):
        raise ApiError("invalid", "Invalid selection.")
    return list(value)


def _int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError("invalid", f"Invalid {name}.")
    return value


def _dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 64:
        raise ApiError("invalid", f"Invalid {name}.")
    return value


class _NoDialogs:
    """Used when no window exists (tests, headless): every file dialog is unavailable."""

    def open_file(self, title: str, file_types: tuple[str, ...] | None = None) -> Any:
        raise ApiError("unavailable", "File dialogs are not available here.")

    def save_file(self, title: str, name: str) -> Any:
        raise ApiError("unavailable", "File dialogs are not available here.")

    def choose_folder(self, title: str) -> Any:
        raise ApiError("unavailable", "File dialogs are not available here.")


class Api:
    def __init__(self, controller: Any, port: Any, window_ops: WindowOps, *, glass: bool = False,
                 dialogs: Any = None) -> None:
        from ..app.home import HomeService
        from ..app.login_editor import LoginEditorService
        from ..app.secrets import SecretService
        from ..app.tools import GeneratorService, PaletteService
        from ..password_tools import generate_from_preferences

        self._controller = controller
        self._port = port
        self._window_ops = window_ops
        self._glass = glass
        self._home = HomeService(controller)
        self._secrets = SecretService(controller, port)
        self._editor = LoginEditorService(
            controller, port, generate=lambda: generate_from_preferences(controller.settings.generator_preferences))
        self._generator = GeneratorService(controller)
        self._palette = PaletteService(controller)
        from ..app.documents import DocumentService
        from ..app.login_extras import LoginExtrasService
        from ..app.trash import TrashService
        from ..app.typed import TypedService

        self._typed = TypedService(controller, port)
        self._documents = DocumentService(controller, port, dialogs or _NoDialogs())
        self._trash = TrashService(controller, port)
        self._extras = LoginExtrasService(controller, port, self._editor)
        from ..app.qr_import import QrImportService

        self._qr = QrImportService(controller, self._editor, self._extras, emit=controller._bus.emit)
        self._dialogs = dialogs or _NoDialogs()
        self._security = None
        self._stage4()

    def _changed(self) -> None:
        self._controller._bus.emit("items.changed", {})

    # ------------------------------------------------------------------ app
    @guarded
    def app_info(self) -> dict[str, Any]:
        return ok(version=APP_VERSION, glass=self._glass)

    # -------------------------------------------------------------- profiles
    @guarded
    def profiles_list(self) -> dict[str, Any]:
        return ok(profiles=self._controller.list_profiles())

    @guarded
    def profiles_select(self, profile_id: Any) -> dict[str, Any]:
        return ok(**self._controller.select_profile(_text(profile_id, "profile", 128)))

    # ----------------------------------------------------------------- vault
    @guarded
    def vault_state(self) -> dict[str, Any]:
        return ok(**self._controller.state())

    @guarded
    def vault_unlock(self, password: Any) -> dict[str, Any]:
        with _secret(password, "password") as secret:
            return ok(**self._controller.unlock(secret))

    @guarded
    def vault_create(self, password: Any, confirm: Any) -> dict[str, Any]:
        with ExitStack() as owned:  # each SecretText is wiped on exit, even when a later one is refused
            secret = owned.enter_context(_secret(password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._controller.create(secret, confirmation))

    @guarded
    def vault_lock(self) -> dict[str, Any]:
        return ok(**self._controller.lock())

    # ---------------------------------------------------------------- modals
    @guarded
    def modal_answer(self, request_id: Any, value: Any = None) -> dict[str, Any]:
        return ok(accepted=bool(self._port.answer(_text(request_id, "request", 64), value)))

    # ---------------------------------------------------------------- window
    @guarded
    def window_theme_sync(self) -> dict[str, Any]:
        set_theme = getattr(self._window_ops, "set_theme", None)
        if callable(set_theme):
            set_theme(self._controller.settings.appearance)
        return ok()

    @guarded
    def window_minimize(self) -> dict[str, Any]:
        self._window_ops.minimize()
        return ok()

    @guarded
    def window_toggle_maximize(self) -> dict[str, Any]:
        self._window_ops.toggle_maximize()
        return ok()

    @guarded
    def window_close(self) -> dict[str, Any]:
        self._window_ops.close()
        return ok()

    @guarded
    def system_open_url(self, url: Any) -> dict[str, Any]:
        text = _text(url, "link", 2048)
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return fail("invalid", "Only web links can be opened.")
        webbrowser.open(text)
        return ok()

    # ------------------------------------------------------------------ home
    @guarded
    def nav_get(self) -> dict[str, Any]:
        return ok(**self._home.nav())

    @guarded
    def items_list(self, filter_kind: Any = None, chip: Any = None, query: Any = "") -> dict[str, Any]:
        return ok(**self._home.items(_optional_text(filter_kind, "filter", 256), _optional_text(chip, "chip", 32),
                                     _text(query or "", "search", 512)))

    @guarded
    def quick_search(self, query: Any = "", kind: Any = "") -> dict[str, Any]:
        try:
            return ok(**self._home.quick_search(_text(query or "", "search", 512), _text(kind or "", "type", 32)))
        except ValueError as exc:
            raise ApiError("invalid", str(exc)) from exc

    @guarded
    def overview_get(self) -> dict[str, Any]:
        return ok(**self._home.overview())

    @guarded
    def codes_list(self) -> dict[str, Any]:
        return ok(**self._home.codes())

    @guarded
    def status_get(self) -> dict[str, Any]:
        return ok(**self._home.status())

    # ----------------------------------------------------------------- items
    @guarded
    def item_detail(self, ref: Any) -> dict[str, Any]:
        return ok(**self._secrets.detail(_ref(ref)))

    @guarded
    def item_reveal(self, ref: Any) -> dict[str, Any]:
        return ok(**self._secrets.reveal_password(_ref(ref)))

    @guarded
    def item_copy(self, ref: Any, field: Any) -> dict[str, Any]:
        return ok(**self._secrets.copy(_ref(ref), _text(field, "field", 16)))

    @guarded
    def item_totp(self, ref: Any) -> dict[str, Any]:
        return ok(**self._secrets.totp(_ref(ref)))

    @guarded
    def item_favorite(self, ref: Any, value: Any) -> dict[str, Any]:
        result = self._secrets.set_favorite(_ref(ref), bool(value))
        self._changed()
        return ok(**result)

    @guarded
    def item_trash(self, ref: Any) -> dict[str, Any]:
        result = self._secrets.trash(_ref(ref))
        self._changed()
        return ok(**result)

    @guarded
    def item_open_website(self, ref: Any) -> dict[str, Any]:
        return ok(**self._secrets.open_website(_ref(ref)))

    # ---------------------------------------------------------------- editor
    @guarded
    def login_new(self) -> dict[str, Any]:
        return ok(**self._editor.open_new())

    @guarded
    def login_open(self, ref: Any) -> dict[str, Any]:
        return ok(**self._editor.open(_ref(ref)))

    @guarded
    def login_update(self, draft_id: Any, changes: Any) -> dict[str, Any]:
        return ok(**self._editor.update(_text(draft_id, "editor", 64), _dict(changes, "changes")))

    @guarded
    def login_regenerate(self, draft_id: Any, chip: Any) -> dict[str, Any]:
        chip = _text(chip, "chip", 16)
        if chip not in ("Passphrase", "Random", "PIN"):
            raise ApiError("invalid", "Invalid chip.")
        return ok(**self._editor.regenerate(_text(draft_id, "editor", 64), chip))

    @guarded
    def login_save(self, draft_id: Any) -> dict[str, Any]:
        draft_id = _text(draft_id, "editor", 64)
        try:
            result = self._editor.save(draft_id)
        except ApiError as exc:
            if exc.code == "invalid":
                try:
                    view = self._editor.view(draft_id)
                except ApiError:
                    raise exc from None
                return {**fail(exc.code, exc.message), "view": view}
            raise
        self._changed()
        return ok(**result)

    @guarded
    def login_close(self, draft_id: Any) -> dict[str, Any]:
        self._editor.close(_text(draft_id, "editor", 64))
        return ok()

    # ----------------------------------------------------------------- tools
    @guarded
    def generator_get(self) -> dict[str, Any]:
        return ok(**self._generator.get())

    @guarded
    def generator_generate(self, options: Any = None) -> dict[str, Any]:
        return ok(**self._generator.generate(_dict(options or {}, "options")))

    @guarded
    def generator_username(self, style: Any = "word") -> dict[str, Any]:
        return ok(**self._generator.username(_text(style, "style", 16)))

    @guarded
    def generator_copy(self, value: Any) -> dict[str, Any]:
        return ok(**self._generator.copy(_text(value, "password", 4096)))

    @guarded
    def palette_query(self, query: Any = "", scope: Any = "everything") -> dict[str, Any]:
        return ok(**self._palette.query(_text(query or "", "search", 512), _text(scope, "scope", 16)))

    @guarded
    def palette_run(self, command_id: Any) -> dict[str, Any]:
        return ok(**self._palette.run(_text(command_id, "command", 64)))

    # ----------------------------------------------------------- typed items
    @guarded
    def typed_schema(self) -> dict[str, Any]:
        return ok(**self._typed.schema())

    @guarded
    def typed_detail(self, ref: Any) -> dict[str, Any]:
        return ok(**self._typed.detail(_ref(ref)))

    @guarded
    def typed_open(self, ref: Any) -> dict[str, Any]:
        return ok(**self._typed.open_edit(_ref(ref)))

    @guarded
    def typed_save(self, ref: Any, kind: Any, data: Any) -> dict[str, Any]:
        result = self._typed.save(None if ref is None else _ref(ref), _text(kind, "kind", 32), _dict(data, "item"))
        self._changed()
        return ok(**result)

    @guarded
    def typed_reveal(self, ref: Any, field: Any) -> dict[str, Any]:
        return ok(**self._typed.reveal(_ref(ref), _text(field, "field", 64)))

    @guarded
    def typed_copy(self, ref: Any, field: Any) -> dict[str, Any]:
        return ok(**self._typed.copy(_ref(ref), _text(field, "field", 64)))

    # -------------------------------------------------------------- documents
    @guarded
    def doc_create(self, title: Any = "", description: Any = "") -> dict[str, Any]:
        result = self._documents.create(_text(title or "", "title", 512), _text(description or "", "description", 2048))
        self._changed()
        return ok(**result)

    @guarded
    def doc_replace(self, ref: Any) -> dict[str, Any]:
        result = self._documents.replace(_ref(ref))
        self._changed()
        return ok(**result)

    @guarded
    def doc_info(self, ref: Any) -> dict[str, Any]:
        return ok(**self._documents.info(_ref(ref)))

    @guarded
    def doc_preview(self, ref: Any) -> dict[str, Any]:
        return ok(**self._documents.preview(_ref(ref)))

    @guarded
    def doc_open(self, ref: Any) -> dict[str, Any]:
        return ok(**self._documents.open_externally(_ref(ref)))

    @guarded
    def doc_save_copy(self, ref: Any) -> dict[str, Any]:
        return ok(**self._documents.save_copy(_ref(ref)))

    # ------------------------------------------------------------------ trash
    @guarded
    def trash_list(self) -> dict[str, Any]:
        return ok(**self._trash.list())

    @guarded
    def trash_restore(self, ids: Any) -> dict[str, Any]:
        result = self._trash.restore(_ids(ids))
        self._changed()
        return ok(**result)

    @guarded
    def trash_purge(self, ids: Any) -> dict[str, Any]:
        result = self._trash.purge(_ids(ids))
        self._changed()
        return ok(**result)

    @guarded
    def trash_empty(self) -> dict[str, Any]:
        result = self._trash.empty()
        self._changed()
        return ok(**result)

    # ----------------------------------------------------------- login extras
    @guarded
    def history_list(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.history(_ref(ref)))

    @guarded
    def history_copy(self, ref: Any, index: Any, changed_at: Any) -> dict[str, Any]:
        return ok(**self._extras.history_copy(_ref(ref), _int(index, "row"), _int(changed_at, "row")))

    @guarded
    def recovery_count(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.recovery_count(_ref(ref)))

    @guarded
    def recovery_get(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.recovery_codes(_ref(ref)))

    @guarded
    def recovery_save(self, ref: Any, codes: Any) -> dict[str, Any]:
        if not isinstance(codes, list) or len(codes) > 100 or not all(isinstance(c, str) and len(c) <= 512 for c in codes):
            raise ApiError("invalid", "At most 100 recovery codes of up to 512 characters.")
        return ok(**self._extras.recovery_codes_save(_ref(ref), codes))

    @guarded
    def recovery_use_next(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.recovery_use_next(_ref(ref)))

    @guarded
    def fields_get(self, ref: Any, reveal: Any = False) -> dict[str, Any]:
        return ok(**self._extras.custom_fields(_ref(ref), reveal=bool(reveal)))

    @guarded
    def fields_save(self, ref: Any, fields: Any, removed: Any = None) -> dict[str, Any]:
        if not isinstance(fields, list) or len(fields) > 50 or not all(isinstance(f, dict) for f in fields):
            raise ApiError("invalid", "At most 50 custom fields")
        removed = [] if removed is None else removed
        if not isinstance(removed, list) or len(removed) > 50:
            raise ApiError("invalid", "Invalid removed fields.")
        return ok(**self._extras.custom_fields_save(_ref(ref), fields,
                                                    removed=[_int(i, "removed field") for i in removed]))

    @guarded
    def policy_get(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.policy(_ref(ref)))

    @guarded
    def policy_save(self, ref: Any, changes: Any) -> dict[str, Any]:
        return ok(**self._extras.policy_save(_ref(ref), _dict(changes, "policy")))

    @guarded
    def ga_parse(self, text: Any, label: Any = "", origin: Any = "") -> dict[str, Any]:
        return ok(**self._extras.ga_parse(_text(text, "export", 65536), label=_text(label or "", "label", 512),
                                          origin=_text(origin or "", "origin", 2048)))

    @guarded
    def ga_apply(self, draft_id: Any, token: Any, index: Any) -> dict[str, Any]:
        return ok(**self._extras.ga_apply(_text(draft_id, "editor", 64), _text(token, "import", 64), _int(index, "account")))

    @guarded
    def qr_scan_image(self, draft_id: Any, image: Any) -> dict[str, Any]:
        return ok(**self._qr.scan_image(_text(draft_id, "editor", 64), _text(image, "image", 17 * 1024 * 1024)))

    @guarded
    def qr_scan_camera(self, draft_id: Any) -> dict[str, Any]:
        return ok(**self._qr.scan_camera(_text(draft_id, "editor", 64)))

    @guarded
    def qr_cancel(self) -> dict[str, Any]:
        return ok(**self._qr.cancel())

    @guarded
    def qr_switch_camera(self) -> dict[str, Any]:
        return ok(**self._qr.switch_camera())

    # --------------------------------------------------------------- security
    def _stage4(self) -> None:
        if getattr(self, "_security", None) is not None:
            return
        from ..app.health import HealthService
        from ..app.lockmodes import LockModes
        from ..app.master import MasterService
        from ..app.recovery import RecoveryWebService
        from ..app.security import SecurityService

        bus = self._controller._bus
        self._security = SecurityService(self._controller, self._home)
        self._health = HealthService(self._controller, self._port, self._home, bus)
        self._master = MasterService(self._controller, self._port)
        self._recovery = RecoveryWebService(self._controller, self._port, self._dialogs)
        self._lockmodes = LockModes(self._controller)
        from ..app.schedule import ScheduleRunner

        self._schedule = ScheduleRunner(self._controller, bus)
        from ..app.unlock_methods import FaceService, HelloService

        hwnd = getattr(self._window_ops, "hwnd", None)
        self._hello = HelloService(self._controller, self._port, hwnd=hwnd if callable(hwnd) else (lambda: None))
        self._face = FaceService(self._controller, self._port, bus)
        self._controller.hello_reauth = self._hello.reauthenticate
        from ..app.connections import ConnectionsService
        from ..app.licence import LicenceService
        from ..app.profiles import ProfilesService
        from ..app.settings import SettingsService
        from ..app.updates import UpdatesService

        self._settings = SettingsService(self._controller, self._port, bus, dialogs=self._dialogs,
                                         schedule=self._schedule)
        self._licence = LicenceService(self._controller, self._port, self._dialogs)
        self._updates = UpdatesService(self._controller, self._port)
        self._profiles = ProfilesService(self._controller, self._port, self._dialogs)
        self._connections = ConnectionsService(self._port, self._dialogs)
        from ..app.sync import SyncWebService

        self._sync = SyncWebService(self._controller, self._port, bus, self._dialogs,
                                    on_licence=self._licence.after_unlock)
        from ..app.import_export import ExportService, ImportService
        from ..app.transfer_web import TransferService

        self._imports = ImportService(self._controller, self._port, self._dialogs, bus)
        self._exports = ExportService(self._controller, self._port, self._dialogs)
        self._transfer = TransferService(self._controller, self._port, self._dialogs)
        from ..app.phone_backup_web import PhoneBackupService

        self._phone_backup = PhoneBackupService(self._controller, self._port, self._dialogs,
                                                on_licence=self._licence.after_unlock)
        from ..app.onboarding import OnboardingWebService
        from ..app.workspace import (
            ActivityService,
            CatalogService,
            CollectionsService,
            RemindersService,
        )

        self._reminders = RemindersService(self._controller, self._changed)
        self._activity = ActivityService(self._controller)
        self._collections = CollectionsService(self._controller, self._changed)
        self._catalog = CatalogService(self._controller, self._port, self._changed)
        self._onboarding = OnboardingWebService(self._controller, self._recovery,
                                                apply_setting=self._settings.apply)

    @guarded
    def security_center(self) -> dict[str, Any]:
        return ok(**self._security.center())

    @guarded
    def security_set(self, key: Any, value: Any) -> dict[str, Any]:
        if not isinstance(value, bool):
            raise ApiError("invalid", "Invalid switch value.")
        return ok(**self._security.set_setting(_text(key, "setting", 64), value))

    @guarded
    def health_report(self, filter_key: Any = None) -> dict[str, Any]:
        return ok(**self._health.report(_optional_text(filter_key, "filter", 16)))

    @guarded
    def health_scan(self, ids: Any = None) -> dict[str, Any]:
        return ok(**self._health.scan(None if ids is None else _ids(ids)))

    @guarded
    def health_cancel(self) -> dict[str, Any]:
        return ok(**self._health.cancel())

    @guarded
    def master_info(self) -> dict[str, Any]:
        return ok(**self._master.info())

    @guarded
    def master_change(self, current: Any, new: Any, confirm: Any, phrase: Any = None) -> dict[str, Any]:
        with ExitStack() as owned:
            current_secret = owned.enter_context(_secret(current, "password"))
            new_secret = owned.enter_context(_secret(new, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._master.change(current_secret, new_secret, confirmation,
                                            _optional_text(phrase, "recovery phrase", 1024)))

    # ---------------------------------------------------------------- backups
    @guarded
    def backup_status(self) -> dict[str, Any]:
        return ok(**self._recovery.status())

    @guarded
    def backup_create(self, backup_password: Any, confirm: Any, vault_password: Any) -> dict[str, Any]:
        with ExitStack() as owned:  # every SecretText is wiped on exit, even when a later one is refused
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.create_backup(backup_secret, confirmation, vault_secret))

    @guarded
    def backup_verify(self, backup_password: Any, vault_password: Any) -> dict[str, Any]:
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.verify(backup_secret, vault_secret))

    @guarded
    def backup_restore(self, name: Any, backup_password: Any, vault_password: Any) -> dict[str, Any]:
        name_text = _text(name, "profile name", 128)
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.restore(name_text, backup_secret, vault_secret))

    @guarded
    def backup_test(self, backup_password: Any, vault_password: Any) -> dict[str, Any]:
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.test_restore(backup_secret, vault_secret))

    @guarded
    def backup_verify_trial(self, vault_password: Any) -> dict[str, Any]:
        with _secret(vault_password, "password") as vault_secret:
            return ok(**self._recovery.verify_trial(vault_secret))

    @guarded
    def backup_kit(self) -> dict[str, Any]:
        return ok(**self._recovery.write_kit())

    @guarded
    def backup_cancel_trial(self) -> dict[str, Any]:
        return ok(**self._recovery.cancel_trial())

    @guarded
    def phrase_create(self, vault_password: Any) -> dict[str, Any]:
        with _secret(vault_password, "password") as vault_secret:
            return ok(**self._recovery.phrase_create(vault_secret))

    @guarded
    def phrase_confirm(self, token: Any, answers: Any) -> dict[str, Any]:
        if not isinstance(answers, list) or len(answers) > 24 or not all(isinstance(a, str) and len(a) <= 64 for a in answers):
            raise ApiError("invalid", "Invalid words.")
        return ok(**self._recovery.phrase_confirm(_text(token, "card", 64), answers))

    @guarded
    def phrase_close(self, token: Any) -> dict[str, Any]:
        return ok(**self._recovery.phrase_close(_text(token, "card", 64)))

    @guarded
    def vault_recover(self, phrase: Any, new: Any, confirm: Any) -> dict[str, Any]:
        phrase_text = _text(phrase, "recovery phrase", 1024)
        with ExitStack() as owned:
            new_secret = owned.enter_context(_secret(new, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._controller.recover(phrase_text, new_secret, confirmation))

    @guarded
    def lock_emergency(self) -> dict[str, Any]:
        return ok(**self._lockmodes.emergency_lock())

    @guarded
    def lock_switch(self) -> dict[str, Any]:
        return ok(**self._lockmodes.lock_and_switch())

    # ---------------------------------------------------- Hello and camera
    @guarded
    def hello_status(self) -> dict[str, Any]:
        return ok(**self._hello.status())

    @guarded
    def hello_enable(self) -> dict[str, Any]:
        return ok(**self._hello.enable())

    @guarded
    def hello_disable(self) -> dict[str, Any]:
        return ok(**self._hello.disable())

    @guarded
    def hello_auto_start(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, bool):
            raise ApiError("invalid", "Invalid switch value.")
        return ok(**self._hello.set_auto_start(value))

    @guarded
    def hello_offer(self) -> dict[str, Any]:
        return ok(**self._hello.offer())

    @guarded
    def hello_offer_answer(self, accepted: Any) -> dict[str, Any]:
        return ok(**self._hello.answer_offer(accepted is True))

    @guarded
    def vault_unlock_hello(self) -> dict[str, Any]:
        return ok(**self._hello.unlock())

    @guarded
    def face_status(self) -> dict[str, Any]:
        return ok(**self._face.status())

    @guarded
    def face_enable(self) -> dict[str, Any]:
        return ok(**self._face.enable())

    @guarded
    def face_disable(self) -> dict[str, Any]:
        return ok(**self._face.disable())

    @guarded
    def face_cancel(self) -> dict[str, Any]:
        return ok(**self._face.cancel())

    @guarded
    def face_switch_camera(self) -> dict[str, Any]:
        return ok(**self._face.switch_camera())

    @guarded
    def vault_unlock_face(self) -> dict[str, Any]:
        return ok(**self._face.unlock())

    # ---------------------------------------------------------------- settings
    @guarded
    def settings_page(self) -> dict[str, Any]:
        return ok(**self._settings.page())

    @guarded
    def settings_set(self, key: Any, value: Any) -> dict[str, Any]:
        if not isinstance(value, (bool, int, str)) or (isinstance(value, str) and len(value) > 1024):
            raise ApiError("invalid", "That value cannot be used.")
        key = _text(key, "setting", 64)
        result = self._settings.apply(key, value)
        if key == "appearance":
            set_theme = getattr(self._window_ops, "set_theme", None)
            if callable(set_theme):
                try:
                    set_theme(self._controller.settings.appearance)
                except Exception:  # noqa: BLE001, S110 - the title bar colour is cosmetic
                    pass
        return ok(**result)

    @guarded
    def settings_choose_folder(self, key: Any) -> dict[str, Any]:
        return ok(**self._settings.choose_folder(_text(key, "setting", 64)))

    @guarded
    def backup_password_set(self, first: Any, second: Any) -> dict[str, Any]:
        with ExitStack() as owned:  # both wiped when the call returns
            secret = owned.enter_context(_secret(first, "password"))
            confirmation = owned.enter_context(_secret(second, "password"))
            return ok(**self._settings.backup_password(secret, confirmation))

    @guarded
    def backup_password_clear(self) -> dict[str, Any]:
        return ok(**self._settings.clear_backup_password())

    # ----------------------------------------------------------------- licence
    @guarded
    def licence_view(self) -> dict[str, Any]:
        return ok(**self._licence.view())

    @guarded
    def licence_install(self, text: Any) -> dict[str, Any]:
        return ok(**self._licence.install(_text(text, "licence", 65536)))

    @guarded
    def licence_install_file(self) -> dict[str, Any]:
        return ok(**self._licence.install_file())

    @guarded
    def licence_remove(self) -> dict[str, Any]:
        return ok(**self._licence.remove())

    # ----------------------------------------------------------------- updates
    @guarded
    def updates_check(self) -> dict[str, Any]:
        # Strict offline consent is always asked by Python, never waived by the page.
        return ok(**self._updates.check())

    @guarded
    def updates_open_release(self) -> dict[str, Any]:
        return ok(**self._updates.open_release_page())

    @guarded
    def updates_reminder(self) -> dict[str, Any]:
        return ok(**self._updates.reminder())

    @guarded
    def updates_snooze(self) -> dict[str, Any]:
        return ok(**self._updates.snooze())

    # ---------------------------------------------------------------- profiles
    @guarded
    def profiles_manage(self) -> dict[str, Any]:
        return ok(**self._profiles.list())

    @guarded
    def profiles_create(self, name: Any) -> dict[str, Any]:
        return ok(**self._profiles.create(_text(name, "profile name", 128)))

    @guarded
    def profiles_update(self, profile_id: Any, name: Any = None, color: Any = None) -> dict[str, Any]:
        return ok(**self._profiles.update(_text(profile_id, "profile", 128), name=_optional_text(name, "profile name", 128),
                                          color=_optional_text(color, "colour", 16)))

    @guarded
    def profiles_photo(self, profile_id: Any) -> dict[str, Any]:
        return ok(**self._profiles.photo(_text(profile_id, "profile", 128)))

    @guarded
    def profiles_remove_photo(self, profile_id: Any) -> dict[str, Any]:
        return ok(**self._profiles.remove_photo(_text(profile_id, "profile", 128)))

    @guarded
    def profiles_delete(self, profile_id: Any) -> dict[str, Any]:
        return ok(**self._profiles.delete(_text(profile_id, "profile", 128)))

    # ------------------------------------------------------------- connections
    @guarded
    def connections_view(self) -> dict[str, Any]:
        return ok(**self._connections.view())

    @guarded
    def connections_repair(self) -> dict[str, Any]:
        return ok(**self._connections.repair())

    @guarded
    def connections_export(self) -> dict[str, Any]:
        return ok(**self._connections.export())

    @guarded
    def errorlog_open(self) -> dict[str, Any]:
        import os

        from ..error_log import log_path

        folder = log_path().parent
        folder.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(folder)  # noqa: S606 - opens the app's own log folder in Explorer
        return ok()

    # -------------------------------------------------------------------- sync
    @guarded
    def sync_view(self) -> dict[str, Any]:
        return ok(**self._sync.view())

    @guarded
    def sync_refresh(self) -> dict[str, Any]:
        return ok(**self._sync.refresh())

    @guarded
    def sync_now(self) -> dict[str, Any]:
        return ok(**self._sync.sync_now())

    @guarded
    def sync_acknowledge_members(self) -> dict[str, Any]:
        return ok(**self._sync.acknowledge_members())

    @guarded
    def sync_choose_folder(self) -> dict[str, Any]:
        return ok(**self._sync.choose_folder())

    @guarded
    def sync_password_check(self, password: Any, confirm: Any) -> dict[str, Any]:
        return ok(**self._sync.password_check(_text(password, "password", MAX_PASSWORD_LENGTH),
                                              _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_create(self, token: Any, password: Any, confirm: Any) -> dict[str, Any]:
        return ok(**self._sync.create(_text(token, "folder", 64), _text(password, "password", MAX_PASSWORD_LENGTH),
                                      _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_join(self, token: Any, password: Any) -> dict[str, Any]:
        return ok(**self._sync.join(_text(token, "folder", 64), _text(password, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_setup_text(self, action: Any) -> dict[str, Any]:
        return ok(**self._sync.setup_text(_text(action, "action", 32)))

    @guarded
    def sync_folder_setup(self, action: Any, token: Any, password: Any, confirm: Any = "") -> dict[str, Any]:
        return ok(**self._sync.folder_setup(_text(action, "action", 32), _text(token, "folder", 64),
                                            _text(password, "password", MAX_PASSWORD_LENGTH),
                                            _text(confirm or "", "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_rotation_text(self) -> dict[str, Any]:
        return ok(**self._sync.rotation_text())

    @guarded
    def sync_change_password(self, password: Any, confirm: Any) -> dict[str, Any]:
        return ok(**self._sync.change_password(_text(password, "password", MAX_PASSWORD_LENGTH),
                                               _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_remove_info(self, card: Any) -> dict[str, Any]:
        return ok(**self._sync.remove_info(_text(card, "card", 16)))

    @guarded
    def sync_remove_device(self, card: Any, device_id: Any, password: Any = "", confirm: Any = "") -> dict[str, Any]:
        return ok(**self._sync.remove_device(_text(card, "card", 16), _text(device_id, "device", 128),
                                             _text(password or "", "password", MAX_PASSWORD_LENGTH),
                                             _text(confirm or "", "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_orphans(self) -> dict[str, Any]:
        return ok(**self._sync.orphans())

    @guarded
    def sync_remove_orphans(self, ids: Any, password: Any, confirm: Any) -> dict[str, Any]:
        return ok(**self._sync.remove_orphans(_ids(ids), _text(password, "password", MAX_PASSWORD_LENGTH),
                                              _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def sync_leave(self) -> dict[str, Any]:
        return ok(**self._sync.leave())

    @guarded
    def sync_reset(self) -> dict[str, Any]:
        return ok(**self._sync.reset())

    @guarded
    def sync_qr_show(self) -> dict[str, Any]:
        return ok(**self._sync.qr_show())

    @guarded
    def sync_qr_poll(self, offer_id: Any) -> dict[str, Any]:
        return ok(**self._sync.qr_poll(_text(offer_id, "offer", 128)))

    @guarded
    def sync_qr_copy(self, offer_id: Any) -> dict[str, Any]:
        return ok(**self._sync.qr_copy(_text(offer_id, "offer", 128)))

    @guarded
    def sync_qr_close(self, offer_id: Any) -> dict[str, Any]:
        return ok(**self._sync.qr_close(_text(offer_id, "offer", 128)))

    @guarded
    def sync_join_qr(self, text: Any) -> dict[str, Any]:
        return ok(**self._sync.join_qr(_text(text, "code", 8192)))

    @guarded
    def sync_wifi_suggest(self) -> dict[str, Any]:
        return ok(**self._sync.wifi_suggest())

    @guarded
    def sync_wifi_enable(self, text: Any) -> dict[str, Any]:
        return ok(**self._sync.wifi_enable(_text(text, "address", 128)))

    @guarded
    def sync_wifi_disable(self) -> dict[str, Any]:
        return ok(**self._sync.wifi_disable())

    @guarded
    def sync_firewall_status(self) -> dict[str, Any]:
        return ok(**self._sync.firewall_status())

    @guarded
    def sync_firewall_allow(self) -> dict[str, Any]:
        return ok(**self._sync.firewall_allow())


    # ---------------------------------------------------------------- import
    @guarded
    def import_open(self) -> dict[str, Any]:
        return ok(**self._imports.open())

    @guarded
    def import_plan(self, handle: Any, password: Any = None, mapping: Any = None) -> dict[str, Any]:
        if mapping is not None and (not isinstance(mapping, dict) or len(mapping) > 16
                                    or not all(isinstance(k, str) and isinstance(v, str) and len(v) <= 256
                                               for k, v in mapping.items())):
            raise ApiError("invalid", "Invalid column choice.")
        return ok(**self._imports.plan(_text(handle, "import", 64),
                                       _optional_text(password, "password", MAX_PASSWORD_LENGTH), mapping))

    @guarded
    def import_review(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.review(_text(handle, "import", 64)))

    @guarded
    def import_decide(self, handle: Any, rows: Any, mode: Any) -> dict[str, Any]:
        if not isinstance(rows, list) or len(rows) > 100000 or not all(
                isinstance(r, int) and not isinstance(r, bool) for r in rows):
            raise ApiError("invalid", "Invalid selection.")
        return ok(**self._imports.decide(_text(handle, "import", 64), rows, _text(mode, "decision", 16)))

    @guarded
    def import_decide_all(self, handle: Any, action: Any) -> dict[str, Any]:
        return ok(**self._imports.decide_all(_text(handle, "import", 64), _text(action, "decision", 32)))

    @guarded
    def import_apply(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.apply(_text(handle, "import", 64)))

    @guarded
    def import_cancel(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.cancel(_text(handle, "import", 64)))

    @guarded
    def import_close(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.close(_text(handle, "import", 64)))

    # ---------------------------------------------------------------- export
    @guarded
    def export_formats(self, fmt: Any = "kdbx", include_totp: Any = False) -> dict[str, Any]:
        return ok(**self._exports.formats(_text(fmt, "format", 32), include_totp is True))

    @guarded
    def export_run(self, fmt: Any, include_totp: Any, password: Any = "", confirm: Any = "") -> dict[str, Any]:
        with ExitStack() as owned:  # both wiped when the call returns
            secret = owned.enter_context(_secret(password or "", "password"))
            confirmation = owned.enter_context(_secret(confirm or "", "password"))
            return ok(**self._exports.export(_text(fmt, "format", 32), include_totp is True, secret, confirmation))

    # -------------------------------------------------------------- transfer
    @guarded
    def transfer_info(self) -> dict[str, Any]:
        return ok(**self._transfer.info())

    @guarded
    def transfer_choose(self, mode: Any) -> dict[str, Any]:
        return ok(**self._transfer.choose(_text(mode, "mode", 16)))

    @guarded
    def transfer_inspect(self, handle: Any) -> dict[str, Any]:
        return ok(**self._transfer.inspect(_text(handle, "package", 64)))

    @guarded
    def transfer_preview(self, mode: Any, handle: Any, password: Any, scope: Any = None, policy: Any = "skip",
                         allow_replace: Any = False) -> dict[str, Any]:
        return ok(**self._transfer.preview(_text(mode, "mode", 16), _text(handle, "package", 64),
                                           _text(password, "password", MAX_PASSWORD_LENGTH),
                                           _dict(scope or {}, "scope"), _text(policy, "policy", 16),
                                           allow_replace is True))

    @guarded
    def transfer_commit(self, token: Any, mode: Any, handle: Any, password: Any, confirm: Any = "", scope: Any = None,
                        policy: Any = "skip", allow_replace: Any = False) -> dict[str, Any]:
        result = self._transfer.commit(_text(token, "preview", 64), _text(mode, "mode", 16),
                                       _text(handle, "package", 64), _text(password, "password", MAX_PASSWORD_LENGTH),
                                       _text(confirm or "", "password", MAX_PASSWORD_LENGTH),
                                       _dict(scope or {}, "scope"), _text(policy, "policy", 16), allow_replace is True)
        if result.get("changed"):
            self._changed()
        return ok(**result)

    @guarded
    def transfer_cancel(self) -> dict[str, Any]:
        return ok(**self._transfer.cancel())

    # ---------------------------------------------------------- phone backup
    @guarded
    def phone_backup_choose(self) -> dict[str, Any]:
        return ok(**self._phone_backup.choose())

    @guarded
    def phone_backup_preview(self, handle: Any, password: Any) -> dict[str, Any]:
        return ok(**self._phone_backup.preview(_text(handle, "package", 64),
                                               _text(password, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def phone_backup_commit(self, token: Any, handle: Any) -> dict[str, Any]:
        result = self._phone_backup.commit(_text(token, "preview", 64), _text(handle, "package", 64))
        if result.get("changed"):
            self._changed()
        return ok(**result)

    @guarded
    def phone_backup_cancel(self) -> dict[str, Any]:
        return ok(**self._phone_backup.cancel())

    # ---------------------------------------------------------------- startup
    @guarded
    def legacy_import(self) -> dict[str, Any]:
        startup = self._controller.startup
        if startup is None:
            raise ApiError("invalid", "There is nothing to import.")
        startup.import_legacy()
        return ok(**self._controller.state())

    @guarded
    def legacy_fresh(self) -> dict[str, Any]:
        startup = self._controller.startup
        if startup is None:
            raise ApiError("invalid", "There is nothing to decide.")
        startup.fresh()
        return ok(**self._controller.state())

    # --------------------------------------------------------------- workspace
    @guarded
    def reminders_list(self) -> dict[str, Any]:
        return ok(**self._reminders.list())

    @guarded
    def reminders_complete(self, reminder_id: Any) -> dict[str, Any]:
        return ok(**self._reminders.complete(_text(reminder_id, "reminder", 128)))

    @guarded
    def reminders_snooze(self, reminder_id: Any) -> dict[str, Any]:
        return ok(**self._reminders.snooze(_text(reminder_id, "reminder", 128)))

    @guarded
    def activity_list(self) -> dict[str, Any]:
        return ok(**self._activity.list())

    @guarded
    def shortcuts_list(self) -> dict[str, Any]:
        from ..app.workspace import shortcuts

        return ok(**shortcuts(self._controller.settings))

    @guarded
    def collections_list(self) -> dict[str, Any]:
        return ok(**self._collections.list())

    @guarded
    def collections_create(self, name: Any, description: Any = "") -> dict[str, Any]:
        return ok(**self._collections.create(_text(name, "name", 128), _text(description or "", "description", 512)))

    @guarded
    def collections_rename(self, collection_id: Any, name: Any, description: Any = None) -> dict[str, Any]:
        return ok(**self._collections.rename(_text(collection_id, "collection", 128), _text(name, "name", 128),
                                             _optional_text(description, "description", 512)))

    @guarded
    def collections_archive(self, collection_id: Any) -> dict[str, Any]:
        return ok(**self._collections.archive(_text(collection_id, "collection", 128)))

    @guarded
    def catalog_status(self) -> dict[str, Any]:
        return ok(**self._catalog.status())

    @guarded
    def catalog_update(self) -> dict[str, Any]:
        return ok(**self._catalog.update())

    @guarded
    def onboarding_state(self) -> dict[str, Any]:
        return ok(**self._onboarding.view())

    @guarded
    def onboarding_perform(self, choice: Any = None) -> dict[str, Any]:
        return ok(**self._onboarding.perform(choice if isinstance(choice, bool) else None))

    @guarded
    def onboarding_skip(self) -> dict[str, Any]:
        return ok(**self._onboarding.skip())

    @guarded
    def onboarding_test_connection(self) -> dict[str, Any]:
        return ok(**self._onboarding.test_connection())

    # --------------------------------------------------------------- desktop
    def _desktop_service(self) -> Any:
        service = getattr(self, "_desktop", None)
        if service is None:
            raise ApiError("unavailable", "Desktop fill is available in the Windows app.")
        return service

    @guarded
    def desktop_bind_scan(self, entry_id: Any = None) -> dict[str, Any]:
        return ok(**self._desktop_service().scan_for_binding(_optional_text(entry_id, "item", 128)))

    @guarded
    def desktop_bind_form(self, token: Any) -> dict[str, Any]:
        return ok(**self._desktop_service().binding_form(_text(token, "binding", 64)))

    @guarded
    def desktop_bind_save(self, token: Any, user_index: Any, password_index: Any, label: Any = "", username: Any = "",
                          password: Any = "") -> dict[str, Any]:
        if user_index is not None:
            user_index = _int(user_index, "field")
        return ok(**self._desktop_service().save_binding(
            _text(token, "binding", 64), user_index, _int(password_index, "field"), _text(label or "", "label", 512),
            _text(username or "", "username", 512), _text(password or "", "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def desktop_signin_scan(self, entry_id: Any) -> dict[str, Any]:
        return ok(**self._desktop_service().sign_in_buttons(_text(entry_id, "item", 128)))

    @guarded
    def desktop_signin_save(self, token: Any, index: Any) -> dict[str, Any]:
        return ok(**self._desktop_service().map_sign_in(_text(token, "binding", 64), _int(index, "button")))

    @guarded
    def desktop_web_warning_reset(self, entry_id: Any) -> dict[str, Any]:
        return ok(**self._desktop_service().require_web_warning(_text(entry_id, "item", 128)))

    @guarded
    def desktop_fill(self, entry_id: Any) -> dict[str, Any]:
        return ok(**self._desktop_service().fill_entry_now(_text(entry_id, "item", 128)))

# Calls that never wait for the vault lock: they do not touch the vault, must answer
# while another call is waiting for the user (modal answers, cancel, lock), or run
# sync jobs that take the lock themselves through the sync gate.
_NO_VAULT_LOCK = frozenset({
    "app_info", "vault_state", "modal_answer", "window_minimize", "window_toggle_maximize", "window_close",
    "window_theme_sync", "system_open_url", "vault_lock", "lock_emergency", "lock_switch", "vault_unlock",
    "vault_create", "vault_recover", "vault_unlock_hello", "vault_unlock_face", "face_cancel",
    "face_switch_camera", "health_cancel", "profiles_list", "profiles_select", "status_get",
    "import_cancel", "transfer_cancel", "legacy_import", "legacy_fresh", "shortcuts_list",
    "onboarding_test_connection",
    # Desktop jobs wait for the user to switch apps and for UI Automation; they take the lock per vault touch.
    "desktop_bind_scan", "desktop_bind_form", "desktop_bind_save", "desktop_fill",
    "desktop_signin_scan", "desktop_signin_save", "desktop_web_warning_reset",
    # QR scans wait for the camera; they take the lock only to read and fill the editor.
    "qr_scan_image", "qr_scan_camera", "qr_cancel", "qr_switch_camera",
})


def _with_vault_lock(fn: Any) -> Any:
    import functools

    @functools.wraps(fn)
    def wrapper(self: "Api", *args: Any, **kwargs: Any) -> Any:
        with self._controller.vault_lock:
            return fn(self, *args, **kwargs)

    return wrapper


for _name, _member in list(vars(Api).items()):
    if (callable(_member) and not _name.startswith("_") and _name not in _NO_VAULT_LOCK
            and not _name.startswith("sync_")):
        setattr(Api, _name, _with_vault_lock(_member))
del _name, _member

# The names the page may call: Api's public methods, the same set pywebview lists for window.pywebview.api.
PAGE_CALLS = frozenset(name for name, member in vars(Api).items() if callable(member) and not name.startswith("_"))


def _page_call(api: Api, name: str) -> Any:
    import inspect

    def call(self: Any, *args: Any, **kwargs: Any) -> Any:
        return getattr(api, name)(*args, **kwargs)

    call.__name__ = call.__qualname__ = name
    call.__signature__ = inspect.signature(getattr(Api, name))  # type: ignore[attr-defined]  # same JS params
    return call


def page_api(api: Api) -> Any:
    """The object handed to pywebview as js_api: one method per page call and nothing else.

    pywebview resolves a page call with getattr on every dotted segment, so the Api
    itself would let page script reach ``_controller`` and its collaborators. This
    object has no public attribute but the calls; the underscore paths that remain
    (``__class__``, a method's ``__closure__``) are refused by the call guard in
    ``web.window.install_call_guard``.
    """
    namespace: dict[str, Any] = {"__slots__": (), "__module__": __name__}
    for name in sorted(PAGE_CALLS):
        namespace[name] = _page_call(api, name)
    return type("PageApi", (), namespace)()
