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

from .. import i18n
from ..secret_text import SecretText
from ..version import APP_VERSION
from .result import ApiError, fail, guarded, ok
from ..i18n import t

MAX_PASSWORD_LENGTH = 1024


class WindowOps(Protocol):
    def minimize(self) -> None: ...

    def toggle_maximize(self) -> None: ...

    def close(self) -> None: ...


# A backup password is 12-4096 characters (design section 3.2); the service checks the bounds.
_BACKUP_PASSWORD_LIMIT = 4096


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ApiError("invalid", t("bridge.invalid", name=name))
    return value


class PageSecret:
    """A password argument from the page, handed over once.

    pywebview keeps a call's argument list (and every frame down to the bridge method keeps its
    arguments) until the call returns, which for an unlock is after the slow key derivation. The call
    guard (``web.window``) swaps each password ``str`` in that list for one of these, so ``_secret``
    takes the only reference and the ``str`` is released before the derivation starts. Released, not
    erased: Python cannot wipe a ``str``.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value: str | None = value

    def take(self) -> str | None:
        value, self._value = self._value, None
        return value

    def __repr__(self) -> str:
        return "PageSecret(...)"


def _secret(value: Any, name: str, limit: int = MAX_PASSWORD_LENGTH) -> SecretText:
    """The master password as a wipeable ``SecretText``; the calling bridge method wipes it when it returns."""
    if isinstance(value, PageSecret):
        value = value.take()
    text = _text(value, name, limit)
    try:
        return SecretText.from_str(text)
    except ValueError:
        # Unencodable text (a lone surrogate): a fixed message that never echoes the value.
        raise ApiError("invalid", t("bridge.invalid", name=name)) from None


def _optional_text(value: Any, name: str, limit: int) -> str | None:
    return None if value is None else _text(value, name, limit)


def _ref(value: Any) -> dict[str, str]:
    """An item reference from the page: exactly {source, id, kind} as short strings."""
    if (not isinstance(value, dict) or set(value) != {"source", "id", "kind"}
            or value.get("source") not in ("credential", "typed")
            or not all(isinstance(value[k], str) and 0 < len(value[k]) <= 128 for k in ("id", "kind"))):
        raise ApiError("invalid", t("bridge.invalidItem"))
    return {"source": value["source"], "id": value["id"], "kind": value["kind"]}


def _nothing() -> None:
    pass


def _ids(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 5000 or not all(isinstance(v, str) and 0 < len(v) <= 128 for v in value):
        raise ApiError("invalid", t("bridge.invalidSelection"))
    return list(value)


def _int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError("invalid", t("bridge.invalid", name=name))
    return value


def _dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 64:
        raise ApiError("invalid", t("bridge.invalid", name=name))
    return value


class _NoDialogs:
    """Used when no window exists (tests, headless): every file dialog is unavailable."""

    def open_file(self, title: str, file_types: tuple[str, ...] | None = None) -> Any:
        raise ApiError("unavailable", t("error.dialogsUnavailable"))

    def save_file(self, title: str, name: str) -> Any:
        raise ApiError("unavailable", t("error.dialogsUnavailable"))

    def choose_folder(self, title: str) -> Any:
        raise ApiError("unavailable", t("error.dialogsUnavailable"))


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
        # The quick-search palette window asks its own questions (master password for a strict login).
        palette_port = port.surface_view("palette") if hasattr(port, "surface_view") else port
        self._palette_secrets = SecretService(controller, palette_port)
        # Set by the app: hide the palette (and cancel its prompts), hide or show its window only,
        # and the window the palette was opened over.
        self._palette_hide: Any = None
        self._palette_hide_window: Any = None
        self._palette_show_again: Any = None
        self._palette_target: Any = None
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
        from ..app.qr_accounts import QrAccountsService
        from ..app.qr_import import QrImportService

        self._qr_accounts = QrAccountsService(
            controller, self._editor, port,
            generate=lambda: generate_from_preferences(controller.settings.generator_preferences))
        self._qr = QrImportService(controller, self._editor, self._extras, emit=controller._bus.emit,
                                   accounts=self._qr_accounts)
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
    def vault_unlock(self, password: Any, use_picked_keyfile: Any = False) -> dict[str, Any]:
        # use_picked_keyfile: the key file chosen with factors_pick_keyfile (its path never leaves Python);
        # otherwise the remembered one. The page never names a path.
        path = self._factors.picked_keyfile() if use_picked_keyfile is True else None
        with _secret(password, "password") as secret:
            if path is None:
                return ok(**self._controller.unlock(secret))
            return ok(**self._controller.unlock(secret, keyfile_path=path))

    @guarded
    def vault_create(self, password: Any, confirm: Any) -> dict[str, Any]:
        with ExitStack() as owned:  # each SecretText is wiped on exit, even when a later one is refused
            secret = owned.enter_context(_secret(password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._controller.create(secret, confirmation))

    @guarded
    def vault_lock(self) -> dict[str, Any]:
        return ok(**self._controller.lock())

    @guarded
    def vault_dismiss_erased(self) -> dict[str, Any]:
        return ok(**self._controller.dismiss_erased_notice())

    # ---------------------------------------------------------------- modals
    @guarded
    def modal_answer(self, request_id: Any, value: Any = None) -> dict[str, Any]:
        return ok(accepted=bool(self._port.answer(_text(request_id, "request", 64), value)))

    # ---------------------------------------------------------------- language
    @guarded
    def i18n_bundle(self) -> dict[str, Any]:
        return ok(lang=i18n.current(), messages=i18n.catalog())

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
            return fail("invalid", t("bridge.onlyWebLinksCanBe"))
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
    def items_sort_set(self, option: Any = None, favorites_first: Any = True) -> dict[str, Any]:
        return ok(**self._home.set_sort(option, favorites_first))

    @guarded
    def import_card_dismiss(self) -> dict[str, Any]:
        return ok(**self._home.dismiss_import_card())

    @guarded
    def notes_formatting_get(self) -> dict[str, Any]:
        return ok(enabled=bool(getattr(self._controller.settings, "notes_show_formatting", True)))

    @guarded
    def notes_formatting_set(self, enabled: Any = True) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ApiError("invalid", t("bridge.invalid", name="formatting"))
        settings = self._controller.settings
        settings.notes_show_formatting = enabled
        try:
            settings.save()
        except OSError:
            pass  # kept until the app closes
        return ok(enabled=enabled)

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
    def codes_collapsed_set(self, collapsed: Any = False) -> dict[str, Any]:
        return ok(**self._home.set_codes_collapsed(collapsed))

    @guarded
    def status_get(self) -> dict[str, Any]:
        return ok(**self._home.status())

    # ----------------------------------------------------------------- items
    @guarded
    def item_detail(self, ref: Any) -> dict[str, Any]:
        ref = _ref(ref)
        detail = self._secrets.detail(ref)
        if ref.get("source") == "credential" and self._controller.is_unlocked():
            session = self._controller.session
            record = session.credential_detail(ref["id"])
            if record is not None:
                try:
                    detail["access"] = self._access.banner(session, record)
                finally:
                    record.clear()
            try:
                enabled = bool(self._autotype.settings_get().get("enabled"))
            except Exception:  # noqa: BLE001 - a damaged settings file reads as off
                enabled = False
            if enabled:
                actions = detail.get("actions")
                detail["actions"] = [*actions, "autotype"] if isinstance(actions, list) else ["autotype"]
        return ok(**detail)

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
            raise ApiError("invalid", t("bridge.invalidChip"))
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
    def login_copy_password(self, draft_id: Any) -> dict[str, Any]:
        return ok(**self._editor.copy_password(_text(draft_id, "editor", 64)))

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
    def typed_wifi_qr(self, ref: Any) -> dict[str, Any]:
        return ok(**self._typed.wifi_qr(_ref(ref)))

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
    def history_restore(self, ref: Any, index: Any, changed_at: Any) -> dict[str, Any]:
        result = self._extras.history_restore(_ref(ref), _int(index, "row"), _int(changed_at, "row"))
        self._changed()
        return ok(**result)

    @guarded
    def recovery_count(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.recovery_count(_ref(ref)))

    @guarded
    def recovery_get(self, ref: Any) -> dict[str, Any]:
        return ok(**self._extras.recovery_codes(_ref(ref)))

    @guarded
    def recovery_save(self, ref: Any, codes: Any) -> dict[str, Any]:
        if not isinstance(codes, list) or len(codes) > 100 or not all(isinstance(c, str) and len(c) <= 512 for c in codes):
            raise ApiError("invalid", t("bridge.atMost100RecoveryCodes"))
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
            raise ApiError("invalid", t("bridge.atMost50CustomFields"))
        removed = [] if removed is None else removed
        if not isinstance(removed, list) or len(removed) > 50:
            raise ApiError("invalid", t("bridge.invalidRemovedFields"))
        return ok(**self._extras.custom_fields_save(_ref(ref), fields,
                                                    removed=[_int(i, t("bridge.removedField")) for i in removed]))

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

    # The Scan sheet: a QR code without an open editor (picture file, pasted snip, dropped file or webcam).
    @guarded
    def qr_sheet_scan_image(self, image: Any, token: Any = None) -> dict[str, Any]:
        return ok(**self._qr.sheet_scan_image(_text(image, "image", 17 * 1024 * 1024),
                                              None if token is None else _text(token, "scan", 64)))

    @guarded
    def qr_sheet_scan_camera(self, token: Any = None) -> dict[str, Any]:
        return ok(**self._qr.sheet_scan_camera(None if token is None else _text(token, "scan", 64)))

    @guarded
    def qr_sheet_open(self, token: Any, index: Any, target: Any = None) -> dict[str, Any]:
        return ok(**self._qr_accounts.open(_text(token, "scan", 64), _int(index, "account"),
                                           None if not target else _text(target, "login", 128)))

    @guarded
    def qr_sheet_add(self, token: Any, choices: Any) -> dict[str, Any]:
        return ok(**self._qr_accounts.add(_text(token, "scan", 64), choices))

    @guarded
    def qr_sheet_discard(self, token: Any) -> dict[str, Any]:
        return ok(**self._qr_accounts.discard(_text(token, "scan", 64)))

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
        self._security.agent_exposed = lambda session: len(self._health._agent_exposures(session))
        self._master = MasterService(self._controller, self._port)
        from ..app.factors import FactorService

        # Key file / YubiKey (Settings › Unlocking, the unlock screen); its YubiKey responder also serves backups.
        self._factors = FactorService(self._controller, self._port, self._dialogs, bus=bus)
        self._recovery = RecoveryWebService(self._controller, self._port, self._dialogs,
                                            yubikey=self._factors.responder)
        self._lockmodes = LockModes(self._controller)
        from ..app.schedule import ScheduleRunner

        self._schedule = ScheduleRunner(self._controller, bus)
        from ..app.unlock_methods import FaceService, HelloService, SecurityKeyService

        hwnd = getattr(self._window_ops, "hwnd", None)
        self._hello = HelloService(self._controller, self._port, hwnd=hwnd if callable(hwnd) else (lambda: None))
        self._face = FaceService(self._controller, self._port, bus)
        self._security_key = SecurityKeyService(self._controller, self._port,
                                                hwnd=hwnd if callable(hwnd) else (lambda: None))
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
        from ..app.rating import RatingService

        self._rating = RatingService(self._controller)
        from ..app.store_move import StoreMoveService

        self._store_move = StoreMoveService(self._controller)
        self._profiles = ProfilesService(self._controller, self._port, self._dialogs)
        from ..app.power_user import PowerUserService

        self._power = PowerUserService(self._controller, self._port, self._dialogs)
        self._connections = ConnectionsService(self._port, self._dialogs)
        from ..app.passkey_doctor import PasskeyDoctorService

        self._passkey_doctor = PasskeyDoctorService(lambda: self._controller.settings)
        from ..app.developer import DeveloperService

        self._developer = DeveloperService(self._controller, self._port)
        from ..app.secret_scan_service import SecretScanService

        self._secret_scan = SecretScanService(self._controller, self._port, bus)
        from ..app.device_removal import RemovalGuard
        from ..app.sync import SyncWebService

        self._removal = RemovalGuard(self._controller)
        self._sync = SyncWebService(self._controller, self._port, bus, self._dialogs,
                                    on_licence=self._licence.after_unlock, on_removal=self._removal.check_soon)
        from ..app.import_export import ExportService, ImportService
        from ..app.transfer_web import TransferService

        self._imports = ImportService(self._controller, self._port, self._dialogs, bus)
        self._exports = ExportService(self._controller, self._port, self._dialogs)
        self._transfer = TransferService(self._controller, self._port, self._dialogs)
        from ..app.share_web import ShareService

        self._share = ShareService(self._controller, self._port, self._dialogs)
        # Feature pack 2026-11-15: access rules, item history, travel mode, clean up, privacy proof, auto-type.
        from ..app.auto_type_service import AutoTypeService
        from ..app.feature_pack import (
            AccessRulesService,
            HygieneService,
            ItemHistoryService,
            TravelService,
        )
        from ..app.privacy_page import PrivacyProofService

        self._access = AccessRulesService(self._controller, self._port, self._extras)
        self._item_history = ItemHistoryService(self._controller, self._port)
        self._travel = TravelService(self._controller, self._port)
        self._hygiene = HygieneService(self._controller, self._port)
        self._privacy = PrivacyProofService(self._controller, self._port, self._dialogs)
        self._autotype = AutoTypeService(self._controller, self._port)
        from ..app.heir_service import HeirService

        # Emergency access (sub-plan 08): its heir-folder backup runs on the scheduled-backup timer.
        self._heir = HeirService(self._controller, self._port, self._dialogs, bus=bus)
        self._schedule.heir = self._heir
        from ..app.duress_service import DuressService

        # Duress password (sub-plan 08, Task 4): its look for other devices' markers runs on the same timer.
        self._duress = DuressService(self._controller, self._port, bus=bus)
        self._schedule.duress = self._duress
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
        from ..app.collection_share import CollectionShareService

        self._collection_share = CollectionShareService(self._controller, self._port, self._dialogs, sync=self._sync,
                                                        changed=self._changed)
        self._catalog = CatalogService(self._controller, self._port, self._changed)
        self._onboarding = OnboardingWebService(self._controller, self._recovery,
                                                apply_setting=self._settings.apply)

    @guarded
    def security_center(self) -> dict[str, Any]:
        return ok(**self._security.center())

    @guarded
    def network_activity(self) -> dict[str, Any]:
        return ok(**self._security.network_activity())

    @guarded
    def security_set(self, key: Any, value: Any) -> dict[str, Any]:
        if not isinstance(value, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
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
    def agent_exposure_get(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._health.agent_exposure(_text(item_id, "item", 128)))

    @guarded
    def agent_exposure_dismiss(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._health.dismiss_agent_exposure(_text(item_id, "item", 128)))

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
                                            _optional_text(phrase, t("bridge.recoveryPhrase"), 1024)))

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
    def backup_choose(self, kind: Any) -> dict[str, Any]:
        return ok(**self._recovery.choose(_text(kind, "kind", 16)))

    @guarded
    def backup_verify(self, backup_password: Any, vault_password: Any) -> dict[str, Any]:
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.verify(backup_secret, vault_secret))

    @guarded
    def backup_restore(self, name: Any, backup_password: Any, vault_password: Any) -> dict[str, Any]:
        name_text = _text(name, t("bridge.profileName"), 128)
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = owned.enter_context(_secret(vault_password, "password"))
            return ok(**self._recovery.restore(name_text, backup_secret, vault_secret))

    @guarded
    def backup_restore_phrase(self, name: Any, backup_password: Any, phrase: Any, new_password: Any,
                              confirm: Any) -> dict[str, Any]:
        name_text = _text(name, t("bridge.profileName"), 128)
        phrase_text = _text(phrase, t("bridge.recoveryPhrase"), 1024)
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            new_secret = owned.enter_context(_secret(new_password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._recovery.restore_with_phrase(name_text, backup_secret, phrase_text, new_secret,
                                                           confirmation))

    @guarded
    def backup_factors(self) -> dict[str, Any]:
        return ok(**self._recovery.factors())

    @guarded
    def backup_factor_keyfile(self) -> dict[str, Any]:
        return ok(**self._recovery.choose_keyfile())

    @guarded
    def backup_factors_clear(self) -> dict[str, Any]:
        return ok(**self._recovery.clear_factors())

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
    def recovery_kit_facts(self) -> dict[str, Any]:
        return ok(**self._recovery.kit_facts())

    # ------------------------------------------------- duress password (sub-plan 08, Task 4)
    @guarded
    def duress_status(self) -> dict[str, Any]:
        return ok(**self._duress.view())

    @guarded
    def duress_setup(self, current: Any, password: Any, confirm: Any, lock_hours: Any,
                     items: Any = None) -> dict[str, Any]:
        ids = _ids([] if items is None else items)
        hours = _int(lock_hours, t("duress.lockHours"))
        with ExitStack() as owned:  # every SecretText is wiped on exit, even when a later one is refused
            current_secret = owned.enter_context(_secret(current, "password"))
            secret = owned.enter_context(_secret(password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._duress.setup(current_secret, secret, confirmation, hours, ids))

    @guarded
    def duress_remove(self) -> dict[str, Any]:
        return ok(**self._duress.remove())

    # ------------------------------------------------- emergency access (sub-plan 08)
    @guarded
    def heir_plan_list(self) -> dict[str, Any]:
        return ok(**self._heir.view())

    @guarded
    def heir_plan_choose_folder(self) -> dict[str, Any]:
        return ok(**self._heir.choose_folder())

    @guarded
    def heir_plan_create(self, k: Any, holders: Any, wait_days: Any, folder: Any, owner: Any,
                         phrase: Any) -> dict[str, Any]:
        if not isinstance(holders, list) or not 2 <= len(holders) <= 5:
            raise ApiError("invalid", t("heir.err.invalid"))
        names = [_text(name, t("heir.holder"), 64) for name in holders]
        return ok(**self._heir.create(k=_int(k, "k"), holders=names, wait_days=_int(wait_days, "days"),
                                      folder=_text(folder, "folder", 1024), owner=_text(owner, "owner", 128),
                                      phrase=_text(phrase, t("bridge.recoveryPhrase"), 1024)))

    @guarded
    def heir_plan_set_folder(self) -> dict[str, Any]:
        return ok(**self._heir.set_folder())

    @guarded
    def heir_plan_sheet(self, handle: Any) -> dict[str, Any]:
        return ok(**self._heir.sheet(_text(handle, "plan", 64)))

    @guarded
    def heir_plan_save(self, handle: Any) -> dict[str, Any]:
        return ok(**self._heir.save_files(_text(handle, "plan", 64)))

    @guarded
    def heir_plan_done(self, handle: Any) -> dict[str, Any]:
        return ok(**self._heir.done(_text(handle, "plan", 64)))

    @guarded
    def heir_plan_deny(self, request_id: Any) -> dict[str, Any]:
        return ok(**self._heir.deny(_text(request_id, "request", 64)))

    @guarded
    def heir_plan_grant(self, request_id: Any, phrase: Any) -> dict[str, Any]:
        return ok(**self._heir.grant(_text(request_id, "request", 64),
                                     _text(phrase, t("bridge.recoveryPhrase"), 1024)))

    @guarded
    def heir_backup_now(self) -> dict[str, Any]:
        return ok(**self._heir.backup_now())

    @guarded
    def heir_receive_view(self) -> dict[str, Any]:
        return ok(**self._heir.receive_view())

    @guarded
    def heir_shard_add_file(self) -> dict[str, Any]:
        return ok(**self._heir.shard_add_file())

    @guarded
    def heir_shard_add_text(self, text: Any) -> dict[str, Any]:
        return ok(**self._heir.shard_add_text(_text(text, "shard", 8192)))

    @guarded
    def heir_shards_clear(self) -> dict[str, Any]:
        return ok(**self._heir.shards_clear())

    @guarded
    def heir_receive_folder(self) -> dict[str, Any]:
        return ok(**self._heir.choose_receive_folder())

    @guarded
    def heir_request_create(self) -> dict[str, Any]:
        return ok(**self._heir.request())

    @guarded
    def heir_restore(self, name: Any, new_password: Any, confirm: Any) -> dict[str, Any]:
        name_text = _text(name, t("bridge.profileName"), 128)
        with ExitStack() as owned:
            new_secret = owned.enter_context(_secret(new_password, "password"))
            confirmation = owned.enter_context(_secret(confirm, "password"))
            return ok(**self._heir.restore(name_text, new_secret, confirmation))

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
            raise ApiError("invalid", t("bridge.invalidWords"))
        return ok(**self._recovery.phrase_confirm(_text(token, "card", 64), answers))

    @guarded
    def phrase_close(self, token: Any) -> dict[str, Any]:
        return ok(**self._recovery.phrase_close(_text(token, "card", 64)))

    @guarded
    def vault_recover(self, phrase: Any, new: Any, confirm: Any) -> dict[str, Any]:
        phrase_text = _text(phrase, t("bridge.recoveryPhrase"), 1024)
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
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
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
    def security_key_status(self) -> dict[str, Any]:
        return ok(**self._security_key.status())

    @guarded
    def security_key_enable(self) -> dict[str, Any]:
        return ok(**self._security_key.enable())

    @guarded
    def security_key_disable(self) -> dict[str, Any]:
        return ok(**self._security_key.disable())

    @guarded
    def vault_unlock_security_key(self) -> dict[str, Any]:
        return ok(**self._security_key.unlock())

    @guarded
    def face_status(self) -> dict[str, Any]:
        return ok(**self._face.status())

    @guarded
    def face_enable(self) -> dict[str, Any]:
        return ok(**self._face.enable())

    @guarded
    def face_disable(self) -> dict[str, Any]:
        result = self._face.disable()
        phrase = result.pop("new_recovery_phrase", None)
        notes = result.pop("phrase_notes", None)
        if phrase:
            # Removing camera verification replaced the recovery phrase (L-4): the page shows it once.
            result["phrase_card"] = self._recovery.phrase_card(phrase, notes)
        return ok(**result)

    @guarded
    def face_cancel(self) -> dict[str, Any]:
        return ok(**self._face.cancel())

    @guarded
    def face_switch_camera(self) -> dict[str, Any]:
        return ok(**self._face.switch_camera())

    @guarded
    def vault_unlock_face(self) -> dict[str, Any]:
        return ok(**self._face.unlock())

    # ------------------------------------------------- key file and YubiKey
    def _phrase_card(self, result: dict[str, Any]) -> dict[str, Any]:
        """Removing camera unlock for "Always ask" may replace the recovery phrase: shown once as a card."""
        phrase = result.pop("new_recovery_phrase", None)
        notes = result.pop("phrase_notes", None)
        if phrase:
            result["phrase_card"] = self._recovery.phrase_card(phrase, notes)
        return result

    @guarded
    def factors_status(self) -> dict[str, Any]:
        return ok(**self._factors.status())

    @guarded
    def factors_pick_keyfile(self) -> dict[str, Any]:
        return ok(**self._factors.pick_keyfile())

    @guarded
    def factors_add_keyfile(self) -> dict[str, Any]:
        # The file is picked in Python's own open dialog: the page never names a path.
        return ok(**self._phrase_card(self._factors.add_keyfile()))

    @guarded
    def factors_create_keyfile(self) -> dict[str, Any]:
        # The location is picked in Python's own save dialog.
        return ok(**self._phrase_card(self._factors.create_keyfile()))

    @guarded
    def factors_add_yubikey(self, slot: Any = 2) -> dict[str, Any]:
        if isinstance(slot, bool) or slot not in (1, 2):
            raise ApiError("invalid", t("bridge.invalid", name="slot"))
        return ok(**self._phrase_card(self._factors.add_yubikey(int(slot))))

    @guarded
    def factors_check_backup_yubikey(self) -> dict[str, Any]:
        return ok(**self._factors.check_backup_yubikey())

    @guarded
    def factors_remove(self, kind: Any) -> dict[str, Any]:
        return ok(**self._factors.remove(_text(kind, "kind", 32)))

    @guarded
    def factors_set_always_ask(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._phrase_card(self._factors.set_always_ask(value)))

    @guarded
    def factors_set_remember(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._factors.set_remember(value))

    @guarded
    def factors_cancel(self) -> dict[str, Any]:
        return ok(**self._factors.cancel())

    # ---------------------------------------------------------------- settings
    @guarded
    def settings_page(self) -> dict[str, Any]:
        return ok(**self._settings.page())

    @guarded
    def settings_set(self, key: Any, value: Any) -> dict[str, Any]:
        if not isinstance(value, (bool, int, str)) or (isinstance(value, str) and len(value) > 1024):
            raise ApiError("invalid", t("settings.error.invalidValue"))
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

    # Scheduled-backup key (docs/design/backup-public-key-2026-10-31.md): set once, then only with proof.
    @guarded
    def backup_password_set(self, first: Any, second: Any) -> dict[str, Any]:
        with ExitStack() as owned:  # both wiped when the call returns
            secret = owned.enter_context(_secret(first, "password", _BACKUP_PASSWORD_LIMIT))
            confirmation = owned.enter_context(_secret(second, "password", _BACKUP_PASSWORD_LIMIT))
            return ok(**self._settings.backup_password(secret, confirmation))

    @guarded
    def backup_password_change(self, old: Any, first: Any, second: Any, relock: Any = True) -> dict[str, Any]:
        if not isinstance(relock, bool):
            raise ApiError("invalid", t("bridge.invalid", name="relock"))
        with ExitStack() as owned:
            old_secret = owned.enter_context(_secret(old, "password", _BACKUP_PASSWORD_LIMIT))
            secret = owned.enter_context(_secret(first, "password", _BACKUP_PASSWORD_LIMIT))
            confirmation = owned.enter_context(_secret(second, "password", _BACKUP_PASSWORD_LIMIT))
            return ok(**self._settings.change_backup_password(old_secret, secret, confirmation, relock))

    @guarded
    def backup_password_reset(self, phrase: Any, first: Any, second: Any) -> dict[str, Any]:
        words = _text(phrase, t("bridge.recoveryPhrase"), 1024)
        with ExitStack() as owned:
            secret = owned.enter_context(_secret(first, "password", _BACKUP_PASSWORD_LIMIT))
            confirmation = owned.enter_context(_secret(second, "password", _BACKUP_PASSWORD_LIMIT))
            return ok(**self._settings.reset_backup_password(words, secret, confirmation))

    @guarded
    def backup_key_rebind(self, password: Any) -> dict[str, Any]:
        with _secret(password, "password", _BACKUP_PASSWORD_LIMIT) as secret:
            return ok(**self._settings.rebind_backup_key(secret))

    @guarded
    def backup_key_confirm(self, password: Any) -> dict[str, Any]:
        with _secret(password, "password", _BACKUP_PASSWORD_LIMIT) as secret:
            return ok(**self._settings.confirm_backup_key(secret))

    @guarded
    def backup_key_remove(self, password: Any = None, phrase: Any = None) -> dict[str, Any]:
        words = _optional_text(phrase, t("bridge.recoveryPhrase"), 1024)
        if password is None or password == "":
            return ok(**self._settings.remove_backup_key(None, words))
        with _secret(password, "password", _BACKUP_PASSWORD_LIMIT) as secret:
            return ok(**self._settings.remove_backup_key(secret, None))

    @guarded
    def backup_notice_dismiss(self) -> dict[str, Any]:
        return ok(**self._settings.dismiss_backup_notice())

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

    # ------------------------------------------------------------------ rating
    @guarded
    def rating_prompt(self) -> dict[str, Any]:
        return ok(**self._rating.prompt())

    @guarded
    def rating_answer(self, rate: Any) -> dict[str, Any]:
        return ok(**self._rating.answer(rate is True))

    @guarded
    def rating_open(self) -> dict[str, Any]:
        return ok(**self._rating.open())

    # -------------------------------------------------------------- store move
    @guarded
    def store_move_notice(self) -> dict[str, Any]:
        return ok(**self._store_move.notice())

    @guarded
    def store_move_answer(self, open_store: Any) -> dict[str, Any]:
        return ok(**self._store_move.answer(open_store is True))

    @guarded
    def store_move_open(self) -> dict[str, Any]:
        return ok(**self._store_move.open())

    # ---------------------------------------------------------------- profiles
    @guarded
    def profiles_manage(self) -> dict[str, Any]:
        return ok(**self._profiles.list())

    @guarded
    def profiles_create(self, name: Any) -> dict[str, Any]:
        return ok(**self._profiles.create(_text(name, t("bridge.profileName"), 128)))

    @guarded
    def profiles_update(self, profile_id: Any, name: Any = None, color: Any = None) -> dict[str, Any]:
        return ok(**self._profiles.update(_text(profile_id, "profile", 128), name=_optional_text(name, t("bridge.profileName"), 128),
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

    # ------------------------------------------------- feature pack 2026-11-15
    @guarded
    def access_get(self, ref: Any) -> dict[str, Any]:
        return ok(**self._access.get(_ref(ref)))

    @guarded
    def access_save(self, ref: Any, changes: Any) -> dict[str, Any]:
        result = self._access.save(_ref(ref), _dict(changes, "access"))
        self._changed()
        return ok(**result)

    @guarded
    def item_history_list(self, ref: Any) -> dict[str, Any]:
        return ok(**self._item_history.list(_ref(ref)))

    @guarded
    def item_history_diff(self, ref: Any, snapshot_id: Any, reveal: Any = False) -> dict[str, Any]:
        return ok(**self._item_history.diff(_ref(ref), _text(snapshot_id, "version", 64), reveal is True))

    @guarded
    def item_history_restore_field(self, ref: Any, snapshot_id: Any, field: Any) -> dict[str, Any]:
        result = self._item_history.restore_field(_ref(ref), _text(snapshot_id, "version", 64),
                                                  _text(field, "field", 512))
        self._changed()
        return ok(**result)

    @guarded
    def travel_get(self) -> dict[str, Any]:
        return ok(**self._travel.get())

    @guarded
    def travel_save(self, collections: Any, tags: Any) -> dict[str, Any]:
        if not isinstance(collections, list) or not isinstance(tags, list) or len(collections) > 100                 or len(tags) > 100:
            raise ApiError("invalid", t("travel.chooseCollections"))
        result = self._travel.save([_text(c, "collection", 64) for c in collections],
                                   [_text(x, "tag", 256) for x in tags])
        self._changed()
        return ok(**result)

    @guarded
    def travel_off(self) -> dict[str, Any]:
        result = self._travel.off()
        self._changed()
        return ok(**result)

    @guarded
    def hygiene_scan(self) -> dict[str, Any]:
        return ok(**self._hygiene.scan())

    @guarded
    def hygiene_merge_preview(self, keeper_ref: Any, other_ref: Any) -> dict[str, Any]:
        return ok(**self._hygiene.merge_preview(_ref(keeper_ref), _ref(other_ref)))

    @guarded
    def hygiene_merge(self, keeper_ref: Any, other_ref: Any) -> dict[str, Any]:
        result = self._hygiene.merge(_ref(keeper_ref), _ref(other_ref))
        self._changed()
        return ok(**result)

    @guarded
    def hygiene_merge_all(self) -> dict[str, Any]:
        result = self._hygiene.merge_all()
        self._changed()
        return ok(**result)

    @guarded
    def hygiene_delete(self, refs: Any) -> dict[str, Any]:
        if not isinstance(refs, list) or not refs or len(refs) > 5000:
            raise ApiError("invalid", t("hygiene.none"))
        result = self._hygiene.delete([_ref(r) for r in refs])
        self._changed()
        return ok(**result)

    @guarded
    def hygiene_undo(self) -> dict[str, Any]:
        result = self._hygiene.undo()
        self._changed()
        return ok(**result)

    @guarded
    def privacy_proof_get(self) -> dict[str, Any]:
        return ok(**self._privacy.get())

    @guarded
    def privacy_proof_export(self) -> dict[str, Any]:
        return ok(**self._privacy.export())

    @guarded
    def autotype_settings_get(self) -> dict[str, Any]:
        return ok(**self._autotype.settings_get())

    @guarded
    def autotype_settings_set(self, enabled: Any, confirm: Any) -> dict[str, Any]:
        if type(enabled) is not bool or type(confirm) is not bool:
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._autotype.settings_set(enabled, confirm))

    @guarded
    def autotype_run(self, ref: Any) -> dict[str, Any]:
        return ok(**self._autotype.run(_ref(ref)))

    def _start_autotype_watch(self, interval: float = 0.5) -> None:
        """Remember the last window in front that is not LocalGateKeys, while auto-type is on.

        Reads only the foreground window handle and its process (no keyboard hook, no clipboard), so
        "Type into the last window" knows where the user was before they clicked into the app.
        """
        import threading
        import time

        def loop() -> None:
            enabled, tick = False, 0
            while True:
                if tick % 8 == 0:
                    try:
                        enabled = bool(self._autotype.settings_get().get("enabled"))
                    except Exception:  # noqa: BLE001
                        enabled = False
                tick += 1
                if enabled:
                    self._autotype.note_foreground()
                time.sleep(interval)

        threading.Thread(target=loop, name="lgk-autotype-watch", daemon=True).start()

    # ------------------------------------------------------------- connections
    @guarded
    def passkey_doctor_view(self) -> dict[str, Any]:
        return ok(**self._passkey_doctor.view())

    @guarded
    def passkey_doctor_status(self) -> dict[str, Any]:
        return ok(**self._passkey_doctor.status_line())

    @guarded
    def passkey_doctor_open_settings(self) -> dict[str, Any]:
        return ok(**self._passkey_doctor.open_settings())

    @guarded
    def connections_view(self) -> dict[str, Any]:
        return ok(**self._connections.view())

    @guarded
    def connections_repair(self) -> dict[str, Any]:
        return ok(**self._connections.repair())

    @guarded
    def connections_export(self) -> dict[str, Any]:
        return ok(**self._connections.export())

    # --------------------------------------------------------------- developer
    @guarded
    def developer_status(self) -> dict[str, Any]:
        return ok(**self._developer.status())

    @guarded
    def developer_set(self, key: Any, value: Any) -> dict[str, Any]:
        if key != "ssh_agent" or not isinstance(value, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.set_agent(value))

    @guarded
    def developer_key_toggle(self, item_id: Any, on: Any) -> dict[str, Any]:
        if not isinstance(on, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.toggle_key(_text(item_id, "item", 128), on))

    @guarded
    def developer_generate_key(self, title: Any = "") -> dict[str, Any]:
        return ok(**self._developer.generate_key(_text(title or "", "title", 128)))

    @guarded
    def developer_copy_public_key(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._developer.copy_public_key(_text(item_id, "item", 128)))

    @guarded
    def developer_cli_get(self) -> dict[str, Any]:
        return ok(**self._developer.cli_enabled())

    @guarded
    def developer_cli_set(self, enabled: Any) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.set_cli(enabled))

    @guarded
    def developer_agents_set(self, key: Any, enabled: Any) -> dict[str, Any]:
        if key not in ("enabled", "hello") or not isinstance(enabled, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.set_agents(key, enabled))

    @guarded
    def developer_agent_item_get(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._developer.agent_item(_text(item_id, "item", 128)))

    @guarded
    def developer_agent_item_set(self, item_id: Any, on: Any) -> dict[str, Any]:
        if not isinstance(on, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.set_agent_item(_text(item_id, "item", 128), on))

    @guarded
    def developer_cli_item_toggle(self, item_id: Any, on: Any) -> dict[str, Any]:
        if not isinstance(on, bool):
            raise ApiError("invalid", t("bridge.invalidSwitchValue"))
        return ok(**self._developer.toggle_cli_item(_text(item_id, "item", 128), on))

    @guarded
    def developer_copy_reference(self, item_id: Any, field: Any = "") -> dict[str, Any]:
        return ok(**self._developer.copy_reference(_text(item_id, "item", 128), _text(field or "", "field", 128)))

    @guarded
    def developer_env_apply(self) -> dict[str, Any]:
        return ok(**self._developer.env_apply())

    @guarded
    def developer_env_undo(self) -> dict[str, Any]:
        return ok(**self._developer.env_undo())

    @guarded
    def developer_git_plan(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._developer.git_preview(_text(item_id, "item", 128)))

    @guarded
    def developer_git_apply(self, item_id: Any) -> dict[str, Any]:
        return ok(**self._developer.git_apply(_text(item_id, "item", 128)))

    @guarded
    def developer_git_undo(self) -> dict[str, Any]:
        return ok(**self._developer.git_undo())

    @guarded
    def secret_scan_choose_folder(self) -> dict[str, Any]:
        folder = self._dialogs.choose_folder(t("secret_scan.chooseFolder"))
        if not folder:
            raise ApiError("cancelled", t("error.noFolderChosen"))
        return ok(folder=str(folder))

    @guarded
    def secret_scan_start(self, roots: Any = None) -> dict[str, Any]:
        return ok(**self._secret_scan.start(roots))

    @guarded
    def secret_scan_cancel(self) -> dict[str, Any]:
        return ok(**self._secret_scan.cancel())

    @guarded
    def secret_scan_import(self, ids: Any) -> dict[str, Any]:
        return ok(**self._secret_scan.import_findings(_ids(ids)))

    @guarded
    def secret_scan_rewrite_preview(self, finding_id: Any) -> dict[str, Any]:
        return ok(**self._secret_scan.rewrite_preview(_text(finding_id, "finding", 32)))

    @guarded
    def secret_scan_rewrite_apply(self, finding_id: Any, token: Any) -> dict[str, Any]:
        return ok(**self._secret_scan.rewrite_apply(_text(finding_id, "finding", 32), _text(token, "token", 128)))

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
    def sync_status(self) -> dict[str, Any]:
        return ok(**self._sync.status_summary())

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
    def sync_acknowledge_rollback(self) -> dict[str, Any]:
        return ok(**self._sync.acknowledge_rollback())

    @guarded
    def sync_dismiss_peer_rollback(self, device_id: str) -> dict[str, Any]:
        return ok(**self._sync.dismiss_peer_rollback(device_id))

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
    def sync_lost_device(self, card: Any, device_id: Any, password: Any = "", confirm: Any = "") -> dict[str, Any]:
        return ok(**self._sync.lost_device(_text(card, "card", 16), _text(device_id, "device", 128),
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
    def sync_qr_poll(self, offer_id: Any, decision: Any = None) -> dict[str, Any]:
        """Poll the shown QR offer; *decision* ``"accept"``/``"decline"`` first answers its Accept prompt."""
        offer = _text(offer_id, "offer", 128)
        if decision is not None:
            if decision not in ("accept", "decline"):
                raise ApiError("invalid", t("bridge.chooseAcceptOrDecline"))
            self._sync.qr_decide(offer, decision == "accept")
        return ok(**self._sync.qr_poll(offer))

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
    def sync_find_again_qr(self, text: Any) -> dict[str, Any]:
        return ok(**self._sync.find_again_qr(_text(text, "code", 8192)))

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
            raise ApiError("invalid", t("bridge.invalidColumnChoice"))
        return ok(**self._imports.plan(_text(handle, "import", 64),
                                       _optional_text(password, "password", MAX_PASSWORD_LENGTH), mapping))

    @guarded
    def import_review(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.review(_text(handle, "import", 64)))

    @guarded
    def import_decide(self, handle: Any, rows: Any, mode: Any) -> dict[str, Any]:
        if not isinstance(rows, list) or len(rows) > 100000 or not all(
                isinstance(r, int) and not isinstance(r, bool) for r in rows):
            raise ApiError("invalid", t("bridge.invalidSelection"))
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
    def import_undo(self, token: Any) -> dict[str, Any]:
        result = self._imports.undo(_text(token, "import", 64))
        self._changed()
        return ok(**result)

    @guarded
    def import_close(self, handle: Any) -> dict[str, Any]:
        return ok(**self._imports.close(_text(handle, "import", 64)))

    # ---------------------------------------------------------------- export
    @guarded
    def export_formats(self, fmt: Any = "kdbx", include_totp: Any = False) -> dict[str, Any]:
        return ok(**self._exports.formats(_text(fmt, "format", 32), include_totp is True))

    @guarded
    def export_coverage(self) -> dict[str, Any]:
        return ok(**self._exports.coverage())

    @guarded
    def export_items(self) -> dict[str, Any]:
        return ok(**self._exports.items())

    @guarded
    def export_run(self, fmt: Any, include_totp: Any, password: Any = "", confirm: Any = "",
                   ids: Any = None) -> dict[str, Any]:
        selection = {} if ids is None else {"ids": _ids(ids)}  # a CXF export names the selected items
        with ExitStack() as owned:  # both wiped when the call returns
            secret = owned.enter_context(_secret(password or "", "password"))
            confirmation = owned.enter_context(_secret(confirm or "", "password"))
            return ok(**self._exports.export(_text(fmt, "format", 32), include_totp is True, secret, confirmation,
                                             **selection))

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

    # ----------------------------------------------------------- share (UX 9)
    @guarded
    def share_start(self, ref: Any, expires_hours: Any = None, one_use: Any = False) -> dict[str, Any]:
        hours = expires_hours if type(expires_hours) is int else None
        return ok(**self._share.start(_ref(ref), expires_hours=hours, one_use=one_use is True))

    # ------------------------------------------------- power-user pack (sub-plan 12)
    @guarded
    def restore_test_status(self) -> dict[str, Any]:
        return ok(**self._power.restore_status())

    @guarded
    def restore_test_pick(self) -> dict[str, Any]:
        return ok(**self._power.restore_pick())

    @guarded
    def restore_test_run(self, path: Any, backup_password: Any, vault_password: Any = None) -> dict[str, Any]:
        with ExitStack() as owned:
            backup_secret = owned.enter_context(_secret(backup_password, "password"))
            vault_secret = None if vault_password in (None, "") else owned.enter_context(
                _secret(vault_password, "password"))
            return ok(**self._power.restore_run(_text(path, "path", 4096), backup_secret, vault_secret))

    @guarded
    def change_password_open(self, entry_id: Any) -> dict[str, Any]:
        return ok(**self._power.change_password_open(_text(entry_id, "id", 128)))

    @guarded
    def health_report_print(self, page: Any = "a4") -> dict[str, Any]:
        return ok(**self._power.health_print(_text(page, "page", 16)))

    @guarded
    def estate_create(self) -> dict[str, Any]:
        return ok(**self._power.estate_create())

    @guarded
    def share_save_file(self, handle: Any) -> dict[str, Any]:
        return ok(**self._share.save_file(_text(handle, "share", 64)))

    @guarded
    def share_qr(self, handle: Any) -> dict[str, Any]:
        return ok(**self._share.qr(_text(handle, "share", 64)))

    @guarded
    def share_cancel(self) -> dict[str, Any]:
        return ok(**self._share.cancel())

    @guarded
    def share_revoke(self, handle: Any) -> dict[str, Any]:
        return ok(**self._share.revoke(str(handle or "")))

    @guarded
    def share_receive_file(self) -> dict[str, Any]:
        return ok(**self._share.receive_file())

    @guarded
    def share_receive_text(self, text: Any) -> dict[str, Any]:
        return ok(**self._share.receive_text(_text(text, t("bridge.sharedItem"), 300 * 1024)))

    @guarded
    def share_receive_qr_image(self, image: Any) -> dict[str, Any]:
        return ok(**self._share.receive_qr_image(_text(image, "image", 17 * 1024 * 1024)))

    @guarded
    def share_incoming(self) -> dict[str, Any]:
        return ok(**self._share.incoming())

    @guarded
    def share_preview(self, package_id: Any, code: Any) -> dict[str, Any]:
        return ok(**self._share.preview(_text(package_id, "item", 64), _text(code, "code", 200)))

    @guarded
    def share_save(self, package_id: Any, code: Any, mode: Any = "keep") -> dict[str, Any]:
        result = self._share.save(_text(package_id, "item", 64), _text(code, "code", 200), _text(mode, "mode", 16))
        if result.pop("changed", False):
            self._changed()
        return ok(**result)

    @guarded
    def share_reject(self, package_id: Any) -> dict[str, Any]:
        return ok(**self._share.reject(_text(package_id, "item", 64)))

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
            raise ApiError("invalid", t("bridge.thereIsNothingToImport"))
        startup.import_legacy()
        return ok(**self._controller.state())

    @guarded
    def legacy_fresh(self) -> dict[str, Any]:
        startup = self._controller.startup
        if startup is None:
            raise ApiError("invalid", t("bridge.thereIsNothingToDecide"))
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
    def activity_verify(self) -> dict[str, Any]:
        return ok(**self._activity.verify())

    @guarded
    def activity_export(self) -> dict[str, Any]:
        return ok(**self._activity.export())

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

    # ------------------------------------------------------- shared collections
    @guarded
    def collection_share_members(self, collection_id: Any) -> dict[str, Any]:
        return ok(**self._collection_share.view(_text(collection_id, "collection", 128)))

    @guarded
    def collection_share_choose_folder(self) -> dict[str, Any]:
        return ok(**self._collection_share.choose_folder())

    @guarded
    def collection_share_create(self, collection_id: Any, token: Any, password: Any, confirm: Any,
                                can_edit: Any = False, name: Any = "") -> dict[str, Any]:
        if not isinstance(can_edit, bool):
            raise ApiError("invalid", t("bridge.invalid", name="can_edit"))
        return ok(**self._collection_share.create(
            _text(collection_id, "collection", 128), _text(token, "folder", 64),
            _text(password, "password", MAX_PASSWORD_LENGTH), _text(confirm, "password", MAX_PASSWORD_LENGTH),
            can_edit, _text(name or "", "name", 128)))

    @guarded
    def collection_share_join(self, token: Any, password: Any, name: Any = "") -> dict[str, Any]:
        return ok(**self._collection_share.join(_text(token, "folder", 64),
                                                _text(password, "password", MAX_PASSWORD_LENGTH),
                                                _text(name or "", "name", 128)))

    @guarded
    def collection_share_rejoin(self, collection_id: Any, password: Any, name: Any = "") -> dict[str, Any]:
        return ok(**self._collection_share.rejoin(_text(collection_id, "collection", 128),
                                                  _text(password, "password", MAX_PASSWORD_LENGTH),
                                                  _text(name or "", "name", 128)))

    @guarded
    def collection_share_approve(self, collection_id: Any, device_ids: Any) -> dict[str, Any]:
        return ok(**self._collection_share.approve(_text(collection_id, "collection", 128), _ids(device_ids)))

    @guarded
    def collection_share_remove_member(self, collection_id: Any, device_id: Any, password: Any,
                                       confirm: Any) -> dict[str, Any]:
        return ok(**self._collection_share.remove(
            _text(collection_id, "collection", 128), _text(device_id, "device", 128),
            _text(password, "password", MAX_PASSWORD_LENGTH), _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def collection_share_upgrade(self, collection_id: Any, password: Any, confirm: Any) -> dict[str, Any]:
        return ok(**self._collection_share.upgrade(
            _text(collection_id, "collection", 128),
            _text(password, "password", MAX_PASSWORD_LENGTH), _text(confirm, "password", MAX_PASSWORD_LENGTH)))

    @guarded
    def collection_share_leave(self, collection_id: Any) -> dict[str, Any]:
        return ok(**self._collection_share.leave(_text(collection_id, "collection", 128)))

    @guarded
    def collection_share_forget_link(self, collection_id: Any) -> dict[str, Any]:
        return ok(**self._collection_share.forget_link(_text(collection_id, "collection", 128)))

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
    def onboarding_card(self) -> dict[str, Any]:
        return ok(**self._onboarding.card())

    @guarded
    def onboarding_perform(self, step: Any = None) -> dict[str, Any]:
        return ok(**self._onboarding.perform(_text(step, "step", 32)))

    @guarded
    def onboarding_skip(self, step: Any = None) -> dict[str, Any]:
        return ok(**self._onboarding.skip(_optional_text(step, "step", 32)))

    @guarded
    def onboarding_skip_all(self) -> dict[str, Any]:
        return ok(**self._onboarding.skip_all())

    @guarded
    def onboarding_hide(self) -> dict[str, Any]:
        return ok(**self._onboarding.hide())

    @guarded
    def onboarding_show(self) -> dict[str, Any]:
        return ok(**self._onboarding.show_again())

    @guarded
    def onboarding_test_connection(self) -> dict[str, Any]:
        return ok(**self._onboarding.test_connection())

    # --------------------------------------------------------------- desktop
    def _desktop_service(self) -> Any:
        service = getattr(self, "_desktop", None)
        if service is None:
            raise ApiError("unavailable", t("bridge.desktopFillIsAvailableIn"))
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

    # ------------------------------------------------- quick-search palette
    @guarded
    def palette_copy(self, ref: Any, field: Any) -> dict[str, Any]:
        """Copy a field of a search result; the same checks, prompts and clipboard timeout as item_copy."""
        return ok(**self._palette_secrets.copy(_ref(ref), _text(field, "field", 16)))

    @guarded
    def palette_fill(self, ref: Any) -> dict[str, Any]:
        """Fill the chosen row, and only it, into the window the palette was opened over."""
        item = _ref(ref)
        if not self._controller.is_unlocked():
            raise ApiError("locked", t("error.lockedProfile"))
        if item["source"] != "credential" or item["kind"] != "desktop":
            raise ApiError("cannot_fill", t("quickPalette.cannotFill"))
        target = self._palette_target() if self._palette_target is not None else 0
        return ok(**self._desktop_service().fill_entry_into(
            item["id"], int(target or 0), hide=self._palette_hide_window or _nothing,
            show_again=self._palette_show_again or _nothing))

    @guarded
    def palette_hide(self) -> dict[str, Any]:
        hook = self._palette_hide
        if hook is not None:
            hook()
        return ok()

# Calls that never wait for the vault lock: they do not touch the vault, must answer
# while another call is waiting for the user (modal answers, cancel, lock), or run
# sync jobs that take the lock themselves through the sync gate.
_NO_VAULT_LOCK = frozenset({
    "app_info", "vault_state", "modal_answer", "window_minimize", "window_toggle_maximize", "window_close",
    "window_theme_sync", "system_open_url", "vault_lock", "vault_dismiss_erased", "lock_emergency", "lock_switch", "vault_unlock",
    "vault_create", "vault_recover", "vault_unlock_hello", "vault_unlock_security_key", "vault_unlock_face", "face_cancel",
    "face_switch_camera", "health_cancel", "secret_scan_cancel", "secret_scan_choose_folder", "collection_share_choose_folder", "profiles_list", "profiles_select", "status_get",
    "import_cancel", "transfer_cancel", "legacy_import", "legacy_fresh", "shortcuts_list",
    "onboarding_test_connection",
    # Desktop jobs wait for the user to switch apps and for UI Automation; they take the lock per vault touch.
    "desktop_bind_scan", "desktop_bind_form", "desktop_bind_save", "desktop_fill",
    "desktop_signin_scan", "desktop_signin_save", "desktop_web_warning_reset",
    # The palette fill waits for the app behind it like desktop_fill; hiding touches no vault data.
    "palette_fill", "palette_hide",
    # QR scans wait for the camera; they take the lock only to read and fill the editor.
    "qr_scan_image", "qr_scan_camera", "qr_cancel", "qr_switch_camera",
    "qr_sheet_scan_image", "qr_sheet_scan_camera",
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

# The page calls whose arguments are passwords, by parameter name. Each one reaches only ``_secret``, which
# accepts a ``PageSecret``; the positions are looked up from the signatures, so a renamed parameter fails here.
_SECRET_PARAMS: dict[str, tuple[str, ...]] = {
    "vault_unlock": ("password",),
    "vault_create": ("password", "confirm"),
    "vault_recover": ("new", "confirm"),
    "master_change": ("current", "new", "confirm"),
    "duress_setup": ("current", "password", "confirm"),
    "phrase_create": ("vault_password",),
    "heir_restore": ("new_password", "confirm"),
    "backup_create": ("backup_password", "confirm", "vault_password"),
    "backup_verify": ("backup_password", "vault_password"),
    "backup_restore": ("backup_password", "vault_password"),
    "backup_restore_phrase": ("backup_password", "new_password", "confirm"),
    "backup_test": ("backup_password", "vault_password"),
    "backup_verify_trial": ("vault_password",),
    "restore_test_run": ("backup_password", "vault_password"),
    "backup_password_set": ("first", "second"),
    "backup_password_change": ("old", "first", "second"),
    "backup_password_reset": ("first", "second"),
    "backup_key_rebind": ("password",),
    "backup_key_confirm": ("password",),
    "backup_key_remove": ("password",),
    "export_run": ("password", "confirm"),
}


def _secret_positions() -> dict[str, frozenset[int]]:
    import inspect

    positions: dict[str, frozenset[int]] = {}
    for call_name, params in _SECRET_PARAMS.items():
        names = list(inspect.signature(getattr(Api, call_name)).parameters)[1:]  # without self
        positions[call_name] = frozenset(names.index(param) for param in params)
    return positions


PAGE_SECRET_ARGS = _secret_positions()


def hold_page_secrets(func_name: Any, param: Any) -> Any:
    """Swap each password in a page call's argument list for a ``PageSecret``, in place.

    Called by the call guard before pywebview starts the worker thread, so neither pywebview's
    copy of the list nor the frames that pass the arguments along keep the ``str``.
    """
    positions = PAGE_SECRET_ARGS.get(func_name) if isinstance(func_name, str) else None
    if positions and isinstance(param, list):
        for index in positions:
            if index < len(param) and isinstance(param[index], str) and param[index]:
                param[index] = PageSecret(param[index])
    return param


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
