"""Small, non-Tk view models for the next release UI journeys.

The existing Tk windows are deliberately thin presentation layers.  This module
holds the state and validation that can be tested without a display:

* declarative, data-only form templates and an in-memory editor history;
* a session-bound recovery drill that delegates crypto and filesystem work to
  :mod:`localvault.recovery`;
* local, resumable onboarding progress; and
* theme, accessibility, and DPI tokens shared by new surfaces.

Nothing in this module opens a browser, enables fill/sign-in, starts a network
operation, or writes a password to state, telemetry, or a log.
"""
from __future__ import annotations

import copy
import datetime as _datetime
import json
import math
import os
import re
import tempfile
import time
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any

from .item_schema import ITEM_KINDS, ItemSchemaError, validate_bookmark_url
from .recovery import RecoveryController, RecoveryError, RecoveryService
from .app.recovery_center import summarize_recovery
from .secret_text import SecretText, is_blank_secret
from .session_guard import StaleSession


class UIModelError(ValueError):
    """A presentation-boundary input was malformed."""


class TemplateValidationError(UIModelError):
    """A declarative form definition was rejected."""


class FormValidationError(UIModelError):
    """One or more form values failed field validation."""

    def __init__(self, errors: Mapping[str, str]):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{key}: {value}" for key, value in self.errors.items()))


class StaleEditorError(StaleSession):
    """An editor callback belongs to an earlier profile/session revision."""


_FIELD_TYPES = frozenset(
    {"text", "multiline", "secret", "date", "integer", "decimal", "currency", "boolean", "url", "choice"}
)
_FIELD_TYPE_ALIASES = {"number": "decimal"}
_TEMPLATE_KEYS = frozenset(
    {"id", "kind", "name", "description", "fields", "version", "revision", "created_at", "updated_at"}
)
_FIELD_KEYS = frozenset(
    {
        "id", "name", "label", "type", "required", "default", "max_length", "choices",
        "secret", "metadata", "protected",
    }
)
# These names have schema-owned sensitivity or trust semantics.  A custom
# template cannot shadow them by changing a flag in its own descriptor.
_PROTECTED_FIELD_NAMES = frozenset(
    {
        "password", "passphrase", "totp", "otp", "recovery_code", "recovery_codes",
        "license_value", "secret", "token", "api_key", "private_key", "note", "body",
        "document_text", "identity", "government_id", "payment", "card_number", "cvv",
    }
)
_METADATA_FIELD_NAMES = frozenset(
    {"title", "url", "website", "vendor", "product", "currency", "amount_minor", "created_at", "updated_at"}
)
_SENSITIVE_WORDS = re.compile(r"(?:password|passphrase|secret|token|api[_ -]?key|recovery[_ -]?code)", re.IGNORECASE)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DECIMAL_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$")


def _text(value: Any, label: str, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TemplateValidationError(f"{label} must be text")
    if "\x00" in value:
        raise TemplateValidationError(f"{label} contains a null character")
    if len(value) > limit:
        raise TemplateValidationError(f"{label} is too long")
    if not allow_empty and not value.strip():
        raise TemplateValidationError(f"{label} cannot be empty")
    return value


def _field_id(value: Any, label: str = "field id") -> str:
    value = _text(value, label, 128).strip()
    if not _ID_RE.fullmatch(value):
        raise TemplateValidationError(f"{label} is malformed")
    return value


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TemplateValidationError(f"{label} is malformed")
    return value


@dataclass(frozen=True)
class FormField:
    """A validated, data-only form field descriptor."""

    id: str
    label: str
    type: str = "text"
    required: bool = False
    default: Any = None
    max_length: int = 4_096
    choices: tuple[str, ...] = ()
    secret: bool = False
    metadata: bool = False
    protected: bool = True

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "label": self.label,
            "type": self.type,
            "required": self.required,
            "max_length": self.max_length,
            "choices": list(self.choices),
            "secret": self.secret,
            "metadata": self.metadata,
            "protected": self.protected,
        }
        # A secret default is rejected at construction, but avoiding it here
        # also makes accidental debug/serialization calls safe by default.
        if self.default is not None and not self.secret:
            result["default"] = copy.deepcopy(self.default)
        return result


@dataclass(frozen=True)
class FormTemplate:
    """Versioned form schema used by the editor and replacement preview."""

    id: str
    kind: str
    name: str
    fields: tuple[FormField, ...]
    description: str = ""
    version: int = 1
    revision: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "revision": self.revision,
            "fields": [field.as_dict() for field in self.fields],
        }

    def field(self, field_id: str) -> FormField:
        for value in self.fields:
            if value.id == field_id:
                return value
        raise KeyError(field_id)

    def defaults(self) -> dict[str, Any]:
        return {value.id: copy.deepcopy(value.default) for value in self.fields if value.default is not None}


def _normalize_template_field(
    raw: Mapping[str, Any], *, allow_metadata: bool, known_fields: set[str]
) -> FormField:
    if not isinstance(raw, Mapping):
        raise TemplateValidationError("template field must be an object")
    if set(raw) - _FIELD_KEYS:
        raise TemplateValidationError("template field contains unsupported data")
    # Existing built-ins use ``name``.  Treat it as a stable ID during the
    # compatibility transition; new callers should provide the explicit id.
    raw_id = raw.get("id", raw.get("name"))
    field_id = _field_id(raw_id)
    label = _text(raw.get("label", raw.get("name", field_id)), "field label", 100).strip()
    field_type = raw.get("type", "text")
    field_type = _FIELD_TYPE_ALIASES.get(field_type, field_type)
    if field_type not in _FIELD_TYPES:
        raise TemplateValidationError("template field type is unsupported")
    required = raw.get("required", False)
    secret = raw.get("secret", field_type == "secret")
    metadata = raw.get("metadata", False)
    if type(required) is not bool or type(secret) is not bool or type(metadata) is not bool:
        raise TemplateValidationError("template field flags are malformed")
    if field_type == "secret":
        secret = True
    if secret and metadata:
        raise TemplateValidationError("secret fields cannot be metadata")
    if metadata and (not allow_metadata or field_id.casefold() not in {name.casefold() for name in known_fields}):
        raise TemplateValidationError("metadata fields require an explicit schema policy")
    max_length = raw.get("max_length", 4_096)
    max_length = _positive_int(max_length, "field max_length", 65_536)
    choices_raw = raw.get("choices", ())
    if field_type == "choice":
        if not isinstance(choices_raw, (list, tuple)) or not 1 <= len(choices_raw) <= 100:
            raise TemplateValidationError("choice fields need between 1 and 100 choices")
        choices: list[str] = []
        seen: set[str] = set()
        for choice in choices_raw:
            value = _text(choice, "choice", 256).strip()
            if value.casefold() in seen:
                raise TemplateValidationError("choice values must be unique")
            seen.add(value.casefold())
            choices.append(value)
        normalized_choices = tuple(choices)
    else:
        if choices_raw not in ((), [], None):
            raise TemplateValidationError("choices are supported only for choice fields")
        normalized_choices = ()
    default = raw.get("default")
    if secret and default is not None:
        raise TemplateValidationError("secret defaults are prohibited")
    # A known schema-owned field is allowed to be protected by its domain
    # schema; arbitrary custom fields are protected regardless of UI flags.
    protected = field_id.casefold() not in {name.casefold() for name in _METADATA_FIELD_NAMES}
    if field_id.casefold() in {name.casefold() for name in _PROTECTED_FIELD_NAMES}:
        protected = True
    if field_id.casefold() not in {name.casefold() for name in known_fields}:
        protected = True
    if metadata:
        protected = False
    field = FormField(
        id=field_id,
        label=label,
        type=field_type,
        required=required,
        default=copy.deepcopy(default),
        max_length=max_length,
        choices=normalized_choices,
        secret=secret,
        metadata=metadata,
        protected=protected,
    )
    # Defaults are validated with the same path as user values, including
    # choices, date, URL, and numeric bounds.
    if default is not None:
        try:
            _validate_field_value(field, default, allow_blank=False)
        except FormValidationError as exc:
            raise TemplateValidationError(f"default for {field_id} is invalid: {exc}") from exc
    return field


def validate_template_definition(
    value: Mapping[str, Any] | FormTemplate,
    *,
    allow_metadata: bool = False,
    known_fields: Sequence[str] = (),
) -> FormTemplate:
    """Validate a versioned declarative template.

    Template input is data only.  Unsupported keys such as expressions,
    scripts, network references, and arbitrary validators are rejected before
    any UI consumes it.  ``name`` remains accepted as a stable field ID for
    the repository's existing built-in templates.
    """
    if isinstance(value, FormTemplate):
        return value
    if not isinstance(value, Mapping):
        raise TemplateValidationError("template must be an object")
    if set(value) - _TEMPLATE_KEYS:
        raise TemplateValidationError("template contains unsupported data")
    template_id = _text(value.get("id", ""), "template id", 128).strip()
    if not _ID_RE.fullmatch(template_id):
        raise TemplateValidationError("template id is malformed")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in ITEM_KINDS:
        raise TemplateValidationError("template kind is unsupported")
    name = _text(value.get("name", ""), "template name", 100).strip()
    description = _text(value.get("description", ""), "template description", 500, allow_empty=True)
    version = value.get("version", 1)
    revision = value.get("revision", 1)
    if type(version) is not int or not 1 <= version <= 2**31 - 1:
        raise TemplateValidationError("template version is malformed")
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise TemplateValidationError("template revision is malformed")
    fields_raw = value.get("fields", ())
    if not isinstance(fields_raw, (list, tuple)) or len(fields_raw) > 50:
        raise TemplateValidationError("template fields must contain at most 50 values")
    field_values: list[FormField] = []
    ids: set[str] = set()
    schema_owned_names = set(known_fields)
    for raw in fields_raw:
        field = _normalize_template_field(raw, allow_metadata=allow_metadata, known_fields=schema_owned_names)
        if field.id.casefold() in ids:
            raise TemplateValidationError("template field IDs must be unique")
        # Existing built-ins use the legacy ``name`` key.  New custom fields
        # use explicit IDs and may not shadow a protected schema-owned name.
        legacy_name = isinstance(raw, Mapping) and "id" not in raw and "name" in raw
        if (field.id.casefold() in {name.casefold() for name in _PROTECTED_FIELD_NAMES}
                and field.id.casefold() not in {name.casefold() for name in schema_owned_names}
                and not legacy_name):
            raise TemplateValidationError("custom field shadows a protected field")
        ids.add(field.id.casefold())
        field_values.append(field)
    return FormTemplate(
        id=template_id,
        kind=kind,
        name=name,
        description=description,
        version=version,
        revision=revision,
        fields=tuple(field_values),
    )


def clone_template(
    template: Mapping[str, Any] | FormTemplate,
    *,
    template_id: str,
    name: str,
    revision: int = 1,
    allow_metadata: bool = False,
) -> FormTemplate:
    """Clone a built-in/custom template with a new stable identity."""
    source = validate_template_definition(template, allow_metadata=allow_metadata)
    candidate = source.as_dict()
    candidate.update({"id": template_id, "name": name, "revision": revision})
    return validate_template_definition(
        candidate,
        allow_metadata=allow_metadata,
        known_fields=[value.id for value in source.fields],
    )


def _validate_field_value(field: FormField, value: Any, *, allow_blank: bool = True) -> Any:
    if value is None:
        if field.required and not allow_blank:
            raise FormValidationError({field.id: "This field is required."})
        return ""
    if field.type == "boolean":
        if type(value) is not bool:
            raise FormValidationError({field.id: "Choose true or false."})
        return value
    if isinstance(value, str):
        if len(value) > field.max_length:
            raise FormValidationError({field.id: f"Use at most {field.max_length} characters."})
        if not value.strip():
            if field.required and not allow_blank:
                raise FormValidationError({field.id: "This field is required."})
            return ""
    if field.type in {"text", "multiline", "secret"}:
        if not isinstance(value, str):
            raise FormValidationError({field.id: "Enter text."})
        return value
    if field.type == "date":
        if not isinstance(value, str):
            raise FormValidationError({field.id: "Enter a date as YYYY-MM-DD."})
        try:
            _datetime.date.fromisoformat(value)
        except ValueError:
            raise FormValidationError({field.id: "Enter a date as YYYY-MM-DD."}) from None
        return value
    if field.type == "url":
        try:
            return validate_bookmark_url(value)
        except (ItemSchemaError, TypeError) as exc:
            raise FormValidationError({field.id: "Enter an http or https URL."}) from exc
    if field.type == "integer":
        if type(value) is int:
            return value
        if not isinstance(value, str) or not re.fullmatch(r"[+-]?\d+", value.strip()):
            raise FormValidationError({field.id: "Enter a whole number."})
        return int(value)
    if field.type in {"decimal", "currency"}:
        if type(value) is bool or (not isinstance(value, (str, int, float, Decimal))):
            raise FormValidationError({field.id: "Enter a number."})
        text = str(value).strip()
        if not _DECIMAL_RE.fullmatch(text):
            raise FormValidationError({field.id: "Enter a number."})
        try:
            number = Decimal(text)
        except InvalidOperation:
            raise FormValidationError({field.id: "Enter a number."}) from None
        if not number.is_finite():
            raise FormValidationError({field.id: "Enter a finite number."})
        return number
    if field.type == "choice":
        if not isinstance(value, str) or value not in field.choices:
            raise FormValidationError({field.id: "Choose one of the available values."})
        return value
    raise FormValidationError({field.id: "This field type is unsupported."})


def validate_form_values(
    template: Mapping[str, Any] | FormTemplate,
    values: Mapping[str, Any],
    *,
    allow_unknown: bool = False,
) -> dict[str, Any]:
    """Validate and normalize values for an explicit editor submission."""
    schema = validate_template_definition(template)
    if not isinstance(values, Mapping):
        raise FormValidationError({"form": "Form values must be an object."})
    field_ids = {value.id for value in schema.fields}
    if not allow_unknown and set(values) - field_ids:
        raise FormValidationError({str(key): "This field is not in the selected template." for key in set(values) - field_ids})
    result = schema.defaults()
    errors: dict[str, str] = {}
    for field_spec in schema.fields:
        raw = values[field_spec.id] if field_spec.id in values else result.get(field_spec.id, "")
        try:
            result[field_spec.id] = _validate_field_value(field_spec, raw, allow_blank=False)
        except FormValidationError as exc:
            errors.update(exc.errors)
    if errors:
        raise FormValidationError(errors)
    return result


def preview_form(
    template: Mapping[str, Any] | FormTemplate,
    values: Mapping[str, Any],
    *,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    """Return an application preview, masking secret fields by default."""
    schema = validate_template_definition(template)
    normalized = validate_form_values(schema, values)
    result: dict[str, Any] = {}
    for field_spec in schema.fields:
        value = normalized.get(field_spec.id, "")
        if field_spec.secret and not reveal_secrets and value not in ("", None):
            result[field_spec.id] = "••••••••"
        else:
            result[field_spec.id] = value
    return result


def apply_template_values(
    template: Mapping[str, Any] | FormTemplate,
    values: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
    expected_revision: int | None = None,
    current_revision: int | None = None,
) -> dict[str, Any]:
    """Validate an explicit replacement application with revision guarding."""
    schema = validate_template_definition(template)
    if expected_revision is not None and current_revision != expected_revision:
        raise StaleEditorError("The item or template changed; review the form again.")
    merged = dict(existing or {})
    merged.update(values)
    return validate_form_values(schema, merged)


def _wipe(value: Any) -> None:
    if isinstance(value, MutableMapping):
        for nested in list(value.values()):
            _wipe(nested)
        value.clear()
    elif isinstance(value, list):
        for nested in value:
            _wipe(nested)
        value.clear()


@dataclass(frozen=True)
class EditorSnapshot:
    values: Mapping[str, Any]
    revision: int


class EditorUndoModel:
    """Bounded in-memory undo/redo history for one explicit editor."""

    def __init__(self, values: Mapping[str, Any] | None = None, *, revision: int = 1, max_entries: int = 50) -> None:
        if type(revision) is not int or revision < 0:
            raise ValueError("revision must be a non-negative integer")
        if type(max_entries) is not int or not 1 <= max_entries <= 200:
            raise ValueError("max_entries must be between 1 and 200")
        self._initial = copy.deepcopy(dict(values or {}))
        self._values = copy.deepcopy(self._initial)
        self._undo: list[EditorSnapshot] = []
        self._redo: list[EditorSnapshot] = []
        self._revision = revision
        self._max_entries = max_entries
        self._valid = True
        self._saved_values = copy.deepcopy(self._values)

    @property
    def values(self) -> dict[str, Any]:
        self._require_valid()
        return copy.deepcopy(self._values)

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def dirty(self) -> bool:
        return self._valid and self._values != self._saved_values

    @property
    def can_undo(self) -> bool:
        return bool(self._undo) and self._valid

    @property
    def can_redo(self) -> bool:
        return bool(self._redo) and self._valid

    def _require_valid(self, expected_revision: int | None = None) -> None:
        if not self._valid:
            raise StaleEditorError("The editor session is no longer valid.")
        if expected_revision is not None and expected_revision != self._revision:
            raise StaleEditorError("The editor revision changed; review the form again.")

    def _push(self) -> None:
        self._undo.append(EditorSnapshot(copy.deepcopy(self._values), self._revision))
        del self._undo[:-self._max_entries]
        self._redo.clear()

    def set_value(self, field_id: str, value: Any, *, expected_revision: int | None = None) -> None:
        self._require_valid(expected_revision)
        if self._values.get(field_id) == value:
            return
        self._push()
        self._values[field_id] = copy.deepcopy(value)

    def replace(self, values: Mapping[str, Any], *, expected_revision: int | None = None) -> None:
        self._require_valid(expected_revision)
        candidate = copy.deepcopy(dict(values))
        if candidate == self._values:
            return
        self._push()
        self._values = candidate

    def undo(self, *, expected_revision: int | None = None) -> dict[str, Any]:
        self._require_valid(expected_revision)
        if not self._undo:
            return self.values
        self._redo.append(EditorSnapshot(copy.deepcopy(self._values), self._revision))
        self._values = copy.deepcopy(dict(self._undo.pop().values))
        return self.values

    def redo(self, *, expected_revision: int | None = None) -> dict[str, Any]:
        self._require_valid(expected_revision)
        if not self._redo:
            return self.values
        self._undo.append(EditorSnapshot(copy.deepcopy(self._values), self._revision))
        self._values = copy.deepcopy(dict(self._redo.pop().values))
        return self.values

    def mark_saved(self, *, revision: int | None = None) -> None:
        self._require_valid()
        if revision is not None:
            if type(revision) is not int or revision < 0:
                raise ValueError("revision must be a non-negative integer")
            self._revision = revision
        self._saved_values = copy.deepcopy(self._values)
        self._initial = copy.deepcopy(self._values)
        self._undo.clear()
        self._redo.clear()

    def cancel(self) -> None:
        """Discard the edit and all protected buffers."""
        self.clear()

    def clear(self) -> None:
        _wipe(self._initial)
        _wipe(self._values)
        _wipe(self._saved_values)
        self._undo.clear()
        self._redo.clear()
        self._valid = False

    invalidate = clear
    clear_on_lock = clear
    clear_on_profile_switch = clear


UndoModel = EditorUndoModel


class RecoveryDrillStage(str, Enum):
    READY = "ready"
    CREATED = "created"
    INSPECTED = "inspected"
    VERIFIED = "verified"
    PLANNED = "planned"
    RESTORED = "restored"
    CATALOG_VERIFIED = "catalog_verified"
    SAMPLE_OPENED = "sample_opened"
    KIT_WRITTEN = "kit_written"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RecoveryDrillState:
    stage: RecoveryDrillStage = RecoveryDrillStage.READY
    backup_path: str | None = None
    backup_sha256: str | None = None
    trial_profile: str | None = None
    verified_backup: bool = False
    verified_catalog: bool = False
    result: Mapping[str, Any] = field(default_factory=dict)


def _safe_result(result: Mapping[str, Any] | Any) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {}
    safe = summarize_recovery(result)
    # These bounded booleans/counts are drill evidence, not vault payload.
    for key in ("catalog_verified", "reachable_blobs_verified", "typed_items", "templates", "sample_opened"):
        if key in result:
            safe[key] = result[key]
    return safe


class GuidedRecoveryDrill:
    """Explicit Create → Verify → Plan → Test → Catalog → Kit recovery flow."""

    def __init__(
        self,
        controller: RecoveryController | None = None,
        *,
        service: RecoveryService | None = None,
        session_checker: Callable[[], Any] | None = None,
        catalog_verifier: Callable[[Path, str], Mapping[str, Any]] | None = None,
        sample_opener: Callable[[Path, str], Mapping[str, Any]] | None = None,
    ) -> None:
        if controller is None and service is None:
            raise RecoveryError("A recovery controller or service is required")
        self.controller = controller
        self.service = service or controller.service  # type: ignore[union-attr]
        self._session_checker = session_checker
        self._catalog_verifier = catalog_verifier
        self._sample_opener = sample_opener
        self._state = RecoveryDrillState()

    @property
    def state(self) -> RecoveryDrillState:
        return self._state

    def _require_session(self) -> None:
        if self.controller is not None:
            self.controller.binding.current()
        if self._session_checker is not None:
            self._session_checker()

    def _set(self, stage: RecoveryDrillStage, result: Mapping[str, Any], **updates: Any) -> dict[str, Any]:
        safe = _safe_result(result)
        backup_path = updates.pop("backup_path", self._state.backup_path)
        backup_sha256 = updates.pop("backup_sha256", self._state.backup_sha256)
        if backup_sha256 is None:
            backup_sha256 = safe.get("backup_sha256") or safe.get("sha256")
        self._state = RecoveryDrillState(
            stage=stage,
            backup_path=backup_path,
            backup_sha256=backup_sha256,
            trial_profile=updates.pop("trial_profile", self._state.trial_profile),
            verified_backup=updates.pop("verified_backup", self._state.verified_backup),
            verified_catalog=updates.pop("verified_catalog", self._state.verified_catalog),
            result=safe,
        )
        return copy.deepcopy(safe)

    def create(self, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        self._require_session()
        result = (self.controller.create_backup(destination, **kwargs)
                  if self.controller is not None else self.service.create_backup(destination, **kwargs))
        self._require_session()
        return self._set(RecoveryDrillStage.CREATED, result, backup_path=str(destination))

    def inspect(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        # Manifest/backup inspection is independent of the live session.
        result = self.service.inspect_backup(source, **kwargs)
        return self._set(RecoveryDrillStage.INSPECTED, result, backup_path=str(source), verified_backup=False)

    def verify(self, source: Path | str, **kwargs: Any) -> dict[str, Any]:
        result = (self.controller.verify_backup(source, **kwargs)
                  if self.controller is not None else self.service.verify_backup(source, **kwargs))
        if result.get("verified") is not True:
            raise RecoveryError("Backup verification did not produce a verified result")
        return self._set(RecoveryDrillStage.VERIFIED, result, backup_path=str(source), verified_backup=True)

    def plan(self, source: Path | str, destination: Path | str, **kwargs: Any) -> dict[str, Any]:
        result = (self.controller.plan_restore(source, destination, **kwargs)
                  if self.controller is not None else self.service.plan_restore(source, destination, **kwargs))
        if result.get("dry_run") is not True or result.get("requires_confirmation") is not True:
            raise RecoveryError("Recovery plan must be a non-mutating confirmation step")
        return self._set(RecoveryDrillStage.PLANNED, result, backup_path=str(source), trial_profile=str(destination))

    def test_restore(self, source: Path | str, destination: Path | str, *, confirm: bool = False, **kwargs: Any) -> dict[str, Any]:
        """Preview unless the caller explicitly confirms a fresh trial profile."""
        if confirm:
            # A direct service seam may be used in tests or other UI callers;
            # enforce the same active-session guard before any confirmed write.
            self._require_session()
        result = (self.controller.restore(source, destination, confirm=confirm, **kwargs)
                  if self.controller is not None else self.service.restore(source, destination, confirm=confirm, **kwargs))
        stage = RecoveryDrillStage.RESTORED if result.get("committed") is True else RecoveryDrillStage.PLANNED
        return self._set(stage, result, backup_path=str(source), trial_profile=str(destination))

    def verify_restored_catalog(
        self,
        trial_profile: Path | str,
        *,
        vault_password: str | SecretText,
        verifier: Callable[[Path, str | SecretText], Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Authenticate the restored profile and all reachable data.

        A caller may supply the application's richer catalog/blob verifier.
        The fallback unlocks the restored catalog and walks typed items, which
        still proves the profile is readable without exposing its values.
        """
        if is_blank_secret(vault_password):
            raise RecoveryError("Vault master password is required for catalog verification")
        path = Path(trial_profile)
        check = verifier or self._catalog_verifier
        if check is not None:
            result = dict(check(path, vault_password))
        else:
            from .vault import unlock_vault
            session = unlock_vault(path / "vault.json", vault_password)
            try:
                entries = session.all_entries()
                payload = session._require_typed_catalog()
                # Reading each catalog-referenced sidecar exercises the
                # authenticated blob path.  Plaintext is released immediately
                # and is never included in the evidence mapping.
                attachment_store = session.attachments
                attachment_records = payload.get("attachments", [])
                for record in attachment_records:
                    if isinstance(record, Mapping) and isinstance(record.get("id"), str):
                        blob = attachment_store.read_bytes(record["id"])
                        del blob
                result = {
                    "catalog_verified": True,
                    "entries": len(entries),
                    "typed_items": len(payload.get("items", [])),
                    "templates": len(payload.get("templates", [])),
                    "attachments": len(attachment_records),
                    "reachable_blobs_verified": True,
                }
                del entries
            finally:
                session.lock()
        safe = _safe_result(result)
        if result.get("catalog_verified", result.get("verified", False)) is not True:
            raise RecoveryError("Restored catalog verification did not complete")
        return self._set(RecoveryDrillStage.CATALOG_VERIFIED, safe, trial_profile=str(path), verified_catalog=True)

    def open_sample(self, trial_profile: Path | str, *, sample_id: str, opener: Callable[[Path, str], Mapping[str, Any]] | None = None) -> dict[str, Any]:
        if not isinstance(sample_id, str) or not sample_id.strip() or _SENSITIVE_WORDS.search(sample_id):
            raise RecoveryError("Choose a non-secret sample identifier")
        callback = opener or self._sample_opener
        if callback is None:
            raise RecoveryError("An explicit sample opener is required")
        result = dict(callback(Path(trial_profile), sample_id))
        safe = _safe_result(result)
        return self._set(RecoveryDrillStage.SAMPLE_OPENED, safe, trial_profile=str(trial_profile), verified_catalog=True)

    def kit(self, destination: Path | str, *, backup: Path | str | None = None, **kwargs: Any) -> dict[str, Any]:
        if not self._state.verified_catalog:
            raise RecoveryError("Verify the restored catalog before writing a recovery kit")
        source = backup or self._state.backup_path
        if source is None:
            raise RecoveryError("A verified backup is required for the recovery kit")
        result = self.service.recovery_kit(destination, backup=source, **kwargs)
        return self._set(RecoveryDrillStage.KIT_WRITTEN, result, backup_path=str(source), verified_catalog=True)

    # Service-shaped aliases make the controller straightforward to wire into
    # an existing Recovery Center without creating a second recovery API.
    create_backup = create
    inspect_backup = inspect
    verify_backup = verify
    plan_restore = plan
    restore_trial = test_restore
    verify_catalog = verify_restored_catalog
    write_kit = kit

    def cancel(self) -> None:
        self._state = RecoveryDrillState(stage=RecoveryDrillStage.CANCELLED)


RecoveryDrillController = GuidedRecoveryDrill


ONBOARDING_STAGES = (
    "welcome", "security", "demo", "bridge_diagnostic", "first_item", "backup", "complete"
)
_ONBOARDING_CHOICES = frozenset({"offline_mode", "demo_enabled", "bridge_diagnostic", "backup_verified", "first_item_created"})


class OnboardingStage(str, Enum):
    WELCOME = "welcome"
    SECURITY = "security"
    DEMO = "demo"
    BRIDGE_DIAGNOSTIC = "bridge_diagnostic"
    FIRST_ITEM = "first_item"
    BACKUP = "backup"
    COMPLETE = "complete"


@dataclass
class OnboardingState:
    """Serializable progress only; no password, token, or vault content."""

    profile_id: str
    stage: str = "welcome"
    completed: set[str] = field(default_factory=set)
    skipped: set[str] = field(default_factory=set)
    choices: dict[str, bool] = field(default_factory=dict)
    revision: int = 1
    updated_at: int = field(default_factory=lambda: int(time.time()))

    def __post_init__(self) -> None:
        self.profile_id = _text(self.profile_id, "profile id", 256)
        if self.stage not in ONBOARDING_STAGES:
            raise UIModelError("onboarding stage is unsupported")
        if not self.completed.issubset(set(ONBOARDING_STAGES)) or not self.skipped.issubset(set(ONBOARDING_STAGES)):
            raise UIModelError("onboarding progress contains an unsupported stage")
        if set(self.choices) - _ONBOARDING_CHOICES or any(type(v) is not bool for v in self.choices.values()):
            raise UIModelError("onboarding choices are malformed")
        if _SENSITIVE_WORDS.search(self.profile_id):
            raise UIModelError("profile id cannot contain secret labels")

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "stage": self.stage,
            "completed": sorted(self.completed),
            "skipped": sorted(self.skipped),
            "choices": dict(self.choices),
            "revision": self.revision,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> OnboardingState:
        if not isinstance(value, Mapping):
            raise UIModelError("onboarding state is malformed")
        allowed = {"profile_id", "stage", "completed", "skipped", "choices", "revision", "updated_at"}
        if set(value) - allowed:
            raise UIModelError("onboarding state contains unsupported data")
        completed, skipped = value.get("completed", []), value.get("skipped", [])
        if not isinstance(completed, list) or not isinstance(skipped, list):
            raise UIModelError("onboarding progress is malformed")
        revision, updated_at = value.get("revision", 1), value.get("updated_at", int(time.time()))
        if type(revision) is not int or revision < 1 or type(updated_at) is not int or updated_at < 0:
            raise UIModelError("onboarding timestamps are malformed")
        choices = value.get("choices", {})
        if not isinstance(choices, Mapping):
            raise UIModelError("onboarding choices are malformed")
        return cls(
            profile_id=str(value.get("profile_id", "")),
            stage=str(value.get("stage", "welcome")),
            completed=set(completed),
            skipped=set(skipped),
            choices=dict(choices),
            revision=revision,
            updated_at=updated_at,
        )

    def advance(self, stage: str) -> OnboardingState:
        if stage not in ONBOARDING_STAGES:
            raise UIModelError("onboarding stage is unsupported")
        current_index = ONBOARDING_STAGES.index(self.stage)
        target_index = ONBOARDING_STAGES.index(stage)
        if target_index < current_index:
            # Revisiting is allowed, but does not erase earlier progress.
            self.stage = stage
        else:
            self.completed.add(self.stage)
            self.stage = stage
        self.revision += 1
        self.updated_at = int(time.time())
        return self

    def skip(self, stage: str | None = None) -> OnboardingState:
        target = stage or self.stage
        if target not in ONBOARDING_STAGES or target == "complete":
            raise UIModelError("that onboarding step cannot be skipped")
        self.skipped.add(target)
        self.completed.discard(target)
        self.revision += 1
        self.updated_at = int(time.time())
        return self

    def choose(self, key: str, value: bool) -> OnboardingState:
        if key not in _ONBOARDING_CHOICES or type(value) is not bool:
            raise UIModelError("unsupported onboarding choice")
        self.choices[key] = value
        self.revision += 1
        self.updated_at = int(time.time())
        return self


class OnboardingStore:
    """Local JSON progress store keyed by profile identity."""

    FORMAT = "localgatekeys-onboarding-v1"

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"format": self.FORMAT, "profiles": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise UIModelError("onboarding progress cannot be read") from exc
        if not isinstance(data, dict) or data.get("format") != self.FORMAT or not isinstance(data.get("profiles"), dict):
            raise UIModelError("onboarding progress has an unsupported format")
        return data

    def load(self, profile_id: str) -> OnboardingState:
        profile_id = _text(profile_id, "profile id", 256)
        data = self._read()
        value = data["profiles"].get(profile_id)
        return OnboardingState(profile_id=profile_id) if value is None else OnboardingState.from_dict(value)

    def save(self, state: OnboardingState) -> OnboardingState:
        if not isinstance(state, OnboardingState):
            raise UIModelError("onboarding state is required")
        data = self._read()
        data["profiles"][state.profile_id] = state.to_dict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except (OSError, TypeError, ValueError) as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise UIModelError("onboarding progress cannot be saved") from exc
        return state


class OnboardingController:
    """Resumable/skippable onboarding bound to an optional session identity."""

    def __init__(self, profile_id: str, store: OnboardingStore, *, session_checker: Callable[[], Any] | None = None) -> None:
        self.store = store
        self._session_checker = session_checker
        self._valid = True
        self._state = store.load(profile_id)

    @property
    def state(self) -> OnboardingState:
        self._require_valid()
        return copy.deepcopy(self._state)

    def _require_valid(self) -> None:
        if not self._valid:
            raise StaleSession("Onboarding belongs to a previous profile/session")
        if self._session_checker is not None:
            self._session_checker()

    def _save(self) -> OnboardingState:
        self._require_valid()
        self.store.save(self._state)
        return self.state

    def advance(self, stage: str) -> OnboardingState:
        self._state.advance(stage)
        return self._save()

    def skip(self, stage: str | None = None) -> OnboardingState:
        self._state.skip(stage)
        return self._save()

    def choose(self, key: str, value: bool) -> OnboardingState:
        self._state.choose(key, value)
        return self._save()

    def invalidate(self) -> None:
        self._valid = False

    on_lock = invalidate
    on_profile_switch = invalidate


class ThemeMode(str, Enum):
    LIGHT = "light"
    DARK = "dark"
    SYSTEM = "system"
    HIGH_CONTRAST = "high_contrast"


@dataclass(frozen=True)
class ThemeTokens:
    mode: ThemeMode
    background: str
    surface: str
    text: str
    muted_text: str
    accent: str
    focus: str
    border: str
    error: str
    success: str
    warning: str
    high_contrast: bool = False
    ordinary_text_contrast_target: float = 4.5
    large_text_contrast_target: float = 3.0

    @property
    def bg(self) -> str:
        return self.background


def resolve_theme(mode: ThemeMode | str = ThemeMode.SYSTEM, *, system_is_dark: bool = True, high_contrast: bool = False) -> ThemeTokens:
    """Resolve light/dark/system/high-contrast tokens without touching Tk."""
    try:
        requested = ThemeMode(mode)
    except ValueError as exc:
        raise UIModelError("unsupported theme mode") from exc
    if high_contrast or requested is ThemeMode.HIGH_CONTRAST:
        return ThemeTokens(ThemeMode.HIGH_CONTRAST, "#000000", "#000000", "#FFFFFF", "#FFFFFF", "#00FFFF", "#FFFF00", "#FFFFFF", "#FF6666", "#66FF66", "#FFFF00", True)
    if requested is ThemeMode.SYSTEM:
        requested = ThemeMode.DARK if system_is_dark else ThemeMode.LIGHT
    if requested is ThemeMode.LIGHT:
        return ThemeTokens(requested, "#F6F8FB", "#FFFFFF", "#172033", "#4D5D73", "#155EEF", "#0B73E8", "#B8C3D1", "#B42318", "#067647", "#9A6700")
    return ThemeTokens(requested, "#07111F", "#0B1726", "#F7FAFF", "#AAB8C7", "#4E83FF", "#26D4F2", "#2B4665", "#FF6877", "#45D49C", "#F0BD4F")


theme_tokens = resolve_theme


def dpi_scale(value: float, dpi: float = 96) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise UIModelError("DPI value must be finite")
    if isinstance(dpi, bool) or not isinstance(dpi, (int, float)) or not math.isfinite(float(dpi)) or float(dpi) <= 0:
        raise UIModelError("DPI must be positive")
    return max(1, round(float(value) * float(dpi) / 96.0))


scale_for_dpi = dpi_scale


def dpi_metrics(*, dpi: float = 96, padding: int = 12, row_height: int = 32, font_size: int = 10) -> dict[str, int]:
    return {"padding": dpi_scale(padding, dpi), "row_height": dpi_scale(row_height, dpi), "font_size": dpi_scale(font_size, dpi)}


def safe_accessibility_label(label: str, *, secret: bool = False) -> str:
    """Return a visible semantic label while refusing secret values."""
    if secret:
        raise UIModelError("secret values cannot be accessibility labels")
    value = _text(label, "accessibility label", 200).replace("\n", " ").strip()
    if _SENSITIVE_WORDS.search(value) and (":" in value or "=" in value):
        raise UIModelError("accessibility labels cannot contain secret values")
    return value


accessibility_label = safe_accessibility_label


def keyboard_accessibility_bindings() -> dict[str, tuple[str, ...]]:
    return {
        "next": ("<Tab>",),
        "previous": ("<Shift-Tab>",),
        "activate": ("<Return>", "<space>"),
        "cancel": ("<Escape>",),
        "undo": ("<Control-z>",),
        "redo": ("<Control-y>", "<Control-Shift-z>"),
    }


__all__ = [
    "ONBOARDING_STAGES",
    "EditorSnapshot",
    "EditorUndoModel",
    "FormField",
    "FormTemplate",
    "FormValidationError",
    "GuidedRecoveryDrill",
    "OnboardingController",
    "OnboardingState",
    "OnboardingStore",
    "RecoveryDrillController",
    "RecoveryDrillStage",
    "RecoveryDrillState",
    "StaleEditorError",
    "TemplateValidationError",
    "ThemeMode",
    "ThemeTokens",
    "UIModelError",
    "UndoModel",
    "accessibility_label",
    "apply_template_values",
    "clone_template",
    "dpi_metrics",
    "dpi_scale",
    "keyboard_accessibility_bindings",
    "preview_form",
    "resolve_theme",
    "safe_accessibility_label",
    "scale_for_dpi",
    "theme_tokens",
    "validate_form_values",
    "validate_template_definition",
]

# Friendly compatibility names for callers that do not need to distinguish
# the view-model's schema terminology from the existing template service.
FormSchema = FormTemplate
TemplateSchema = FormTemplate
EditorState = EditorUndoModel
RecoveryDrill = GuidedRecoveryDrill
GuidedRecoveryController = GuidedRecoveryDrill
OnboardingProgress = OnboardingState
Theme = ThemeTokens
validate_template = validate_template_definition
validate_form = validate_form_values
apply_form = apply_template_values

__all__ += [
    "EditorState", "FormSchema", "GuidedRecoveryController", "OnboardingProgress", "OnboardingStage",
    "RecoveryDrill", "TemplateSchema", "Theme", "apply_form", "validate_form", "validate_template",
]
