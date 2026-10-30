"""Tk-free model of the login editor form.

``LoginDraft`` is what the user is typing; ``validate`` reports problems per
field key with no UI side effects; ``save_kwargs`` turns a valid draft into the
keyword arguments of ``VaultSession.save_login`` / ``create_web_login``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from ..access_policy import normalized_policy
from ..item_schema import (
    MAX_NOTE_BODY,
    MAX_PROTECTED_VALUE,
    MAX_TAG_LENGTH,
    MAX_TAGS,
    MAX_TITLE,
    MAX_URL,
    MAX_WEB_URLS,
    ItemSchemaError,
    validate_web_urls,
)
from ..origin import MATCH_MODES, OriginError, canonicalize_origin, origin_of
from ..i18n import t
from ..password_tools import estimate_strength, strength_label
from ..totp import TotpError, generate_totp, normalize_secret, parse_otpauth_uri
from ..vault import friendly_origin_label

# Limits vault.py states as literals (_validated_web_login, _apply_entry_fields,
# set_details); label, notes and field values alias the equal item_schema constants.
MAX_PASSWORD = 4096
MAX_USERNAME = 512
MAX_LABEL = MAX_TITLE
MAX_NOTES = MAX_NOTE_BODY
MAX_RECOVERY_CODES = 100
MAX_RECOVERY_CODE = 512
MAX_CUSTOM_FIELDS = 50
MAX_FIELD_NAME = 100
MAX_FIELD_VALUE = MAX_PROTECTED_VALUE

UNTITLED = "Untitled login"
DEFAULT_MATCH = "exact_origin"


@dataclass
class UrlRow:
    url: str
    match: str = DEFAULT_MATCH


@dataclass
class LoginDraft:
    kind: Literal["web", "desktop"] = "web"
    entry_id: str | None = None
    label: str = ""
    label_edited: bool = False
    urls: list[UrlRow] = field(default_factory=list)
    username: str = ""
    password: str | None = None  # None means "keep current"
    favorite: bool = False
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    totp_text: str = ""
    totp_algorithm: str = "SHA1"
    totp_digits: int = 6
    totp_period: int = 30
    recovery_codes: list[str] = field(default_factory=list)
    custom_fields: list[dict] = field(default_factory=list)
    policy: dict = field(default_factory=lambda: normalized_policy(None))
    app_path: str = ""
    window_title: str = ""
    desktop_binding: dict | None = None  # new desktop logins only


@dataclass(frozen=True)
class FieldError:
    field: str
    message: str


@dataclass(frozen=True)
class PasswordMeta:
    segments: int
    label: str
    reuse_text: str


def draft_for_new_web(generated_password: str) -> LoginDraft:
    return LoginDraft(kind="web", urls=[UrlRow("", DEFAULT_MATCH)], password=generated_password)


def draft_from_detail(detail: dict, urls: list[dict]) -> LoginDraft:
    """Build a draft from ``credential_detail`` output; never reads a password."""
    kind = "desktop" if detail.get("kind") == "desktop" else "web"
    scope = detail.get("scope") if isinstance(detail.get("scope"), dict) else {}
    rows = [UrlRow(str(r.get("url", "")), str(r.get("match", DEFAULT_MATCH))) for r in (urls or [])]
    if kind == "web" and not rows and scope.get("origin"):
        rows = [UrlRow(str(scope["origin"]), DEFAULT_MATCH)]
    label = str(detail.get("label") or "")
    derived = _derived_label(rows) if kind == "web" else ""
    totp = detail.get("totp") if isinstance(detail.get("totp"), dict) else None
    draft = LoginDraft(
        kind=kind,
        entry_id=detail.get("id"),
        label=label,
        label_edited=bool(label) and label != derived,
        urls=rows,
        username=str(detail.get("username") or ""),
        password=None,
        favorite=bool(detail.get("favorite")),
        tags=[str(t) for t in detail.get("tags") or []],
        notes=str(detail.get("notes") or ""),
        recovery_codes=[str(c) for c in detail.get("recovery_codes") or []],
        custom_fields=[{"name": str(f.get("name", "")), "value": str(f.get("value", "")),
                        "hidden": f.get("hidden", True) is True}
                       for f in detail.get("custom_fields") or [] if isinstance(f, dict)],
        policy=normalized_policy(detail.get("policy")),
        app_path=str(scope.get("exe_path") or ""),
        window_title=str(scope.get("window_title") or ""),
    )
    if totp:
        draft.totp_text = str(totp.get("secret", ""))
        draft.totp_algorithm = str(totp.get("algorithm", "SHA1")).upper()
        draft.totp_digits = int(totp.get("digits", 6))
        draft.totp_period = int(totp.get("period", 30))
    return draft


def _derived_label(rows: list[UrlRow]) -> str:
    for row in rows:
        text = row.url.strip()
        if not text:
            continue
        try:
            return friendly_origin_label(origin_of(text))
        except OriginError:
            return friendly_origin_label(text)
    return ""


def display_label(d: LoginDraft) -> str:
    """The label for display: the stored English default is shown in the active language."""
    label = effective_label(d)
    return t("loginForm.untitled") if label == UNTITLED else label


def effective_label(d: LoginDraft) -> str:
    if d.label_edited and d.label.strip():
        return d.label.strip()
    if d.kind == "web":
        return _derived_label(d.urls) or UNTITLED
    return d.label.strip() or UNTITLED


def _url_error(row: UrlRow) -> tuple[dict[str, str] | None, str]:
    """Return the normalised vault row, or an inline error message."""
    text = row.url.strip()
    if not text:
        return None, t("loginForm.err.enterAddress")
    if row.match not in MATCH_MODES:
        return None, t("loginForm.err.matchMode")
    if len(text) > MAX_URL:
        return None, t("loginForm.err.addressTooLong", max=MAX_URL)
    if "://" not in text:
        text = "https://" + text  # people type bare domains; plain HTTP must be explicit
    try:
        if row.match == "exact_origin":
            # The vault rejects a path on exact-origin rows; keep only the origin.
            text = canonicalize_origin(origin_of(text))
        validate_web_urls([{"url": text, "match": row.match}])
    except ItemSchemaError as exc:
        return None, str(exc).removeprefix("url is malformed: ")
    except ValueError as exc:  # OriginError, or any parser error that escaped it
        return None, str(exc) if isinstance(exc, OriginError) else t("loginForm.err.validAddress")
    return {"url": text, "match": row.match}, ""


def _clean_tags(tags: list[str]) -> list[str]:
    return list(dict.fromkeys(t.strip() for t in tags if t and t.strip()))


def _filled_fields(d: LoginDraft) -> list[tuple[int, dict]]:
    return [(i, f) for i, f in enumerate(d.custom_fields)
            if str(f.get("name", "")).strip() or str(f.get("value", ""))]


def totp_config(d: LoginDraft) -> dict | None:
    """The dict ``set_details`` expects, or None when the field is blank.

    Raises ``TotpError`` when the text is not a valid secret or URI.
    """
    text = d.totp_text.strip()
    if not text:
        return None
    if text.lower().startswith("otpauth:"):
        parsed = parse_otpauth_uri(text)
        config = {"secret": parsed["secret"], "algorithm": parsed["algorithm"],
                  "digits": parsed["digits"], "period": parsed["period"]}
    else:
        config = {"secret": normalize_secret(text), "algorithm": str(d.totp_algorithm).upper(),
                  "digits": d.totp_digits, "period": d.totp_period}
    generate_totp(**config)  # validates digits, period and algorithm
    return config


def validate(d: LoginDraft) -> list[FieldError]:
    errors: list[FieldError] = []
    if d.kind == "web":
        if not d.urls:
            errors.append(FieldError("urls", t("loginForm.err.addUrl")))
        elif len(d.urls) > MAX_WEB_URLS:
            errors.append(FieldError("urls", t("loginForm.err.maxUrls", max=MAX_WEB_URLS)))
        else:
            for i, row in enumerate(d.urls):
                _, message = _url_error(row)
                if message:
                    errors.append(FieldError(f"urls[{i}]", message))
    if len(d.username) > MAX_USERNAME:
        errors.append(FieldError("username", t("loginForm.err.usernameTooLong", max=MAX_USERNAME)))
    if d.label_edited and len(d.label.strip()) > MAX_LABEL:
        errors.append(FieldError("label", t("loginForm.err.nameTooLong", max=MAX_LABEL)))
    if d.password is None:
        if d.entry_id is None:
            errors.append(FieldError("password", t("loginForm.err.enterPassword")))
    elif not d.password:
        errors.append(FieldError("password", t("loginForm.err.passwordEmpty")))
    elif len(d.password) > MAX_PASSWORD:
        errors.append(FieldError("password", t("loginForm.err.passwordTooLong", max=MAX_PASSWORD)))
    if len(d.notes) > MAX_NOTES:
        errors.append(FieldError("notes", t("loginForm.err.notesTooLong", max=MAX_NOTES)))
    tags = _clean_tags(d.tags)
    if len(tags) > MAX_TAGS:
        errors.append(FieldError("tags", t("loginForm.err.maxTags", max=MAX_TAGS)))
    elif any(len(t) > MAX_TAG_LENGTH for t in tags):
        errors.append(FieldError("tags", t("loginForm.err.tagTooLong", max=MAX_TAG_LENGTH)))
    try:
        totp_config(d)
    except (TotpError, ValueError, TypeError) as exc:
        errors.append(FieldError("totp", str(exc) or t("loginForm.err.totpInvalid")))
    codes = [c for c in d.recovery_codes if c.strip()]
    if len(codes) > MAX_RECOVERY_CODES:
        errors.append(FieldError("recovery_codes", t("loginForm.err.maxRecoveryCodes", max=MAX_RECOVERY_CODES)))
    elif any(len(c) > MAX_RECOVERY_CODE for c in codes):
        errors.append(FieldError("recovery_codes", t("loginForm.err.recoveryCodeTooLong", max=MAX_RECOVERY_CODE)))
    filled = _filled_fields(d)
    if len(filled) > MAX_CUSTOM_FIELDS:
        errors.append(FieldError("custom_fields", t("loginForm.err.maxCustomFields", max=MAX_CUSTOM_FIELDS)))
    for i, f in filled:
        name = str(f.get("name", "")).strip()
        if not name:
            errors.append(FieldError(f"custom_fields[{i}]", t("loginForm.err.fieldNeedsName")))
        elif len(name) > MAX_FIELD_NAME:
            errors.append(FieldError(f"custom_fields[{i}]", t("loginForm.err.nameTooLong", max=MAX_FIELD_NAME)))
        elif len(str(f.get("value", ""))) > MAX_FIELD_VALUE:
            errors.append(FieldError(f"custom_fields[{i}]", t("loginForm.err.valueTooLong", max=MAX_FIELD_VALUE)))
    return errors


def snapshot(d: LoginDraft) -> tuple:
    """Hashable picture of every editable value, for dirty tracking."""
    return (
        d.kind, d.entry_id, effective_label(d),
        tuple((r.url, r.match) for r in d.urls),
        d.username, d.password, d.favorite, tuple(d.tags), d.notes,
        d.totp_text, d.totp_algorithm, d.totp_digits, d.totp_period,
        tuple(d.recovery_codes),
        tuple((str(f.get("name", "")), str(f.get("value", "")), bool(f.get("hidden", True)))
              for f in d.custom_fields),
        tuple(sorted((str(k), repr(v)) for k, v in d.policy.items())),
    )


def is_dirty(d: LoginDraft, original_snapshot: tuple) -> bool:
    return snapshot(d) != original_snapshot


def password_meta(password: str, *, reuse_count: int) -> PasswordMeta:
    score = max(0, min(4, estimate_strength(password).score))
    reuse = t("loginForm.reuseNone") if reuse_count <= 0 else t("loginForm.reuseCount", count=reuse_count)
    return PasswordMeta(segments=score, label=strength_label(score), reuse_text=reuse)


def save_kwargs(d: LoginDraft) -> dict[str, Any]:
    """Keyword arguments for ``save_login`` (and ``create_web_login``).

    Exact-origin rows are reduced to their origin here; the draft keeps the
    text as typed.  Raises ``ValueError`` for a draft that does not validate.
    """
    problems = validate(d)
    if problems:
        raise ValueError(f"Login form is invalid: {problems[0].field}: {problems[0].message}")
    urls: list[dict[str, str]] | None = None
    if d.kind == "web":
        urls = [row for row, _ in (_url_error(r) for r in d.urls) if row is not None]
    return {
        "label": effective_label(d),
        "username": d.username,
        "password": d.password,
        "favorite": bool(d.favorite),
        "tags": _clean_tags(d.tags),
        "notes": d.notes,
        "totp": totp_config(d),
        "recovery_codes": [c for c in d.recovery_codes if c.strip()],
        "custom_fields": [{"name": str(f.get("name", "")).strip(), "value": str(f.get("value", "")),
                           "hidden": f.get("hidden", True) is True} for _, f in _filled_fields(d)],
        "policy": normalized_policy(d.policy),
        "urls": urls,
    }
