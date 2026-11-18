"""Conservative credential release and sign-in policy; no UI/network side effects."""
from __future__ import annotations

import re
from typing import Any

# Intentionally narrow. Unknown/localized labels require manual sign-in rather
# than a broad 'Continue', 'Confirm', or 'Submit' that could authorize a purchase.
SIGN_IN_LABELS = frozenset({"sign in", "signin", "log in", "login", "log on", "zaloguj", "zaloguj się"})


def is_sign_in_label(value: str) -> bool:
    text = re.sub(r"\s+", " ", str(value).replace("&", "")).strip().casefold()
    return text in SIGN_IN_LABELS


def normalized_policy(raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    fill = raw.get("fill", "click")
    signin = raw.get("sign_in", "inherit")
    return {
        "fill": fill if fill in ("click", "never") else "never",
        "sign_in": signin if signin in ("inherit", "never", "enabled") else "never",
        # "Unknown = strictest" (A-L1): absent means off; a present value other than exactly ``false``
        # (``true``, ``null``, ``"yes"``, ``0``, ``{}``, ...) means on, and is written back as ``true``.
        "require_master_password": raw.get("require_master_password", False) is not False,
        "save_prompts": raw.get("save_prompts", True) is True,
    }


def may_sign_in(entry: dict[str, Any], profile_enabled: bool) -> bool:
    policy = enforced_policy(entry)
    return policy["fill"] == "click" and (
        policy["sign_in"] == "enabled"
        or (policy["sign_in"] == "inherit" and profile_enabled is True)
    )


# --- Per-login access rules (feature pack 2026-11-15, contract section 4) ---------------------
#
# Stored under the login's scope as ``scope.access`` (synced; every shipped build keeps unknown
# scope keys).  Only non-default keys are written.  Reading is "unknown = strictest": an access
# value that is not an object, or that holds a key this build does not know, turns every rule on.

ACCESS_SCOPE_KEY = "access"
ACCESS_KEYS = ("copy", "phones", "expires")
_ACCESS_DEFAULTS = {"copy": "normal", "phones": "full", "expires": ""}
DEVICE_COMPUTER = "computer"
DEVICE_PHONE = "phone"


def valid_iso_date(value: Any) -> bool:
    """A real calendar date written ``YYYY-MM-DD`` (dash form only), year 1 or later."""
    import datetime as _dt

    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        return False
    try:
        return _dt.date.fromisoformat(value).year >= 1
    except ValueError:
        return False


def access_of(record: Any) -> Any:
    """The raw ``scope.access`` value of a login (``None`` when absent)."""
    scope = record.get("scope") if isinstance(record, dict) else None
    if not isinstance(scope, dict) or ACCESS_SCOPE_KEY not in scope:
        return None
    return scope[ACCESS_SCOPE_KEY]


def access_unknown(access: Any) -> bool:
    """True when ``access`` comes from a newer version (not an object, or an unknown key)."""
    if access is None:
        return False
    return not isinstance(access, dict) or any(key not in ACCESS_KEYS for key in access)


def effective(record: Any, device_class: str, today: str) -> dict[str, bool]:
    """The rules that apply to ``record`` on this device (contract 4.2).

    ``today`` is the device's local date ``YYYY-MM-DD``.  Returns
    ``{reauth, autofill, copy_once, phone_view, expired}``.
    """
    policy = normalized_policy(record.get("policy") if isinstance(record, dict) else None)
    access = access_of(record)
    if access_unknown(access):
        return {"reauth": True, "autofill": False, "copy_once": True, "phone_view": True, "expired": False}
    access = access or {}
    copy_once = access.get("copy", "normal") != "normal"
    phone_view = access.get("phones", "full") != "full"
    expires = access.get("expires", "")
    if expires == "":
        expired = False
    elif valid_iso_date(expires):
        expired = str(today) >= expires
    else:
        expired = True
    reauth = policy["require_master_password"] or expired
    autofill = (policy["fill"] == "click" and not expired
                and not (phone_view and device_class == DEVICE_PHONE))
    return {"reauth": reauth, "autofill": autofill, "copy_once": copy_once,
            "phone_view": phone_view, "expired": expired}


def has_rule(record: Any, today: str) -> bool:
    """True when any access rule or strict policy applies to this login on a computer."""
    rules = effective(record, DEVICE_COMPUTER, today)
    return (rules["reauth"] or not rules["autofill"] or rules["copy_once"] or rules["phone_view"]
            or access_unknown(access_of(record)))


def stricter_access(a: Any, b: Any) -> Any:
    """Merge two ``scope.access`` values keeping the stricter rule per key (contract 4.2).

    ``None`` means absent.  A value from a newer version (not an object) wins as is, so the merge
    never loosens it; unknown keys are kept (the first value wins on a clash).  Returns ``None``
    when nothing is left.
    """
    if a is not None and not isinstance(a, dict):
        return a
    if b is not None and not isinstance(b, dict):
        return b
    a = a or {}
    b = b or {}
    out: dict[str, Any] = {}
    for key in ("copy", "phones"):
        default = _ACCESS_DEFAULTS[key]
        left, right = a.get(key, default), b.get(key, default)
        if left != default:
            out[key] = left
        elif right != default:
            out[key] = right
    left, right = a.get("expires", ""), b.get("expires", "")
    if left == "" or right == "":
        chosen = left if right == "" else right
    elif not valid_iso_date(left):
        chosen = left
    elif not valid_iso_date(right):
        chosen = right
    else:
        chosen = min(left, right)
    if chosen != "":
        out["expires"] = chosen
    for source in (a, b):
        for key, value in source.items():
            if key not in ACCESS_KEYS and key not in out:
                out[key] = value
    return out or None


def stricter_policy(a: Any, b: Any) -> Any:
    """Keeper policy ``a`` tightened by ``b``: ``fill: never`` and ``require_master_password`` win."""
    if not isinstance(a, dict) and not isinstance(b, dict):
        return None
    out = dict(a) if isinstance(a, dict) else {}
    if "require_master_password" in out and out["require_master_password"] is not False:
        out["require_master_password"] = True  # a non-boolean value is strict (A-L1): keep it, as a bool
    other = normalized_policy(b) if isinstance(b, dict) else None
    if other is not None:
        if other["fill"] == "never":
            out["fill"] = "never"
        if other["require_master_password"]:
            out["require_master_password"] = True
    return out if (isinstance(a, dict) or out) else None


def clean_access(access: dict[str, Any]) -> dict[str, Any] | None:
    """The write form of an access value set by this build: only non-default known keys.

    Raises ``ValueError`` for an unsupported value.  ``None`` when empty (the key is removed).
    """
    out: dict[str, Any] = {}
    copy = access.get("copy", "normal")
    phones = access.get("phones", "full")
    expires = access.get("expires", "")
    if copy not in ("normal", "once") or phones not in ("full", "view"):
        raise ValueError("access rule is not supported")
    if expires not in ("", None) and not valid_iso_date(expires):
        raise ValueError("access date must be YYYY-MM-DD")
    if copy != "normal":
        out["copy"] = copy
    if phones != "full":
        out["phones"] = phones
    if expires:
        out["expires"] = expires
    return out or None


def tightens(old: Any, new: Any) -> bool:
    """True when access value ``new`` (write form or None) is stricter anywhere than ``old``."""
    if access_unknown(old):
        # Replacing a newer-version value by a known one is never a tightening.
        return False
    old = old or {}
    new = new or {}
    if new.get("copy", "normal") != "normal" and old.get("copy", "normal") == "normal":
        return True
    if new.get("phones", "full") != "full" and old.get("phones", "full") == "full":
        return True
    new_exp, old_exp = new.get("expires", ""), old.get("expires", "")
    return bool(new_exp) and (not old_exp or new_exp < old_exp)


def local_today() -> str:
    import datetime as _dt

    return _dt.date.today().isoformat()


def enforced_policy(record: Any, today: str | None = None) -> dict[str, Any]:
    """``normalized_policy`` of a login tightened by its access rules on this computer.

    Every Windows release point (browser fill, auto-type, CLI/MCP, copy) reads this instead of the
    raw policy, so an expired or newer-version rule can never be looser than the stored policy.
    """
    record = record if isinstance(record, dict) else {}
    policy = normalized_policy(record.get("policy"))
    rules = effective(record, DEVICE_COMPUTER, today or local_today())
    if not rules["autofill"]:
        policy["fill"] = "never"
        policy["sign_in"] = "never"
    if rules["reauth"]:
        policy["require_master_password"] = True
    policy["copy_once"] = rules["copy_once"]
    policy["expired"] = rules["expired"]
    return policy
