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
        "require_master_password": raw.get("require_master_password", False) is True,
        "save_prompts": raw.get("save_prompts", True) is True,
    }


def may_sign_in(entry: dict[str, Any], profile_enabled: bool) -> bool:
    policy = normalized_policy(entry.get("policy"))
    return policy["fill"] == "click" and (
        policy["sign_in"] == "enabled"
        or (policy["sign_in"] == "inherit" and profile_enabled is True)
    )
