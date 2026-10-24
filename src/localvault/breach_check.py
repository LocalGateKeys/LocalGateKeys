"""Explicit opt-in Pwned Passwords range query. No automatic/background requests."""
from __future__ import annotations

import hashlib
import re
import urllib.request
from collections.abc import Callable


class BreachCheckError(RuntimeError):
    pass

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BreachCheckError("Redirect refused")

def _fetch(prefix: str) -> str:
    if not re.fullmatch(r"[0-9A-F]{5}", prefix): raise BreachCheckError("Invalid hash prefix")
    request = urllib.request.Request("https://api.pwnedpasswords.com/range/" + prefix,
                                     headers={"Add-Padding": "true", "User-Agent": "LocalGateKeys/0.3.0"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=10) as response:
            if response.status != 200: raise BreachCheckError("Service unavailable")
            raw = response.read(200001)
            if len(raw) > 200000: raise BreachCheckError("Response too large")
            return raw.decode("ascii")
    except Exception:
        raise BreachCheckError("Breach check could not complete; no result is available.") from None

def check_password(password: str, *, consent: bool,
                   strict_offline: bool = False,
                   fetch: Callable[[str], str] = _fetch) -> int:
    if strict_offline:
        raise BreachCheckError("External breach checks are disabled in strict offline mode")
    if not consent: raise BreachCheckError("Explicit consent is required for an external check")
    # SHA-1 is mandated by the HIBP range API (k-anonymity prefix), not used for security.
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    response = fetch(digest[:5])
    count = 0
    valid = 0
    for line in response.splitlines():
        if not re.fullmatch(r"[0-9A-Fa-f]{35}:[0-9]+", line.strip()): continue
        valid += 1
        suffix, value = line.strip().split(":")
        if suffix.upper() == digest[5:]: count = max(count, int(value))
    if not valid: raise BreachCheckError("Invalid response; do not interpret this as not exposed")
    return count
