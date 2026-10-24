"""website/src/static/buy.js refuses Paddle payment links (audit 2026-10-24 M-2).

Runs buy.js in a Node ``vm`` sandbox with a fake DOM and a fake Paddle.js:
``_ptxn`` must be gone from the URL before ``Paddle.Initialize`` runs, no
checkout opens by itself, and ``checkout.completed`` for a transaction whose
``lgk_claim`` is not this page's token never shows a licence link.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUY_JS = ROOT / "website" / "src" / "static" / "buy.js"

HARNESS = r"""
const vm = require("node:vm");
const fs = require("node:fs");
const [src, href, eventClaim] = process.argv.slice(2);
const el = (extra = {}) => ({ textContent: "", hidden: true, disabled: true, href: "#", dataset: {}, listeners: {},
  addEventListener(n, f) { this.listeners[n] = f; }, ...extra });
const nodes = {
  buy: el({ dataset: { paddleToken: "test_tok", priceId: "pri_1", licenceBase: "https://licenses.example/license/" } }),
  "open-checkout": el(), "checkout-status": el(), "after-purchase": el(), "licence-link": el(),
};
const out = { initUrl: null, opens: [], replaced: null };
const location = { href, search: new URL(href).search, replace(u) { out.replaced = u; } };
const store = new Map();
let callback = null;
const window = {
  location,
  history: { state: null, replaceState(_s, _t, u) { out.replaced = u; const n = new URL(u, href); location.href = n.href; location.search = n.search; } },
  Paddle: {
    Initialize(opts) { out.initUrl = location.href; callback = opts.eventCallback; },
    Checkout: { open(opts) { out.opens.push(opts.customData.lgk_claim); } },
  },
};
const ctx = vm.createContext({
  window, document: { getElementById: (id) => nodes[id] }, crypto: globalThis.crypto, btoa, URL, URLSearchParams,
  sessionStorage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) },
});
vm.runInContext(fs.readFileSync(src, "utf8"), ctx);
const token = store.get("lgk_claim");
const claim = eventClaim === "own" ? token : eventClaim;
if (eventClaim !== "none") callback({ name: "checkout.completed", data: { custom_data: { lgk_claim: claim } } });
out.token = token;
out.linkShown = !nodes["after-purchase"].hidden;
out.link = nodes["licence-link"].href;
out.status = nodes["checkout-status"].textContent;
out.claimKept = store.has("lgk_claim");
console.log(JSON.stringify(out));
"""

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def run(tmp_path: Path, href: str, event_claim: str) -> dict:
    harness = tmp_path / "harness.cjs"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run(
        ["node", str(harness), str(BUY_JS), href, event_claim],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


def test_payment_link_is_stripped_before_paddle_initialises(tmp_path: Path) -> None:
    out = run(tmp_path, "https://localgatekeys.app/buy?_ptxn=txn_attacker&ref=x#top", "none")
    assert "_ptxn" not in out["initUrl"]
    assert out["replaced"] == "/buy?ref=x#top"
    assert out["opens"] == []  # nothing opens by itself from a sent link
    assert "Payment links are not used" in out["status"]
    assert out["linkShown"] is False


def test_plain_visit_opens_checkout_with_this_browsers_claim(tmp_path: Path) -> None:
    out = run(tmp_path, "https://localgatekeys.app/buy", "own")
    assert out["replaced"] is None
    assert len(out["token"]) == 43
    assert out["opens"] == [out["token"]]
    assert out["claimKept"] is False  # forgotten once the purchase completed
    assert out["linkShown"] is True
    assert out["link"].startswith("https://licenses.example/license/")


def test_completed_checkout_with_another_claim_shows_no_licence_link(tmp_path: Path) -> None:
    out = run(tmp_path, "https://localgatekeys.app/buy", "A" * 43)
    assert out["linkShown"] is False
    assert out["link"] == "#"
    assert out["claimKept"] is True
    assert "not for the checkout opened on this page" in out["status"]
