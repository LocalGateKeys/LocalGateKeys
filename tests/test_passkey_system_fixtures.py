"""Golden pipe messages shared with the C# provider tests (windows-passkey-provider/tests/fixtures).

The C# suite checks that the provider builds exactly these requests and reads these replies; this suite checks that
the app accepts the same requests and answers with the same keys, so the two sides cannot drift apart.
"""
from __future__ import annotations

import json
from pathlib import Path

from test_passkey_system_broker import _broker

from localvault.pipe_transport import SYSTEM_PASSKEY_ACTIONS, _encode

FIXTURE = Path(__file__).resolve().parents[1] / "windows-passkey-provider" / "tests" / "fixtures" / "system-messages.json"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_covers_every_system_action() -> None:
    fixture = _fixture()
    assert set(fixture["requests"]) == set(SYSTEM_PASSKEY_ACTIONS)
    for action, request in fixture["requests"].items():
        assert request["action"] == action
        assert request["system_protocol"] == 1 and request["transaction_id"] == fixture["transaction_id"]
        assert "token" not in request


def test_frame_matches_the_provider() -> None:
    # PipeFramingTests.EncodesLikeThePythonAgent asserts the same bytes.
    assert _encode({"ok": True}) == bytes.fromhex("0000000b") + b'{"ok":true}'


def test_app_accepts_the_providers_requests_and_answers_with_its_keys(tmp_path) -> None:
    fixture = _fixture()
    requests, replies = fixture["requests"], fixture["replies"]
    broker = _broker(tmp_path)

    def send(action: str) -> dict:
        return broker.dispatch_system(json.loads(json.dumps(requests[action])), 4321)

    for action in ("passkey_create_system", "passkey_get_system", "passkey_lock_status_system",
                   "passkey_credentials_system"):
        reply = send(action)
        assert reply.get("ok") is True, (action, reply)
        assert set(reply) == set(replies[action]), action
    credentials = send("passkey_credentials_system")["credentials"]
    assert credentials and all(set(entry) == set(replies["passkey_credentials_system"]["credentials"][0])
                               for entry in credentials)
    # Last: an unknown transaction's cancel is remembered and would end a later request with the same id.
    assert send("passkey_cancel_system") == replies["passkey_cancel_system"]
    assert set(replies["error"]) == {"ok", "error"}
