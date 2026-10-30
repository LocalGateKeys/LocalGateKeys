"""localgatekeys://install-licence/ links: verified, confirmed, then installed."""
from __future__ import annotations

from urllib.parse import quote

import pytest

from localvault import agent, licence_link, licensing
from tests.test_licensing import make_bundle, signer  # noqa: F401 - fixture

PREFIX = "localgatekeys://install-licence/"


def link_for(bundle) -> str:
    return PREFIX + licensing.encode_paste(bundle)


def run(link, answer=True):
    asked, told = [], []

    def ask(text):
        asked.append(text)
        return answer

    return licence_link.handle(link, ask, told.append), asked, told


def test_find_link_picks_the_scheme_argument():
    assert licence_link.find_link(["--background", "LocalGateKeys://install-licence/LGK1-x"]) \
        == "LocalGateKeys://install-licence/LGK1-x"
    assert licence_link.find_link(["--background", "https://example.com"]) is None
    assert licence_link.find_link([]) is None


def test_confirmed_link_installs_the_licence(signer):  # noqa: F811
    done, asked, told = run(link_for(make_bundle(signer)))
    assert done and not told
    assert asked == ["Install the LocalGateKeys Pro licence for Ada Lovelace (ada@example.com) on this device?"]
    assert licensing.installed_bundle()["license"]["license_id"] == "lic-0001"


def test_declined_link_installs_nothing(signer):  # noqa: F811
    done, asked, told = run(link_for(make_bundle(signer)), answer=False)
    assert not done and asked and not told
    assert not licensing.license_path().exists()


def test_percent_encoded_and_trailing_slash_are_accepted(signer):  # noqa: F811
    key = licensing.encode_paste(make_bundle(signer))
    done, _, _ = run(PREFIX + quote(key) + "/")
    assert done


def test_replacing_another_licence_says_whose(signer):  # noqa: F811
    licensing.install_license(licensing.encode_paste(make_bundle(signer)))
    other = make_bundle(signer, license_id="lic-0002", name="Grace", email="grace@example.com")
    _, asked, _ = run(link_for(other), answer=False)
    assert "This replaces the licence for Ada Lovelace (ada@example.com)." in asked[0]
    _, again, _ = run(link_for(make_bundle(signer)), answer=False)
    assert "replaces" not in again[0]  # the same licence again


@pytest.mark.parametrize("link", [
    "localgatekeys://something-else/LGK1-abc",
    PREFIX + "not-a-key",
    PREFIX + "LGK1-" + "A" * 20_000,
    "localgatekeys:",
])
def test_bad_links_never_ask_and_install_nothing(signer, link):  # noqa: F811
    done, asked, told = run(link)
    assert not done and not asked and len(told) == 1
    assert not licensing.license_path().exists()


def test_tampered_licence_is_refused_without_asking(signer):  # noqa: F811
    bundle = make_bundle(signer)
    bundle["license"]["email"] = "mallory@example.com"
    done, asked, told = run(link_for(bundle))
    assert not done and not asked
    assert "not valid" in told[0]


def test_second_instance_with_a_link_signals_and_exits(signer, monkeypatch):  # noqa: F811
    calls = []
    monkeypatch.setattr("sys.argv", ["LocalGateKeys.exe", link_for(make_bundle(signer))])
    monkeypatch.setattr(agent, "_install_from_link", lambda link: calls.append(("install", link)) or True)
    monkeypatch.setattr(agent, "_acquire_windows_instance_mutex", lambda: None)
    monkeypatch.setattr(agent, "_tell_already_running", lambda background: calls.append("already running"))
    monkeypatch.setattr(licence_link, "signal_running_app", lambda: calls.append("signal"))
    monkeypatch.setattr("localvault.ui_assets.enable_dpi_awareness", lambda: None)
    agent.main()
    assert [c if isinstance(c, str) else c[0] for c in calls] == ["install", "signal"]


def test_second_instance_that_installed_nothing_does_not_signal(signer, monkeypatch):  # noqa: F811
    calls = []
    monkeypatch.setattr("sys.argv", ["LocalGateKeys.exe", PREFIX + "junk"])
    monkeypatch.setattr(agent, "_install_from_link", lambda link: False)
    monkeypatch.setattr(agent, "_acquire_windows_instance_mutex", lambda: None)
    monkeypatch.setattr(agent, "_tell_already_running", lambda background: calls.append("already running"))
    monkeypatch.setattr(licence_link, "signal_running_app", lambda: calls.append("signal"))
    monkeypatch.setattr("localvault.ui_assets.enable_dpi_awareness", lambda: None)
    agent.main()
    assert calls == []


def test_signal_reaches_the_watcher(monkeypatch):
    import os
    import threading
    import uuid

    if os.name != "nt":
        pytest.skip("Windows named events")
    # A running LocalGateKeys watches the real (auto-reset) event and would take the signal first.
    monkeypatch.setattr(licence_link, "EVENT_NAME", f"Local\\LocalGateKeys.Test.{uuid.uuid4().hex}")
    seen = threading.Event()
    licence_link.watch_for_installs(seen.set)
    licence_link.signal_running_app()
    assert seen.wait(5)
