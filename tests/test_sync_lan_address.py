"""The explicit LAN address ranges shared by pairing and the transport."""
from __future__ import annotations

import importlib.util
import ipaddress
import sys
from pathlib import Path

import pytest

from localvault.sync.lan_address import LAN_NETWORKS, is_lan_address

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_sync_vectors.py"


def _cases() -> list[tuple[str, bool]]:
    """The documented table; it lives in the vector generator, which writes it to lan_ranges.json."""
    module = sys.modules.get("make_sync_vectors")
    if module is None:
        spec = importlib.util.spec_from_file_location("make_sync_vectors", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules["make_sync_vectors"] = module
        spec.loader.exec_module(module)
    return list(module.LAN_RANGE_CASES)


LAN_RANGE_CASES = _cases()


@pytest.mark.parametrize("text,ok", LAN_RANGE_CASES)
def test_lan_address_table(text, ok):
    assert is_lan_address(ipaddress.ip_address(text)) is ok


def test_table_covers_the_documented_edges():
    table = dict(LAN_RANGE_CASES)
    for text, ok in (("::ffff:192.168.1.1", False), ("0.0.0.0", False), ("::", False),  # noqa: S104
                     ("fe80::1", True), ("fe80::1%eth0", False), ("fe80::1%1", False)):
        assert table[text] is ok, text


def test_lan_networks_are_the_documented_list():
    assert [str(n) for n in LAN_NETWORKS] == [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
        "::1/128", "fe80::/10", "fc00::/7"]


@pytest.mark.parametrize("host,ok", [("192.168.1.20", True), ("::1", True), ("fe80::1", True), ("100.64.0.1", False),
                                     ("0.0.0.0", False), ("::ffff:192.168.1.1", False),  # noqa: S104
                                     ("fe80::1%eth0", False), ("fe80::1%1", False)])
def test_endpoints_follow_the_table(host, ok):
    from localvault.sync import pairing
    from localvault.sync.transport import LANEndpoint, TransportError

    if ok:
        assert LANEndpoint(host, 4000).host == host
        assert pairing._private_lan_endpoint(host, 4000) == (host, 4000)
    else:
        with pytest.raises(TransportError, match="private address"):
            LANEndpoint(host, 4000)
        with pytest.raises(pairing.PairingError, match="private LAN address"):
            pairing._private_lan_endpoint(host, 4000)
