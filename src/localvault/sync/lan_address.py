"""The address ranges a LAN sync endpoint may use.

The list is explicit rather than derived from ``ipaddress`` flags, because those
flags change between Python versions and an iPhone app has to apply the same
rule.  An IPv4-mapped IPv6 address (``::ffff:0:0/96``) is never accepted, and
neither is an IPv6 address with a zone id (``fe80::1%eth0``): the zone names an
interface of the device that wrote it and means nothing on another device.
"""
from __future__ import annotations

import ipaddress

LAN_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
        "::1/128", "fe80::/10", "fc00::/7"))


def is_lan_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when *address* lies in one of :data:`LAN_NETWORKS` and carries no IPv6 zone id."""
    if getattr(address, "scope_id", None) is not None:
        return False
    return any(address.version == net.version and address in net for net in LAN_NETWORKS)
