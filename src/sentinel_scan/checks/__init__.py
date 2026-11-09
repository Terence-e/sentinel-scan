"""Check registry. Each check is grouped by how intrusive it is."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from sentinel_scan.checks import (
    access,
    exposure,
    frontend,
    login,
    network,
    secrets,
    transport,
    urlscan,
)
from sentinel_scan.context import ScanContext, ScanOptions
from sentinel_scan.models import Finding


class Tier(Enum):
    PASSIVE = "passive"  # Only the pages a normal visitor loads.
    PROBE = "probe"  # A short, fixed list of GET requests.
    ACTIVE = "active"  # Submits invalid credentials to a login form.
    NETWORK = "network"  # Port scanning.
    THIRD_PARTY = "third-party"  # Shares the target URL with urlscan.io.


@dataclass(frozen=True)
class Check:
    name: str
    tier: Tier
    run: Callable[[ScanContext], Iterable[Finding]]


CHECKS = (
    Check("transport", Tier.PASSIVE, transport.run),
    Check("frontend", Tier.PASSIVE, frontend.run),
    Check("secrets", Tier.PASSIVE, secrets.run),
    Check("exposure", Tier.PROBE, exposure.run),
    Check("access-control", Tier.PROBE, access.run),
    Check("login", Tier.ACTIVE, login.run),
    Check("network", Tier.NETWORK, network.run),
    Check("urlscan", Tier.THIRD_PARTY, urlscan.run),
)


def select_checks(options: ScanOptions) -> list[Check]:
    tiers = {Tier.PASSIVE}
    if not options.passive_only:
        tiers.add(Tier.PROBE)
    if options.active:
        tiers.add(Tier.ACTIVE)
    if options.network:
        tiers.add(Tier.NETWORK)
    if options.urlscan:
        tiers.add(Tier.THIRD_PARTY)
    return [check for check in CHECKS if check.tier in tiers]
