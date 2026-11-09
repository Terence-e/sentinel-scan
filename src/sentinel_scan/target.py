"""Target parsing and validation."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class TargetError(ValueError):
    """The target is malformed or not allowed."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int | None
    path: str

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port else host

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def url(self) -> str:
        return self.origin + (self.path or "/")

    @property
    def effective_port(self) -> int:
        return self.port or (443 if self.scheme == "https" else 80)


def is_valid_host(host: str) -> bool:
    """Accept only IP addresses and DNS names, which also rules out option-like values."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return bool(_HOSTNAME.fullmatch(host))
    return True


def parse_target(raw: str) -> Target:
    value = raw.strip()
    if not value:
        raise TargetError("No target was provided.")
    if "://" not in value:
        value = f"https://{value}"

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise TargetError(f"Invalid target URL: {error}") from error

    if parts.scheme.lower() not in {"http", "https"}:
        raise TargetError("Only http:// and https:// targets are supported.")
    if parts.username or parts.password:
        raise TargetError("Do not put credentials in the target URL.")

    host = (parts.hostname or "").lower().rstrip(".")
    if not is_valid_host(host):
        raise TargetError(f"Invalid hostname: {host or '(empty)'}")

    return Target(parts.scheme.lower(), host, port, parts.path.rstrip("/"))


def resolve_addresses(host: str) -> list[str]:
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as error:
        raise TargetError(f"Could not resolve host: {host}") from error
    return sorted({str(record[4][0]) for record in records})


def ensure_allowed(host: str, allow_private: bool = False) -> None:
    """Refuse hosts that resolve to private, loopback or link-local addresses by default."""
    addresses = resolve_addresses(host)
    if allow_private:
        return
    blocked = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if blocked:
        raise TargetError(
            f"{host} resolves to a non-public address ({blocked[0]}). "
            "Use --allow-private only for systems you are authorized to test."
        )
