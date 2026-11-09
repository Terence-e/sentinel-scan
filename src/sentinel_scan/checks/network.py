"""Opt-in port checks using Nmap, or a small TCP connect test when Nmap is missing."""

from __future__ import annotations

import shutil
import socket

# subprocess only runs nmap, with a fixed argument list and no shell.
import subprocess  # nosec B404
from collections.abc import Iterator
from dataclasses import dataclass

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from sentinel_scan.context import ScanContext
from sentinel_scan.models import Confidence, Finding, Risk
from sentinel_scan.target import is_valid_host

CATEGORY = "Network"
NMAP_TIMEOUT_SECONDS = 300
EXPECTED_PORTS = {80, 443}
RISKY_PORTS = {
    21: (Risk.HIGH, "FTP"),
    22: (Risk.MEDIUM, "SSH"),
    23: (Risk.HIGH, "Telnet"),
    25: (Risk.LOW, "SMTP"),
    445: (Risk.HIGH, "SMB file sharing"),
    3306: (Risk.HIGH, "MySQL"),
    3389: (Risk.HIGH, "Remote Desktop"),
    5432: (Risk.HIGH, "PostgreSQL"),
    6379: (Risk.HIGH, "Redis"),
    9200: (Risk.HIGH, "Elasticsearch"),
    27017: (Risk.HIGH, "MongoDB"),
}


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str = ""
    version: str = ""


def parse_nmap_xml(xml_text: str) -> list[OpenPort]:
    """Parse Nmap XML. defusedxml is used because the output contains remote banners."""
    root = ElementTree.fromstring(xml_text)
    open_ports = []
    for port in root.iterfind("./host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        attributes = service.attrib if service is not None else {}
        open_ports.append(
            OpenPort(
                port=int(port.get("portid", "0")),
                service=attributes.get("name", ""),
                version=" ".join(
                    filter(None, (attributes.get("product"), attributes.get("version")))
                ),
            )
        )
    return open_ports


def _run_nmap(nmap: str, host: str) -> list[OpenPort]:
    if not is_valid_host(host):  # Defence in depth: the value becomes a process argument.
        raise ValueError("Refusing to pass an invalid host to Nmap.")
    command = [nmap, "-sT", "-sV", "-Pn", "--top-ports", "100", "-oX", "-", host]
    # No shell, fixed flags, and a host that passed is_valid_host().
    completed = subprocess.run(  # nosec B603
        command, capture_output=True, text=True, timeout=NMAP_TIMEOUT_SECONDS, check=False
    )
    return parse_nmap_xml(completed.stdout)


def _tcp_connect(host: str) -> list[OpenPort]:
    open_ports = []
    for port in RISKY_PORTS:
        try:
            with socket.create_connection((host, port), timeout=3):
                open_ports.append(OpenPort(port))
        except OSError:
            continue
    return open_ports


def run(ctx: ScanContext) -> Iterator[Finding]:
    host = ctx.target.host
    nmap = shutil.which("nmap")
    if nmap is None:
        ctx.warnings.append("Nmap not found, so only a small set of risky ports was tested.")
        ports = _tcp_connect(host)
    else:
        try:
            ports = _run_nmap(nmap, host)
        except (
            subprocess.TimeoutExpired,
            ElementTree.ParseError,
            DefusedXmlException,
            OSError,
        ) as error:
            ctx.warnings.append(f"Nmap did not finish: {type(error).__name__}.")
            return

    for item in ports:
        if item.port in EXPECTED_PORTS:
            continue
        risk, label = RISKY_PORTS.get(item.port, (Risk.LOW, item.service or "Unknown service"))
        detail = f"{item.port}/tcp {item.service} {item.version}".strip()
        yield Finding(
            title=f"Open port: {label}",
            category=CATEGORY,
            risk=risk,
            confidence=Confidence.HIGH,
            evidence=detail,
            explanation=f"{label} is reachable from this machine.",
            recommendation="Close the port or restrict it with a firewall or private network.",
            location=f"{host}:{item.port}",
        )
