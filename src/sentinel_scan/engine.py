"""Runs the selected checks and collects their results."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sentinel_scan import __version__
from sentinel_scan.checks import select_checks
from sentinel_scan.context import ScanContext, ScanOptions
from sentinel_scan.http import Client
from sentinel_scan.models import Finding, ScanResult
from sentinel_scan.target import Target


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique = {(item.title, item.location, item.evidence): item for item in findings}
    return sorted(unique.values(), key=lambda item: (-item.risk, item.category, item.title))


def run_scan(
    target: Target,
    client: Client,
    options: ScanOptions,
    progress: Callable[[str], None] = lambda _message: None,
) -> ScanResult:
    context = ScanContext(target=target, client=client, options=options)
    result = ScanResult(target=target.url, tool_version=__version__, started_at=_now())
    findings: list[Finding] = []

    for check in select_checks(options):
        progress(f"Running {check.name} ({check.tier.value})")
        result.checks_run.append(check.name)
        try:
            findings.extend(check.run(context))
        except Exception as error:  # One failing check must not lose the whole report.
            context.warnings.append(f"Check '{check.name}' failed: {type(error).__name__}.")

    result.findings = _dedupe(findings)
    result.warnings = context.warnings
    result.requests_sent = client.requests_sent
    result.finished_at = _now()
    return result
