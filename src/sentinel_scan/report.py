"""Text, JSON and HTML reports. Everything taken from the target is treated as untrusted."""

from __future__ import annotations

import json
import os
import re
from html import escape
from pathlib import Path

from sentinel_scan.models import ScanResult

NOTICE = "Automated results can be wrong. Confirm findings before acting on them."
_COLORS = {
    "Critical": "#b3261e",
    "High": "#c2410c",
    "Medium": "#a16207",
    "Low": "#1d4ed8",
    "Info": "#475569",
}
_STYLE = """
body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:880px;padding:24px 16px;
color:#0f172a;background:#fff}
h1{font-size:1.6rem;margin:0 0 4px}.muted{color:#475569}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0}
.count{border:1px solid #cbd5e1;border-radius:6px;padding:8px 14px}
.finding{border:1px solid #cbd5e1;border-radius:8px;margin:12px 0;padding:14px 16px}
.finding h2{font-size:1.05rem;margin:0 0 4px}
.badge{border-radius:4px;color:#fff;font-size:.8rem;padding:2px 8px}
code{background:#f1f5f9;border-radius:4px;overflow-wrap:anywhere;padding:1px 4px}
"""


def render_text(result: ScanResult) -> str:
    lines = [
        "SENTINEL SCAN REPORT",
        "=" * 70,
        f"Target:        {result.target}",
        f"Finished:      {result.finished_at}",
        f"Overall risk:  {result.overall_risk.label}",
        f"Requests sent: {result.requests_sent}",
        f"Checks:        {', '.join(result.checks_run)}",
        "",
        "  ".join(f"{label}: {count}" for label, count in result.risk_counts.items()),
        "",
    ]
    for number, finding in enumerate(result.findings, start=1):
        lines += [
            f"{number}. [{finding.risk.label}] {finding.title}",
            f"   Confidence:     {finding.confidence.value}",
            f"   Location:       {finding.location}",
            f"   Evidence:       {finding.evidence}",
            f"   Why it matters: {finding.explanation}",
            f"   Fix:            {finding.recommendation}",
            "",
        ]
    if not result.findings:
        lines += ["No findings. This does not prove that the site is secure.", ""]
    if result.warnings:
        lines += ["Warnings:", *[f"- {warning}" for warning in result.warnings], ""]
    lines.append(NOTICE)
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"


def render_html(result: ScanResult) -> str:
    counts = "".join(
        f'<div class="count"><strong>{count}</strong> {escape(label)}</div>'
        for label, count in result.risk_counts.items()
    )
    findings = "".join(
        '<section class="finding">'
        f'<span class="badge" style="background:{_COLORS[item.risk.label]}">'
        f"{escape(item.risk.label)}</span>"
        f"<h2>{escape(item.title)}</h2>"
        f'<p class="muted">{escape(item.category)} · {escape(item.confidence.value)} confidence'
        f" · <code>{escape(item.location)}</code></p>"
        f"<p><strong>Evidence:</strong> <code>{escape(item.evidence)}</code></p>"
        f"<p><strong>Why it matters:</strong> {escape(item.explanation)}</p>"
        f"<p><strong>Fix:</strong> {escape(item.recommendation)}</p>"
        "</section>"
        for item in result.findings
    ) or "<p>No findings. This does not prove that the site is secure.</p>"
    warnings = "".join(f"<li>{escape(warning)}</li>" for warning in result.warnings)
    warning_block = f"<h2>Warnings</h2><ul>{warnings}</ul>" if warnings else ""
    # The CSP is a second layer: even a missed escape cannot load or run a script.
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "style-src 'unsafe-inline'\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Sentinel Scan Report</title><style>{_STYLE}</style></head><body>"
        f"<h1>Security report</h1><p class=\"muted\"><code>{escape(result.target)}</code>"
        f" · {escape(result.finished_at)} · overall risk "
        f"<strong>{escape(result.overall_risk.label)}</strong></p>"
        f'<div class="counts">{counts}</div>{findings}{warning_block}'
        f'<p class="muted">{escape(NOTICE)}</p></body></html>\n'
    )


RENDERERS = {"txt": render_text, "json": render_json, "html": render_html}


def write_reports(result: ScanResult, directory: Path, formats: list[str], host: str) -> list[Path]:
    """Write reports readable only by the current user where the OS supports it."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = re.sub(r"[^0-9T]", "", result.finished_at.split("+")[0])
    stem = re.sub(r"[^A-Za-z0-9.-]", "_", host)
    paths = []
    for extension in formats:
        path = directory / f"{stem}-{stamp}.{extension}"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(RENDERERS[extension](result))
        paths.append(path)
    return paths
