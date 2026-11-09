"""Known sensitive files and admin panels, using a short fixed list of GET requests."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from sentinel_scan.checks.secrets import scan_text
from sentinel_scan.context import ScanContext
from sentinel_scan.http import Response
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Exposure"
ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", re.MULTILINE)
GIT_HEAD = re.compile(r"^(ref: refs/|[0-9a-f]{40}\s*$)")
PASSWORD_INPUT = re.compile(r"<input[^>]+type=[\"']?password", re.IGNORECASE)
ENV_PATHS = ("/.env", "/.env.local", "/.env.production")
CONFIG_PATHS = ("/config.json", "/app-config.json", "/settings.json", "/config.js", "/env.js")


@dataclass(frozen=True)
class Panel:
    path: str
    name: str
    keywords: tuple[str, ...]
    risk: Risk


PANELS = (
    Panel("/admin", "Admin area", ("admin",), Risk.MEDIUM),
    Panel("/dashboard", "Dashboard", ("dashboard",), Risk.LOW),
    Panel("/wp-admin/", "WordPress admin", ("wordpress", "wp-"), Risk.MEDIUM),
    Panel("/wp-login.php", "WordPress login", ("wordpress", "wp-"), Risk.MEDIUM),
    Panel("/django-admin/", "Django admin", ("django",), Risk.MEDIUM),
    Panel("/cpanel", "cPanel", ("cpanel",), Risk.MEDIUM),
    Panel("/plesk", "Plesk", ("plesk",), Risk.MEDIUM),
    Panel("/phpmyadmin/", "phpMyAdmin", ("phpmyadmin",), Risk.HIGH),
    Panel("/pma/", "phpMyAdmin", ("phpmyadmin",), Risk.HIGH),
    Panel("/adminer.php", "Adminer", ("adminer",), Risk.HIGH),
    Panel("/adminer/", "Adminer", ("adminer",), Risk.HIGH),
    Panel("/mongo-express/", "Mongo Express", ("mongo express",), Risk.HIGH),
    Panel("/__debug__/", "Django debug toolbar", ("djdt", "debug toolbar"), Risk.HIGH),
    Panel("/silk/", "Django Silk profiler", ("silk",), Risk.HIGH),
    Panel("/swagger/", "Swagger API docs", ("swagger",), Risk.LOW),
    Panel("/api/docs/", "API docs", ("swagger", "openapi", "redoc"), Risk.LOW),
    Panel("/redoc/", "ReDoc API docs", ("redoc",), Risk.LOW),
)


def _real_page(ctx: ScanContext, response: Response | None) -> Response | None:
    if response is None or response.status != 200 or ctx.is_fallback_page(response):
        return None
    return response


def _is_html(response: Response) -> bool:
    return "html" in response.content_type or response.text.lstrip()[:1] == "<"


def _env_findings(ctx: ScanContext) -> Iterator[Finding]:
    for path in ENV_PATHS:
        response = _real_page(ctx, ctx.client.try_get(ctx.client.url_for(path)))
        if response is None or _is_html(response):
            continue
        count = len(ENV_LINE.findall(response.text))
        if count:
            yield Finding(
                title="Environment file is publicly readable",
                category=CATEGORY,
                risk=Risk.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=f"{count} variable assignment(s) found. Values were not recorded.",
                explanation="Environment files usually hold database passwords and API keys.",
                recommendation="Block dotfiles at the web server and rotate every exposed value.",
                location=response.url,
            )


def _file_findings(ctx: ScanContext) -> Iterator[Finding]:
    git = _real_page(ctx, ctx.client.try_get(ctx.client.url_for("/.git/HEAD")))
    if git is not None and GIT_HEAD.match(git.text):
        yield Finding(
            title="Git metadata is publicly readable",
            category=CATEGORY,
            risk=Risk.HIGH,
            confidence=Confidence.HIGH,
            evidence="/.git/HEAD returned valid Git content.",
            explanation="An exposed .git directory can reveal source code and history.",
            recommendation="Block /.git at the web server and do not deploy the directory.",
            location=git.url,
        )

    status_page = _real_page(ctx, ctx.client.try_get(ctx.client.url_for("/server-status")))
    if status_page is not None and "server status" in status_page.text.lower():
        yield Finding(
            title="Apache server-status is public",
            category=CATEGORY,
            risk=Risk.HIGH,
            confidence=Confidence.HIGH,
            evidence="/server-status returned a status page.",
            explanation="It exposes live requests, client addresses and internal paths.",
            recommendation="Restrict mod_status to trusted addresses.",
            location=status_page.url,
        )

    for path in CONFIG_PATHS:
        response = _real_page(ctx, ctx.client.try_get(ctx.client.url_for(path)))
        if response is not None and not _is_html(response):
            yield from scan_text(response.text, response.url)


def _panel_findings(ctx: ScanContext) -> Iterator[Finding]:
    for panel in PANELS:
        response = _real_page(ctx, ctx.client.try_get(ctx.client.url_for(panel.path)))
        if response is None:
            continue
        text = response.text.lower()
        if not any(keyword in text for keyword in panel.keywords):
            continue
        has_login = bool(PASSWORD_INPUT.search(response.text))
        state = "shows a login form" if has_login else "loaded without a login prompt"
        yield Finding(
            title=f"Publicly reachable: {panel.name}",
            category=CATEGORY,
            risk=panel.risk,
            confidence=Confidence.HIGH if has_login else Confidence.MEDIUM,
            evidence=f"{panel.path} returned 200 and {state}.",
            explanation="Public management interfaces add attack surface and attract attacks.",
            recommendation="Restrict it by IP or VPN, and require strong authentication.",
            location=response.url,
        )


def run(ctx: ScanContext) -> Iterator[Finding]:
    yield from _env_findings(ctx)
    yield from _file_findings(ctx)
    yield from _panel_findings(ctx)
