"""Review HTML and same-site JavaScript for routes, auth logic and debug artifacts."""

from __future__ import annotations

import re
from collections.abc import Iterator

from sentinel_scan.context import ScanContext
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Frontend"
MAX_EXAMPLES = 8
ROUTE = re.compile(r"[\"'`](/[A-Za-z0-9_\-./{}:?=&%]{2,200})[\"'`]")
SOURCE_MAP = re.compile(r"sourceMappingURL=(\S+)")
ADMIN_ROUTE = re.compile(r"admin|phpmyadmin|server-status|__debug__|internal", re.IGNORECASE)
ASSET = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|mp[34]|pdf)(\?|$)", re.IGNORECASE)
CLIENT_AUTH = re.compile(
    r"\bisAdmin\b|\brole\s*[=!]==?\s*['\"]admin['\"]"
    r"|(?:local|session)Storage\.getItem\(\s*['\"](?:role|isAdmin)['\"]",
    re.IGNORECASE,
)
DEBUG_FLAG = re.compile(r"\bdebug\s*[:=]\s*true\b|\bdebugger;", re.IGNORECASE)


def _examples(items: set[str]) -> str:
    ordered = sorted(items)
    extra = f" (+{len(ordered) - MAX_EXAMPLES} more)" if len(ordered) > MAX_EXAMPLES else ""
    return ", ".join(ordered[:MAX_EXAMPLES]) + extra


def run(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.home is None:
        return

    documents = [ctx.home, *ctx.scripts]
    routes = {
        route
        for document in documents
        for route in ROUTE.findall(document.text)
        if not ASSET.search(route)
    }
    admin_routes = {route for route in routes if ADMIN_ROUTE.search(route)}
    auth_logic = {match.group(0) for doc in documents for match in CLIENT_AUTH.finditer(doc.text)}
    debug_flags = {match.group(0) for doc in documents for match in DEBUG_FLAG.finditer(doc.text)}
    source_maps = {
        script.url for script in ctx.scripts if SOURCE_MAP.search(script.text)
    } | {script.url for script in ctx.scripts if "SourceMap" in script.headers}

    if admin_routes:
        yield Finding(
            title="Admin or internal routes are visible in frontend code",
            category=CATEGORY,
            risk=Risk.LOW,
            confidence=Confidence.MEDIUM,
            evidence=_examples(admin_routes),
            explanation="Public code gives attackers a map of sensitive endpoints.",
            recommendation="Confirm that every listed route enforces server-side authorization.",
            location=ctx.home.url,
        )
    if auth_logic:
        yield Finding(
            title="Possible client-side authorization logic",
            category=CATEGORY,
            risk=Risk.MEDIUM,
            confidence=Confidence.LOW,
            evidence=_examples(auth_logic),
            explanation="Browser checks can be bypassed, so they cannot be the only control.",
            recommendation="Verify that the server enforces the same permissions.",
            location=ctx.home.url,
        )
    if debug_flags:
        yield Finding(
            title="Debug code is present in production assets",
            category=CATEGORY,
            risk=Risk.LOW,
            confidence=Confidence.MEDIUM,
            evidence=_examples(debug_flags),
            explanation="Debug paths can reveal internals or change application behaviour.",
            recommendation="Strip debug flags and statements from production builds.",
            location=ctx.home.url,
        )
    if source_maps:
        yield Finding(
            title="JavaScript references public source maps",
            category=CATEGORY,
            risk=Risk.LOW,
            confidence=Confidence.HIGH,
            evidence=_examples(source_maps),
            explanation="Source maps can reveal original source code and file structure.",
            recommendation="Do not publish source maps, or restrict them to trusted users.",
            location=ctx.home.url,
        )
    if ctx.external_scripts:
        yield Finding(
            title="Third-party JavaScript is loaded",
            category=CATEGORY,
            risk=Risk.INFO,
            confidence=Confidence.HIGH,
            evidence=_examples(set(ctx.external_scripts)),
            explanation="Third-party scripts run with full access to the page.",
            recommendation="Keep the list small and use Subresource Integrity where possible.",
            location=ctx.home.url,
        )
