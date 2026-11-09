"""Unauthenticated GET requests to routes that normally require a login.

Reports the names of sensitive JSON fields, never their values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from sentinel_scan.context import ScanContext
from sentinel_scan.http import Response
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Access control"
API_ROUTES = (
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/admin",
    "/api/admin/users",
    "/api/customers",
    "/api/records",
)
PAGE_ROUTES = ("/dashboard", "/profile", "/account", "/settings", "/admin", "/users")
SENSITIVE_KEYS = {"password", "password_hash", "token", "api_key", "secret", "email", "phone"}
PASSWORD_FIELD = re.compile(r"type=[\"']?password", re.IGNORECASE)
ACTION = re.compile(r"<(?:button|a|form)\b[^>]*>[^<]*\b(delete|remove|edit)\b", re.IGNORECASE)
ACCOUNT_DATA = re.compile(
    r"\b(my account|sign out|log ?out|billing|user settings)\b", re.IGNORECASE
)


def sensitive_keys(value: object, found: set[str] | None = None, depth: int = 0) -> set[str]:
    found = set() if found is None else found
    if depth > 6:
        return found
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                found.add(str(key).lower())
            sensitive_keys(child, found, depth + 1)
    elif isinstance(value, list):
        for child in value[:50]:
            sensitive_keys(child, found, depth + 1)
    return found


def _check_api(ctx: ScanContext, path: str, response: Response) -> Iterator[Finding]:
    if "json" not in response.content_type:
        return
    try:
        keys = sensitive_keys(json.loads(response.text))
    except ValueError:
        return
    if keys:
        yield Finding(
            title="API returned sensitive fields without authentication",
            category=CATEGORY,
            risk=Risk.CRITICAL,
            confidence=Confidence.MEDIUM,
            evidence=f"{path} returned fields: {', '.join(sorted(keys))}. Values not recorded.",
            explanation="Personal data or credentials may be readable by anyone.",
            recommendation="Require authentication and object-level authorization on this route.",
            location=response.url,
        )


def _check_page(ctx: ScanContext, path: str, response: Response) -> Iterator[Finding]:
    if PASSWORD_FIELD.search(response.text):
        return
    account_data = ACCOUNT_DATA.search(response.text)
    action = ACTION.search(response.text)
    if account_data and action:
        yield Finding(
            title="Account page may be reachable without authentication",
            category=CATEGORY,
            risk=Risk.MEDIUM,
            confidence=Confidence.LOW,
            evidence=f"{path} returned 200 with account content and a {action.group(1)} action.",
            explanation="Based on page content only, so a person should confirm this.",
            recommendation="Open the route logged out, and enforce authentication on the server.",
            location=response.url,
        )


def run(ctx: ScanContext) -> Iterator[Finding]:
    for path, check in [
        *((route, _check_api) for route in API_ROUTES),
        *((route, _check_page) for route in PAGE_ROUTES),
    ]:
        response = ctx.client.try_get(ctx.client.url_for(path))
        if response is not None and response.status == 200 and not ctx.is_fallback_page(response):
            yield from check(ctx, path, response)
