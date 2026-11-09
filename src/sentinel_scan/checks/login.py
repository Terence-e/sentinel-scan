"""Opt-in login checks. Uses random invalid credentials, never real or guessed ones."""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from sentinel_scan.context import ScanContext
from sentinel_scan.http import FetchError, Response
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Authentication"
LOGIN_PATHS = ("/login", "/signin", "/admin/login", "/accounts/login", "/wp-login.php")
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_DELAY_SECONDS = 1.0
RATE_LIMIT_SIGNALS = (
    "too many attempts",
    "too many requests",
    "try again later",
    "temporarily locked",
    "account locked",
    "captcha",
    "rate limit",
)


@dataclass(frozen=True)
class LoginForm:
    url: str
    data: dict[str, str]


def parse_login_form(page_url: str, html: str) -> LoginForm | None:
    """Parse the POST form that holds a password field and fill it with invalid credentials."""
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if str(form.get("method", "get")).lower() != "post":
            continue  # A GET form would put even fake credentials into server logs.

        data: dict[str, str] = {}
        username = password = None
        for field in form.find_all("input"):
            name = field.get("name")
            if not name:
                continue
            kind = str(field.get("type", "text")).lower()
            data[name] = str(field.get("value", ""))
            if kind == "password":
                password = name
            elif kind in {"text", "email"} and username is None:
                username = name

        if password and username:
            token = secrets.token_hex(12)
            data[username] = f"sentinel-invalid-{token}@invalid.example"
            data[password] = token
            return LoginForm(urljoin(page_url, str(form.get("action") or page_url)), data)
    return None


def _find_form(ctx: ScanContext) -> LoginForm | None:
    for path in LOGIN_PATHS:
        response = ctx.client.try_get(ctx.client.url_for(path))
        if response is None or response.status != 200 or ctx.is_fallback_page(response):
            continue
        form = parse_login_form(response.url, response.text)
        if form is not None:
            return form
    return None


def is_rate_limited(response: Response) -> bool:
    text = response.text.lower()
    return response.status == 429 or any(signal in text for signal in RATE_LIMIT_SIGNALS)


def looks_logged_in(response: Response) -> bool:
    text = response.text.lower()
    has_session_ui = "logout" in text or "log out" in text or "sign out" in text
    return response.status == 200 and has_session_ui and 'type="password"' not in text


def run(ctx: ScanContext) -> Iterator[Finding]:
    form = _find_form(ctx)
    if form is None:
        return

    limited = False
    for attempt in range(RATE_LIMIT_ATTEMPTS):
        if attempt:
            time.sleep(RATE_LIMIT_DELAY_SECONDS)
        try:
            response = ctx.client.post(form.url, form.data)
        except FetchError as error:
            ctx.warnings.append(f"Login check stopped: {error}")
            return

        if attempt == 0 and looks_logged_in(response):
            yield Finding(
                title="Login may accept invalid credentials",
                category=CATEGORY,
                risk=Risk.HIGH,
                confidence=Confidence.LOW,
                evidence="Random invalid credentials produced a page with a logout control.",
                explanation="If this is confirmed, authentication can be bypassed entirely.",
                recommendation="Reproduce by hand, then fix credential validation on the server.",
                location=form.url,
            )
            return
        if is_rate_limited(response):
            limited = True
            break

    if not limited:
        yield Finding(
            title="No visible login rate limiting",
            category=CATEGORY,
            risk=Risk.MEDIUM,
            confidence=Confidence.LOW,
            evidence=f"{RATE_LIMIT_ATTEMPTS} invalid attempts showed no throttling or lockout.",
            explanation="Limits may simply start later, but none showed up in this small test.",
            recommendation="Throttle failed logins per account and per IP address.",
            location=form.url,
        )
