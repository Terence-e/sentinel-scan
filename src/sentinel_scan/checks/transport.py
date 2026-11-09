"""HTTPS, security headers and cookie flags."""

from __future__ import annotations

import re
from collections.abc import Iterator

from sentinel_scan.context import ScanContext
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Transport and headers"
SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login", re.IGNORECASE)

HEADERS = (
    (
        "Content-Security-Policy",
        Risk.MEDIUM,
        "Without a CSP, an injected script runs with few restrictions.",
        "Add a Content-Security-Policy, starting in report-only mode.",
    ),
    (
        "Strict-Transport-Security",
        Risk.MEDIUM,
        "Without HSTS, a first visit can be downgraded to plain HTTP.",
        "Send Strict-Transport-Security once HTTPS works across the whole site.",
    ),
    (
        "X-Frame-Options",
        Risk.LOW,
        "The page may be framed by another site, which enables clickjacking.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors rule.",
    ),
    (
        "X-Content-Type-Options",
        Risk.LOW,
        "Browsers may guess content types and run a file as something else.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    (
        "Referrer-Policy",
        Risk.LOW,
        "Full URLs may leak to other sites through the Referer header.",
        "Set Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    (
        "Permissions-Policy",
        Risk.INFO,
        "Browser features are not explicitly restricted.",
        "Disable features the site does not use with Permissions-Policy.",
    ),
)


def parse_cookie(header: str) -> tuple[str, set[str]]:
    """Return a cookie's name and lower-cased attribute names. The value is discarded."""
    first, *attributes = header.split(";")
    names = {attribute.split("=", 1)[0].strip().lower() for attribute in attributes}
    return first.split("=", 1)[0].strip(), names


def _cookie_findings(ctx: ScanContext, cookies: list[str], https: bool) -> Iterator[Finding]:
    for header in cookies:
        name, attributes = parse_cookie(header)
        missing = [
            flag
            for flag, attribute, applies in (
                ("Secure", "secure", https),
                ("HttpOnly", "httponly", True),
                ("SameSite", "samesite", True),
            )
            if applies and attribute not in attributes
        ]
        if missing:
            yield Finding(
                title="Cookie is missing security attributes",
                category=CATEGORY,
                risk=Risk.MEDIUM if SESSION_COOKIE.search(name) else Risk.LOW,
                confidence=Confidence.HIGH,
                evidence=f"{name}: missing {', '.join(missing)}",
                explanation="Missing attributes make cookies easier to steal or misuse.",
                recommendation="Set Secure, HttpOnly and SameSite on session cookies.",
                location=ctx.target.url,
            )


def run(ctx: ScanContext) -> Iterator[Finding]:
    home = ctx.home
    if home is None:
        error = ctx.home_error
        if error is not None and error.kind == "tls":
            yield Finding(
                title="TLS certificate could not be verified",
                category=CATEGORY,
                risk=Risk.HIGH,
                confidence=Confidence.HIGH,
                evidence=str(error),
                explanation="Visitors see warnings and connections can be intercepted.",
                recommendation="Install a valid certificate with the full chain.",
                location=ctx.target.url,
            )
        else:
            ctx.warnings.append(f"Homepage could not be fetched: {error}")
        return

    https = home.url.startswith("https://")
    if not https:
        yield Finding(
            title="Site is served over plain HTTP",
            category=CATEGORY,
            risk=Risk.HIGH,
            confidence=Confidence.HIGH,
            evidence=f"Final URL: {home.url}",
            explanation="Traffic, including any credentials, can be read or altered in transit.",
            recommendation="Serve the site over HTTPS and redirect all HTTP traffic to it.",
            location=home.url,
        )
    elif ctx.target.port is None:
        plain = ctx.client.try_get(f"http://{ctx.target.netloc}/", follow=False)
        if plain is not None and plain.status == 200:
            yield Finding(
                title="HTTP is not redirected to HTTPS",
                category=CATEGORY,
                risk=Risk.MEDIUM,
                confidence=Confidence.HIGH,
                evidence="http:// returned 200 without a redirect.",
                explanation="Visitors who arrive over HTTP stay on an unencrypted connection.",
                recommendation="Redirect all HTTP requests to HTTPS with a 301.",
                location=plain.url,
            )

    for name, risk, explanation, recommendation in HEADERS:
        if name == "Strict-Transport-Security" and not https:
            continue
        if name not in home.headers:
            yield Finding(
                title=f"Missing security header: {name}",
                category=CATEGORY,
                risk=risk,
                confidence=Confidence.HIGH,
                evidence=f"{name} is absent from the response.",
                explanation=explanation,
                recommendation=recommendation,
                location=home.url,
            )

    yield from _cookie_findings(ctx, home.set_cookies, https)
