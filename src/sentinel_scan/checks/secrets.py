"""Detect credentials in public content. Reports only ever contain masked values."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator

from sentinel_scan.context import ScanContext
from sentinel_scan.models import Confidence, Finding, Risk

CATEGORY = "Secrets"
RECOMMENDATION = "Remove it from public content, rotate it, and keep it on the server side."
PLACEHOLDERS = ("example", "placeholder", "your_", "your-", "changeme", "xxxx", "process.env")
_NAMED_VALUE = r"\b({names})\b[\"']?\s*[:=]\s*[\"']?([^\"'\s;,`]+)"


def _named(names: str) -> re.Pattern[str]:
    return re.compile(_NAMED_VALUE.format(names=names), re.IGNORECASE)


PATTERNS = (
    (
        "Database password",
        Risk.CRITICAL,
        _named("DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD"),
    ),
    ("Database connection string", Risk.CRITICAL, _named("DATABASE_URL|POSTGRES_URL|MYSQL_URL")),
    ("Backend secret key", Risk.CRITICAL, _named("SECRET_KEY|JWT_SECRET|APP_SECRET|CLIENT_SECRET")),
    ("API key or token", Risk.MEDIUM, _named("API_KEY|ACCESS_TOKEN|AUTH_TOKEN|BEARER_TOKEN")),
    ("AWS access key ID", Risk.HIGH, re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("GitHub token", Risk.CRITICAL, re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("Stripe live secret key", Risk.CRITICAL, re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b")),
    ("Slack token", Risk.CRITICAL, re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{20,})\b")),
    ("Supabase secret key", Risk.CRITICAL, re.compile(r"\b(sb_secret_[A-Za-z0-9_-]{20,})\b")),
    ("Supabase publishable key", Risk.INFO, re.compile(r"\b(sb_publishable_[A-Za-z0-9_-]{20,})\b")),
)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


def mask(value: str) -> str:
    """Show just enough to find the value: at most four characters and its length."""
    prefix = value[:4] if len(value) >= 16 else ""
    return f"{prefix}****(length {len(value)})"


def _jwt_claims(token: str) -> dict[str, object]:
    try:
        payload = token.split(".")[1]
        data = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(data)
    except (IndexError, ValueError, binascii.Error):
        return {}
    return claims if isinstance(claims, dict) else {}


def _finding(title: str, risk: Risk, evidence: str, location: str, why: str) -> Finding:
    return Finding(
        title=title,
        category=CATEGORY,
        risk=risk,
        confidence=Confidence.MEDIUM,
        evidence=evidence,
        explanation=why,
        recommendation=RECOMMENDATION,
        location=location,
    )


def scan_text(text: str, location: str) -> Iterator[Finding]:
    if PRIVATE_KEY.search(text):
        yield _finding(
            "Private key",
            Risk.CRITICAL,
            "A PEM private key header was found.",
            location,
            "Anyone holding a private key can impersonate its owner.",
        )

    for title, risk, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(match.lastindex or 1)
            if len(value) < 8 or any(mark in value.lower() for mark in PLACEHOLDERS):
                continue
            label = f"{match.group(1)}=" if (match.lastindex or 1) > 1 else ""
            yield _finding(
                title,
                risk,
                f"{label}{mask(value)}",
                location,
                "This value looks like a credential served to anyone who requests the page.",
            )

    for token in set(JWT.findall(text)):
        claims = _jwt_claims(token)
        role = str(claims.get("role", "")).lower()
        if role == "service_role":
            yield _finding(
                "Supabase service_role JWT",
                Risk.CRITICAL,
                mask(token),
                location,
                "A service_role key bypasses Row Level Security.",
            )
        elif role == "anon":
            yield _finding(
                "Supabase anon JWT",
                Risk.INFO,
                mask(token),
                location,
                "Anon keys are designed to be public, but safety depends on your RLS policies.",
            )
        else:
            yield _finding(
                "JWT in public content",
                Risk.LOW,
                mask(token),
                location,
                "A hardcoded token may be harmless, but it should be reviewed.",
            )


def run(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.home is not None:
        yield from scan_text(ctx.home.text, ctx.home.url)
    for script in ctx.scripts:
        yield from scan_text(script.text, script.url)
