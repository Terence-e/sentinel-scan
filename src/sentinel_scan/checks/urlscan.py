"""Opt-in urlscan.io lookup. This sends the target URL to a third party."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator

import requests

from sentinel_scan.context import ScanContext
from sentinel_scan.http import USER_AGENT
from sentinel_scan.models import Confidence, Finding, Risk

SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
POLL_ATTEMPTS = 12
POLL_DELAY_SECONDS = 5
TIMEOUT_SECONDS = 15
INTERESTING = re.compile(r"admin|phpmyadmin|adminer|server-status|swagger|redoc", re.IGNORECASE)
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


def _poll(uuid: str, headers: dict[str, str]) -> dict | None:
    for _ in range(POLL_ATTEMPTS):
        time.sleep(POLL_DELAY_SECONDS)
        response = requests.get(
            RESULT_URL.format(uuid=uuid), headers=headers, timeout=TIMEOUT_SECONDS
        )
        if response.status_code == 200:
            return response.json()
        if response.status_code != 404:
            return None
    return None


def run(ctx: ScanContext) -> Iterator[Finding]:
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        ctx.warnings.append("urlscan skipped: URLSCAN_API_KEY is not set.")
        return

    headers = {"API-Key": api_key, "User-Agent": USER_AGENT}
    try:
        submission = requests.post(
            SUBMIT_URL,
            headers=headers,
            json={"url": ctx.target.url, "visibility": "private"},
            timeout=TIMEOUT_SECONDS,
        )
        submission.raise_for_status()
        uuid = str(submission.json().get("uuid", ""))
        result = _poll(uuid, headers) if UUID.fullmatch(uuid) else None
    except (requests.RequestException, ValueError) as error:
        ctx.warnings.append(f"urlscan failed: {type(error).__name__}.")
        return

    if result is None:
        ctx.warnings.append("urlscan result was not available in time.")
        return

    urls = result.get("lists", {}).get("urls", []) or []
    # Query strings can contain tokens, so they are removed before reporting.
    matches = sorted(
        {url.split("?")[0].split("#")[0] for url in urls if isinstance(url, str)}
    )
    interesting = [url for url in matches if INTERESTING.search(url)]
    if interesting:
        yield Finding(
            title="urlscan.io saw panel-like URLs",
            category="Third-party intelligence",
            risk=Risk.INFO,
            confidence=Confidence.MEDIUM,
            evidence=", ".join(interesting[:8]),
            explanation="A page load made requests to URLs that resemble management routes.",
            recommendation="Confirm that these URLs are intended to be public.",
            location=ctx.target.url,
        )
