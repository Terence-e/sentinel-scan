"""State shared between checks during one scan."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from functools import cached_property
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from sentinel_scan.http import Client, FetchError, Response
from sentinel_scan.target import Target

MAX_SCRIPTS = 15
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class ScanOptions:
    passive_only: bool = False
    active: bool = False
    network: bool = False
    urlscan: bool = False


def _title(text: str) -> str:
    match = _TITLE.search(text)
    return match.group(1).strip().lower() if match else ""


@dataclass
class ScanContext:
    target: Target
    client: Client
    options: ScanOptions = field(default_factory=ScanOptions)
    warnings: list[str] = field(default_factory=list)
    home_error: FetchError | None = None

    @cached_property
    def home(self) -> Response | None:
        try:
            return self.client.get(self.target.url)
        except FetchError as error:
            self.home_error = error
            return None

    @cached_property
    def fallback(self) -> Response | None:
        """Fetch a random path, to spot sites that answer 200 for every URL."""
        response = self.client.try_get(self.client.url_for(f"/sentinel-{secrets.token_hex(8)}"))
        return response if response and response.status == 200 else None

    def is_fallback_page(self, response: Response) -> bool:
        baseline = self.fallback
        if baseline is None or response.status != 200:
            return False
        if _title(baseline.text) != _title(response.text):
            return False
        longest = max(len(baseline.text), len(response.text), 1)
        return abs(len(baseline.text) - len(response.text)) / longest <= 0.05

    @cached_property
    def script_urls(self) -> list[str]:
        if self.home is None:
            return []
        soup = BeautifulSoup(self.home.text, "html.parser")
        urls = [urljoin(self.home.url, tag["src"]) for tag in soup.find_all("script", src=True)]
        return list(dict.fromkeys(urls))

    @cached_property
    def external_scripts(self) -> list[str]:
        return [url for url in self.script_urls if not self.client.in_scope(url)]

    @cached_property
    def scripts(self) -> list[Response]:
        """Same-site scripts loaded by the homepage, capped to keep traffic small."""
        fetched = []
        for url in [url for url in self.script_urls if self.client.in_scope(url)][:MAX_SCRIPTS]:
            response = self.client.try_get(url)
            if response and response.status == 200:
                fetched.append(response)
        return fetched
