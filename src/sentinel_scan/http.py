"""HTTP client that enforces scope, request budget, throttling and response size."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

from sentinel_scan import __version__
from sentinel_scan.target import Target, TargetError, ensure_allowed

USER_AGENT = f"sentinel-scan/{__version__} (authorized security assessment)"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5


class FetchError(Exception):
    def __init__(self, message: str, kind: str = "network") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass
class Response:
    url: str
    status: int
    headers: Mapping[str, str]
    text: str
    set_cookies: list[str] = field(default_factory=list)
    redirected: bool = False

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").lower()


class Client:
    def __init__(
        self,
        target: Target,
        *,
        allow_private: bool = False,
        timeout: float = 8.0,
        delay: float = 0.2,
        max_requests: int = 300,
        max_bytes: int = 1_000_000,
    ) -> None:
        self.target = target
        self.allow_private = allow_private
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests_sent = 0
        self._checked_hosts: set[str] = set()
        self._session = requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT

    def url_for(self, path: str) -> str:
        return urljoin(self.target.origin + "/", path.lstrip("/"))

    def in_scope(self, url: str) -> bool:
        """Allow the target host and its www twin, on the target or default web ports."""
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return False
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return False

        def bare(name: str) -> str:
            return name.lower().removeprefix("www.")

        if bare(parts.hostname) != bare(self.target.host):
            return False
        return port in {None, 80, 443, self.target.effective_port}

    def get(self, url: str, *, follow: bool = True) -> Response:
        return self._send("GET", url, None, follow)

    def post(self, url: str, data: Mapping[str, str]) -> Response:
        return self._send("POST", url, data, True)

    def try_get(self, url: str, *, follow: bool = True) -> Response | None:
        try:
            return self.get(url, follow=follow)
        except FetchError:
            return None

    def _send(
        self, method: str, url: str, data: Mapping[str, str] | None, follow: bool
    ) -> Response:
        current_method, current_url, current_data = method, url, data

        for hop in range(MAX_REDIRECTS + 1):
            response = self._send_once(current_method, current_url, current_data)
            response.redirected = hop > 0
            location = response.headers.get("Location")
            if not (follow and response.status in REDIRECT_STATUSES and location):
                return response

            next_url = urljoin(response.url, location)
            if not self.in_scope(next_url):
                return response
            if response.status in {301, 302, 303}:
                current_method, current_data = "GET", None
            current_url = next_url

        raise FetchError("Too many redirects.", "redirects")

    def _send_once(self, method: str, url: str, data: Mapping[str, str] | None) -> Response:
        if not self.in_scope(url):
            raise FetchError(f"Refusing out-of-scope request: {url}", "scope")
        if self.requests_sent >= self.max_requests:
            raise FetchError("Request budget exhausted.", "budget")

        self._guard_host(urlsplit(url).hostname or "")
        if self.requests_sent and self.delay:
            time.sleep(self.delay)
        self.requests_sent += 1

        try:
            with self._session.request(
                method,
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as raw:
                body = self._read_limited(raw)
                encoding = raw.encoding or "utf-8"
                return Response(
                    url=url,
                    status=raw.status_code,
                    headers=raw.headers,
                    text=body.decode(encoding, errors="replace"),
                    set_cookies=list(raw.raw.headers.getlist("Set-Cookie")),
                )
        except LookupError as error:
            raise FetchError("Response used an unknown text encoding.") from error
        except requests.exceptions.SSLError as error:
            raise FetchError("TLS certificate verification failed.", "tls") from error
        except requests.exceptions.Timeout as error:
            raise FetchError("Request timed out.", "timeout") from error
        except requests.exceptions.RequestException as error:
            raise FetchError(f"Request failed: {type(error).__name__}.") from error

    def _read_limited(self, raw: requests.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        for chunk in raw.iter_content(chunk_size=65_536):
            chunks.append(chunk)
            size += len(chunk)
            if size >= self.max_bytes:
                break
        return b"".join(chunks)[: self.max_bytes]

    def _guard_host(self, host: str) -> None:
        if host in self._checked_hosts:
            return
        try:
            ensure_allowed(host, self.allow_private)
        except TargetError as error:
            raise FetchError(str(error), "scope") from error
        self._checked_hosts.add(host)
