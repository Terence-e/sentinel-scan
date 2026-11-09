"""End-to-end scans against a deliberately vulnerable server on localhost."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinel_scan.cli import main
from sentinel_scan.context import ScanOptions
from sentinel_scan.engine import run_scan
from sentinel_scan.http import Client
from sentinel_scan.models import Risk
from sentinel_scan.target import parse_target

ENV_SECRET = "env-value-that-must-not-leak"
JS_SECRET = "js-value-that-must-not-leak-1234"
COOKIE_SECRET = "cookie-value-that-must-not-leak"
API_EMAIL = "victim@customer.test"

HOME = (
    "<html><title>Shop</title><script src='/app.js'></script>"
    "<script src='https://cdn.other.test/x.js'></script></html>"
)
LOGIN = (
    "<title>Login</title><form method=post action=/session>"
    "<input name=user type=text><input name=pw type=password></form>"
)
PAGES = {
    "/": (200, "text/html", HOME),
    "/app.js": (200, "text/javascript", f'const SECRET_KEY="{JS_SECRET}";fetch("/api/admin/x");'),
    "/.env": (200, "text/plain", f"DB_PASSWORD={ENV_SECRET}\nAPP_ENV=prod\n"),
    "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
    "/api/users": (200, "application/json", json.dumps([{"email": API_EMAIL}])),
    "/phpmyadmin/": (200, "text/html", "<title>phpMyAdmin</title><input type=password>"),
    "/login": (200, "text/html", LOGIN),
    "/session": (200, "text/html", "<title>Login</title>Invalid credentials"),
}


class Handler(BaseHTTPRequestHandler):
    posts = 0
    catch_all = False
    paths: list[str] = []

    def _reply(self):
        Handler.paths.append(self.path)
        if self.path == "/leave":
            self.send_response(302)
            self.send_header("Location", "https://outside.test/stolen")
            self.end_headers()
            return
        default = (200, "text/html", "<title>App</title>app shell") if Handler.catch_all else None
        status, kind, body = PAGES.get(self.path, default or (404, "text/plain", "nope"))
        self.send_response(status)
        self.send_header("Content-Type", kind)
        if self.path == "/":
            self.send_header("Set-Cookie", f"session={COOKIE_SECRET}; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._reply()

    def do_POST(self):
        Handler.posts += 1
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._reply()

    def log_message(self, *_args):
        pass


@pytest.fixture
def server():
    Handler.posts = 0
    Handler.catch_all = False
    Handler.paths = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def scan(url, **options):
    target = parse_target(url)
    client = Client(target, allow_private=True, delay=0)
    return run_scan(target, client, ScanOptions(**options))


def test_detects_planted_issues(server):
    result = scan(server)
    titles = {finding.title for finding in result.findings}
    assert {
        "Site is served over plain HTTP",
        "Environment file is publicly readable",
        "Git metadata is publicly readable",
        "API returned sensitive fields without authentication",
        "Publicly reachable: phpMyAdmin",
        "Backend secret key",
        "Third-party JavaScript is loaded",
        "Admin or internal routes are visible in frontend code",
        "Cookie is missing security attributes",
    } <= titles
    assert result.overall_risk is Risk.CRITICAL
    assert not result.warnings


def test_default_scan_never_submits_forms(server):
    scan(server)
    assert Handler.posts == 0


def test_active_scan_is_capped(server, monkeypatch):
    monkeypatch.setattr("sentinel_scan.checks.login.RATE_LIMIT_DELAY_SECONDS", 0)
    result = scan(server, active=True)
    assert Handler.posts == 5
    assert "No visible login rate limiting" in {finding.title for finding in result.findings}


def test_catch_all_site_does_not_create_false_positives(server, monkeypatch):
    Handler.catch_all = True
    monkeypatch.delitem(PAGES, "/phpmyadmin/")
    monkeypatch.delitem(PAGES, "/api/users")
    monkeypatch.delitem(PAGES, "/.env")
    monkeypatch.delitem(PAGES, "/.git/HEAD")
    assert not [item for item in scan(server).findings if item.category == "Exposure"]


def test_redirects_do_not_leave_scope(server):
    target = parse_target(server)
    response = Client(target, allow_private=True, delay=0).get(f"{server}/leave")
    assert response.status == 302


def test_request_budget_is_enforced(server):
    target = parse_target(server)
    client = Client(target, allow_private=True, delay=0, max_requests=3)
    run_scan(target, client, ScanOptions())
    assert client.requests_sent == 3
    assert len(Handler.paths) == 3


def test_reports_never_contain_raw_secrets(server, tmp_path):
    code = main(
        [server, "--i-have-authorization", "--allow-private", "--delay", "0",
         "--output", str(tmp_path), "--format", "html,json,txt"]
    )
    assert code == 0
    files = list(tmp_path.iterdir())
    assert len(files) == 3
    for path in files:
        body = path.read_text(encoding="utf-8")
        for secret in (ENV_SECRET, JS_SECRET, COOKIE_SECRET, API_EMAIL):
            assert secret not in body


def test_cli_requires_authorization(server, tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert main([server, "--allow-private", "--output", str(tmp_path)]) == 2
    assert Handler.paths == []


def test_cli_fail_on_threshold(server, tmp_path):
    code = main(
        [server, "--i-have-authorization", "--allow-private", "--delay", "0",
         "--output", str(tmp_path), "--fail-on", "high"]
    )
    assert code == 1
