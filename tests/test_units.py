import base64
import json

import pytest

from sentinel_scan.checks import Tier, select_checks
from sentinel_scan.checks.access import sensitive_keys
from sentinel_scan.checks.login import parse_login_form
from sentinel_scan.checks.network import parse_nmap_xml
from sentinel_scan.checks.secrets import mask, scan_text
from sentinel_scan.checks.transport import parse_cookie
from sentinel_scan.context import ScanOptions
from sentinel_scan.http import Client
from sentinel_scan.models import Confidence, Finding, Risk, ScanResult, clean_text
from sentinel_scan.report import render_html
from sentinel_scan.target import TargetError, ensure_allowed, parse_target


@pytest.mark.parametrize(
    "raw",
    ["ftp://example.com", "https://-oX.example.com", "--script=evil", "https://user:pw@example.com"],
)
def test_rejects_unsafe_targets(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_parses_bare_hostname_as_https():
    target = parse_target("Example.com/app/")
    assert (target.origin, target.url) == ("https://example.com", "https://example.com/app")


def test_blocks_loopback_unless_allowed():
    with pytest.raises(TargetError):
        ensure_allowed("127.0.0.1")
    ensure_allowed("127.0.0.1", allow_private=True)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/a", True),
        ("http://www.example.com/", True),
        ("https://evil.com/", False),
        ("https://example.com.evil.com/", False),
        ("https://example.com:8080/", False),
        ("file:///etc/passwd", False),
    ],
)
def test_client_scope(url, expected):
    assert Client(parse_target("https://example.com")).in_scope(url) is expected


def test_mask_never_reveals_short_values_and_limits_long_ones():
    assert mask("hunter2!") == "****(length 8)"
    long_value = "abcdefghijklmnopqrstuvwxyz"
    assert mask(long_value) == "abcd****(length 26)"


def test_scan_text_masks_value_and_skips_placeholders():
    secret = "s3cr3t-Value-that-is-long"
    found = list(scan_text(f"DB_PASSWORD={secret}\nJWT_SECRET=changeme-please", "x"))
    assert [item.risk for item in found] == [Risk.CRITICAL]
    assert secret not in found[0].evidence


def test_jwt_roles_are_classified():
    payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode()).decode()
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload.rstrip('=')}.c2lnbmF0dXJlLXZhbHVl"
    assert next(iter(scan_text(token, "x"))).risk is Risk.CRITICAL


def test_cookie_parser_discards_value_and_avoids_substring_matches():
    name, attributes = parse_cookie("session=not-secure-value; Path=/; HttpOnly")
    assert name == "session"
    assert attributes == {"path", "httponly"}


def test_sensitive_keys_returns_names_only():
    assert sensitive_keys([{"email": "a@b.c", "nested": {"token": "x"}, "id": 1}]) == {
        "email",
        "token",
    }


def test_login_form_uses_password_form_and_keeps_csrf():
    html = """
    <form action="/search"><input name="q"></form>
    <form method="post" action="/session">
      <input type="hidden" name="csrf" value="abc">
      <input type="email" name="email"><input type="password" name="pw">
    </form>"""
    form = parse_login_form("https://example.com/login", html)
    assert form.url == "https://example.com/session"
    assert form.data["csrf"] == "abc"
    assert form.data["email"].endswith("@invalid.example")


def test_login_form_refuses_get_method():
    html = '<form method="get"><input name="u"><input type="password" name="p"></form>'
    assert parse_login_form("https://example.com/login", html) is None


def test_nmap_parser_returns_only_open_ports():
    xml = """<nmaprun><host><ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/></port>
    </ports></host></nmaprun>"""
    ports = parse_nmap_xml(xml)
    assert [(port.port, port.version) for port in ports] == [(22, "OpenSSH 9.6")]


def test_nmap_parser_rejects_entity_expansion():
    with pytest.raises(Exception, match="(?i)entit"):
        parse_nmap_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>')


def test_intrusive_tiers_are_opt_in():
    default = {check.tier for check in select_checks(ScanOptions())}
    assert default == {Tier.PASSIVE, Tier.PROBE}
    passive = {check.tier for check in select_checks(ScanOptions(passive_only=True))}
    assert passive == {Tier.PASSIVE}


def test_clean_text_removes_terminal_escapes():
    assert "\x1b" not in clean_text("\x1b[31mred")


def test_html_report_escapes_target_controlled_text():
    result = ScanResult("https://example.com", "0", "now", "now")
    result.findings.append(
        Finding(
            "t", "c", Risk.LOW, Confidence.LOW, "<script>alert(1)</script>", "e", "r", "<img src=x>"
        )
    )
    html = render_html(result)
    assert "<script>" not in html
    assert "<img" not in html
