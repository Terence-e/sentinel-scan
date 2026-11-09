"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel_scan import __version__
from sentinel_scan.context import ScanOptions
from sentinel_scan.engine import run_scan
from sentinel_scan.http import Client
from sentinel_scan.models import Risk
from sentinel_scan.report import RENDERERS, write_reports
from sentinel_scan.target import TargetError, ensure_allowed, parse_target

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-scan",
        description="Defensive website security scanner. Scan only systems you may test.",
    )
    parser.add_argument("target", help="URL or hostname to scan")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )
    tiers = parser.add_argument_group("scan scope")
    tiers.add_argument(
        "--passive-only", action="store_true", help="fetch only the homepage and its scripts"
    )
    tiers.add_argument(
        "--active", action="store_true", help="submit invalid credentials to login forms"
    )
    tiers.add_argument("--network", action="store_true", help="run a port scan")
    tiers.add_argument(
        "--urlscan", action="store_true", help="send the target URL to urlscan.io (needs API key)"
    )
    tiers.add_argument(
        "--allow-private", action="store_true", help="allow private and loopback addresses"
    )
    limits = parser.add_argument_group("limits")
    limits.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    limits.add_argument("--timeout", type=float, default=8.0, help="request timeout in seconds")
    limits.add_argument("--max-requests", type=int, default=300, help="total request budget")
    output = parser.add_argument_group("output")
    output.add_argument("--output", type=Path, default=Path("reports"), help="report directory")
    output.add_argument(
        "--format",
        default="html,json",
        help=f"comma-separated formats from: {', '.join(RENDERERS)}",
    )
    output.add_argument(
        "--fail-on",
        choices=[risk.name.lower() for risk in Risk],
        help="exit with status 1 if any finding reaches this risk",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _confirmed(args: argparse.Namespace, url: str) -> bool:
    if args.i_have_authorization:
        return True
    if not sys.stdin.isatty():
        return False
    print(f"Target: {url}")
    answer = input("Do you own this target or have written permission to test it? [yes/no] ")
    return answer.strip().lower() == "yes"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    formats = [item.strip() for item in args.format.split(",") if item.strip()]
    if not formats or any(item not in RENDERERS for item in formats):
        parser.error(f"--format must use: {', '.join(RENDERERS)}")
    if args.delay < 0 or args.timeout <= 0 or args.max_requests <= 0:
        parser.error("--delay must be 0 or more; --timeout and --max-requests must be positive")
    if args.passive_only and (args.active or args.network or args.urlscan):
        parser.error("--passive-only cannot be combined with --active, --network or --urlscan")

    try:
        target = parse_target(args.target)
        if not _confirmed(args, target.url):
            print("Scan cancelled: authorization was not confirmed.", file=sys.stderr)
            return EXIT_ERROR
        ensure_allowed(target.host, args.allow_private)
    except TargetError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    client = Client(
        target,
        allow_private=args.allow_private,
        timeout=args.timeout,
        delay=args.delay,
        max_requests=args.max_requests,
    )
    options = ScanOptions(args.passive_only, args.active, args.network, args.urlscan)
    result = run_scan(target, client, options, progress=lambda message: print(f"  {message}"))

    try:
        paths = write_reports(result, args.output, formats, target.host)
    except OSError as error:
        print(f"Error: could not write reports: {error}", file=sys.stderr)
        return EXIT_ERROR

    counts = ", ".join(f"{count} {label}" for label, count in result.risk_counts.items())
    print(f"\nOverall risk: {result.overall_risk.label} ({counts})")
    for warning in result.warnings:
        print(f"Warning: {warning}")
    for path in paths:
        print(f"Report: {path}")

    if args.fail_on and result.overall_risk >= Risk[args.fail_on.upper()] and result.findings:
        return EXIT_THRESHOLD
    return EXIT_OK
