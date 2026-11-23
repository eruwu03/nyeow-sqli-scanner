"""Command-line entry point for NYEOWSQLiSCANNER."""

import argparse

from rich.console import Console

from . import TOOL_NAME, __version__
from .legal import confirm_authorization, show_banner

# Safe default: the local DVWA lab (official docker-compose publishes it on 4280).
DEFAULT_TARGET = "http://127.0.0.1:4280/"
TECHNIQUES = ("error", "boolean", "time")

EXAMPLES = """examples:
  # scan the local DVWA lab (default target), logged-in session cookie required
  python -m nyeowsqli --cookie "PHPSESSID=abc123; security=low"

  # test one URL only, no crawling
  python -m nyeowsqli -u "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit" \\
      --cookie "PHPSESSID=abc123; security=low" --no-crawl

  # only error-based and boolean techniques, slower rate
  python -m nyeowsqli -u http://127.0.0.1:4280/ --techniques error,boolean --delay 1

  # preview what would be tested, without sending any request
  python -m nyeowsqli -u "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1" --dry-run

  # authorized non-local target (written permission required)
  python -m nyeowsqli -u https://staging.example.com/item?id=3 --scope staging.example.com

emergency stop: press Ctrl+C once to stop and save a partial report, twice to exit immediately.
"""


def parse_techniques(value: str) -> list[str]:
    chosen = [t.strip().lower() for t in value.split(",") if t.strip()]
    bad = [t for t in chosen if t not in TECHNIQUES]
    if bad or not chosen:
        raise argparse.ArgumentTypeError(
            f"invalid technique(s): {', '.join(bad) or value!r}; choose from {', '.join(TECHNIQUES)}")
    return chosen


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyeowsqli",
        description=f"{TOOL_NAME} - detection-only SQL injection scanner for authorized testing.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_argument_group("target and scope")
    target.add_argument("-u", "--url", default=DEFAULT_TARGET,
                        help=f"start URL (default: {DEFAULT_TARGET})")
    target.add_argument("--scope", default="",
                        help="comma-separated hosts/IPs/CIDRs you are authorized to test, "
                             "e.g. 'app.test,10.0.5.0/24,*.lab.local' (required for non-local targets)")
    target.add_argument("--cookie", default="", help="cookie string, e.g. 'PHPSESSID=x; security=low'")
    target.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                        help="extra request header (repeatable)")

    crawl = parser.add_argument_group("discovery")
    crawl.add_argument("--depth", type=int, default=2, help="crawl depth (default: 2)")
    crawl.add_argument("--no-crawl", action="store_true", help="only test the start URL")
    crawl.add_argument("--post", action="store_true",
                       help="also test POST forms (off by default: POST often changes server state)")
    crawl.add_argument("--exclude", action="append", default=[], metavar="REGEX",
                       help="skip URLs matching this regex (repeatable; logout/setup/reset/delete "
                            "pages are always skipped)")

    scan = parser.add_argument_group("detection")
    scan.add_argument("--techniques", type=parse_techniques, default=list(TECHNIQUES),
                      help="comma-separated: error,boolean,time (default: all)")
    scan.add_argument("--time-delay", type=int, default=5,
                      help="seconds used by time-based payloads (default: 5)")

    safety = parser.add_argument_group("safety limits")
    safety.add_argument("--delay", type=float, default=0.5,
                        help="seconds between requests (default: 0.5)")
    safety.add_argument("--max-requests", type=int, default=500,
                        help="hard cap on requests sent (default: 500)")
    safety.add_argument("--max-time", type=int, default=600,
                        help="stop the whole scan after N seconds (default: 600)")
    safety.add_argument("--timeout", type=float, default=15,
                        help="per-request timeout in seconds (default: 15)")
    safety.add_argument("--dry-run", action="store_true",
                        help="show what would be tested without sending any request")
    safety.add_argument("--accept-disclaimer", action="store_true",
                        help="confirm authorization non-interactively (lab/scripted use)")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", default="output", help="output directory (default: ./output)")
    out.add_argument("--format", default="json,html", help="report formats: json,html (default: both)")
    out.add_argument("-v", "--verbose", action="store_true", help="show every request")
    out.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False)
    show_banner(console)

    if not confirm_authorization(console, args.accept_disclaimer):
        console.print("[red]Authorization not confirmed. Exiting without sending any request.[/red]")
        return 2
    console.print(f"[green]Target:[/green] {args.url}")
    return 0
