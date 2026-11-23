"""Command-line entry point for NYEOWSQLiSCANNER."""

import argparse
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import TOOL_NAME, __version__
from .crawler import Crawler, InjectionPoint, point_from_url
from .detectors import Detector, Finding
from .http_client import HttpClient, KillSwitch, ScanStopped, parse_headers
from .legal import confirm_authorization, show_banner
from .payloads import BOOLEAN_PAIRS, ERROR_PAYLOADS, TIME_PAYLOADS
from .reporter import write_reports
from .scanner import ScanResult, Scanner
from .scope import Scope, ScopeError, build_scope, resolve_warning

# Safe default: the local DVWA lab (official docker-compose publishes it on 4280).
DEFAULT_TARGET = "http://127.0.0.1:4280/"
TECHNIQUES = ("error", "boolean", "time")
FORMATS = ("json", "html")

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


def validate_args(parser: argparse.ArgumentParser, args) -> None:
    if args.depth < 0:
        parser.error("--depth must be 0 or more")
    if args.delay < 0:
        parser.error("--delay cannot be negative")
    if args.max_requests < 1 or args.max_time < 1:
        parser.error("--max-requests and --max-time must be at least 1")
    if not 1 <= args.time_delay <= 30:
        parser.error("--time-delay must be between 1 and 30 seconds")
    try:
        args.headers = parse_headers(args.header)
    except ValueError as exc:
        parser.error(str(exc))
    args.formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    if not args.formats or any(f not in FORMATS for f in args.formats):
        parser.error(f"--format must be a comma-separated list of: {', '.join(FORMATS)}")
    # A sleeping request must not hit the per-request timeout before it returns.
    args.timeout = max(args.timeout, args.time_delay + 5)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    console = Console(no_color=args.no_color, highlight=False)
    show_banner(console)

    try:
        scope = build_scope(args.url, args.scope)
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        return 2

    if not confirm_authorization(console, args.accept_disclaimer):
        console.print("[red]Authorization not confirmed. Exiting without sending any request.[/red]")
        return 2
    if not confirm_non_lab_scope(console, scope, args.url):
        console.print("[red]Non-local scope not confirmed. Exiting.[/red]")
        return 2

    console.print(f"[green]Target:[/green] {args.url}")
    console.print(f"[green]Scope :[/green] {scope.describe()}")
    console.print(f"[green]Limits:[/green] {args.delay}s delay, max {args.max_requests} requests, "
                  f"max {args.max_time}s  |  techniques: {', '.join(args.techniques)}\n")

    if args.dry_run:
        show_dry_run(console, args)
        return 0
    return run_scan(console, args, scope)


def make_run_dir(base: str, url: str) -> Path:
    """output/<host>_<port>_<timestamp>/ - one clearly labelled folder per scan."""
    parsed = urlparse(url)
    label = f"{parsed.hostname}_{parsed.port or parsed.scheme}"
    run_dir = Path(base) / f"{label}_{datetime.now():%Y%m%d-%H%M%S}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def run_scan(console: Console, args, scope: Scope) -> int:
    run_dir = make_run_dir(args.output, args.url)
    kill = KillSwitch()
    kill.install(on_first_press=lambda: console.print(
        "\n[bold yellow]Ctrl+C received: stopping after the current request and saving a "
        "partial report (press again to exit immediately)...[/bold yellow]"))
    verbose = (lambda line: console.print(f"[dim]{line}[/dim]")) if args.verbose else None
    client = HttpClient(scope, kill, cookie=args.cookie, headers=args.headers, delay=args.delay,
                        timeout=args.timeout, max_requests=args.max_requests,
                        max_time=args.max_time, audit_path=run_dir / "audit.log",
                        on_request=verbose)
    result = ScanResult(target=args.url, scope=scope.describe(), techniques=args.techniques)
    try:
        result.points, result.skipped, reachable = discover(console, args, client)
        if not reachable:
            console.print(f"[red]Could not reach {escape(args.url)} - is the lab running?[/red]")
            result.status = "failed: target unreachable"
            return finish_scan(console, args, client, kill, result, run_dir)
        show_points(console, result.points)
        scanner = Scanner(client, Detector(client, time_delay=args.time_delay), args.techniques,
                          on_finding=lambda f: print_finding(console, f),
                          log=lambda msg: console.print(f"[cyan]>[/cyan] {msg}"))
        scanner.run(result)
    except ScanStopped as stop:  # stopped while still crawling
        result.status = f"stopped: {stop}"
    except KeyboardInterrupt:
        result.status = "stopped: hard abort (second Ctrl+C)"
    return finish_scan(console, args, client, kill, result, run_dir)


def finish_scan(console, args, client, kill, result: ScanResult, run_dir: Path) -> int:
    """Always runs - including after Ctrl+C - so a partial scan still leaves a report."""
    kill.uninstall()
    client.close()
    result.finished = result.finished or datetime.now()
    result.requests_sent = client.requests_sent
    reports = write_reports(result, run_dir, args.formats)
    show_summary(console, result, run_dir, reports)
    if "Ctrl+C" in result.status:
        return 130
    return 1 if result.status.startswith("failed") else 0


def discover(console: Console, args, client: HttpClient):
    """Returns (injection points, skipped-for-safety notes, target reachable?)."""
    if args.no_crawl:
        point = point_from_url(args.url)
        reachable = client.send("GET", args.url).status != 0
        return ([point] if point else []), [], reachable
    console.print(f"[bold]Crawling[/bold] (depth {args.depth})...")
    crawler = Crawler(client, max_depth=args.depth, include_post=args.post,
                      extra_excludes=args.exclude,
                      log=lambda msg: console.print(f"  [dim]{msg}[/dim]") if args.verbose else None)
    points = crawler.crawl(args.url)
    return points, crawler.skipped, crawler.pages_fetched > 0


def show_points(console: Console, points: list[InjectionPoint]) -> None:
    if not points:
        console.print("[yellow]No injectable parameters found. Tip: pass a URL with parameters, "
                      "a logged-in --cookie, or --post.[/yellow]")
        return
    table = Table(title=f"{len(points)} injection point(s)", title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("Parameters")
    for i, point in enumerate(points, 1):
        table.add_row(str(i), point.method, escape(point.url),
                      escape(", ".join(point.testable_params)))
    console.print(table)


def print_finding(console: Console, finding: Finding) -> None:
    console.print(f"  [bold red]VULNERABLE[/bold red] {escape(finding.parameter)} "
                  f"({finding.technique}, DBMS: {finding.dbms})\n"
                  f"    payload : {escape(finding.payload)}\n"
                  f"    evidence: {escape(finding.evidence)}")


def show_summary(console: Console, result: ScanResult, run_dir: Path, reports: list[Path]) -> None:
    colour = {"completed": "green", "failed": "red"}.get(result.status.split(":")[0], "yellow")
    console.print(f"\n[bold]Scan {result.status}[/bold]", style=colour)
    console.print(f"  {len(result.points)} endpoint(s), {result.params_tested} parameter(s) tested, "
                  f"{result.requests_sent} request(s), {result.duration:.1f}s")
    if result.findings:
        table = Table(title=f"{len(result.findings)} SQL injection finding(s)", title_justify="left")
        for column in ("Parameter", "URL", "Technique", "DBMS", "Confidence"):
            table.add_column(column)
        for f in result.findings:
            table.add_row(escape(f.parameter), escape(f.url), f.technique, f.dbms, f.confidence)
        console.print(table)
    else:
        console.print("  [green]No SQL injection found in the tested parameters.[/green]")
    for path in reports:
        console.print(f"  Report   : {path}")
    console.print(f"  Audit log: {run_dir / 'audit.log'}")


def show_dry_run(console: Console, args) -> None:
    """Explain what a real run would do, WITHOUT sending a single request."""
    console.print("[bold yellow]DRY RUN - no requests will be sent.[/bold yellow]")
    point = point_from_url(args.url)
    if not args.no_crawl:
        console.print("  Crawling is skipped in dry-run (it needs requests); a real run would "
                      f"crawl to depth {args.depth} and stay inside the scope.")
    if not point:
        console.print("  The start URL has no query parameters to plan payloads for.")
        return
    per_param = {
        "error": len(ERROR_PAYLOADS),
        "boolean": len(BOOLEAN_PAIRS) * 4,      # TRUE+FALSE, two rounds
        "time": len(TIME_PAYLOADS) * 3,         # slow, fast, slow
    }
    table = Table(title="Planned tests for the start URL", title_justify="left")
    for column in ("Parameter", "Technique", "Max requests", "Example payload"):
        table.add_column(column)
    examples = {
        "error": ERROR_PAYLOADS[0],
        "boolean": BOOLEAN_PAIRS[1][0].format(a=7, b=8),
        "time": TIME_PAYLOADS[0][1].format(d=args.time_delay),
    }
    total = 0
    for param in point.testable_params:
        total += 2  # baseline
        for tech in args.techniques:
            total += per_param[tech]
            table.add_row(escape(param), tech, str(per_param[tech]),
                          escape(point.params[param] + examples[tech]))
    console.print(table)
    console.print(f"  Worst case: ~{total} requests (including 2 baseline requests per "
                  f"parameter), capped at {args.max_requests}.")


def confirm_non_lab_scope(console: Console, scope: Scope, url: str) -> bool:
    """Second, stronger confirmation when the scope leaves the local lab.

    The user must re-type the target hostname. This cannot be skipped with
    --accept-disclaimer, so a non-local scan can never start by accident.
    """
    host = urlparse(url).hostname or ""
    if not scope.explicit:
        warning = resolve_warning(host)
        if warning:
            console.print(f"[yellow]Note:[/yellow] {warning}")
        return True
    outside = scope.non_lab_entries()
    if not outside:
        return True
    console.print(f"[bold yellow]Scope includes NON-LOCAL targets:[/bold yellow] {', '.join(outside)}")
    if not sys.stdin.isatty():
        console.print("[red]Non-local scans require interactive confirmation.[/red]")
        return False
    try:
        typed = input(f"Re-type the target host '{host}' to confirm written authorization: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return typed.strip().lower() == host.lower()
