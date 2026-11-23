"""Scope-checked, rate-limited HTTP client with an audit log and kill switch.

Every request the tool makes goes through HttpClient.send(), which:
  1. checks the kill switch (Ctrl+C) and the request / time budgets,
  2. re-checks the URL against the authorization scope,
  3. waits --delay seconds since the previous request (rate limiting),
  4. writes one line to the audit log (method, URL, status, time - no bodies,
     no cookies), so testers can prove exactly what was sent.
"""

import signal
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests

from . import TOOL_NAME, __version__
from .scope import Scope


class ScanStopped(Exception):
    """Raised when the scan must stop (kill switch, budget or time limit)."""


class OutOfScope(Exception):
    """Raised when a request would leave the authorized scope."""


class KillSwitch:
    """First Ctrl+C: stop gracefully (partial report is saved).
    Second Ctrl+C: hard exit immediately."""

    def __init__(self):
        self.event = threading.Event()
        self.reason = ""
        self._previous = None

    def install(self, on_first_press=None):
        def handler(signum, frame):
            if self.event.is_set():
                raise KeyboardInterrupt  # second press: abort right now
            self.trigger("aborted by user (Ctrl+C)")
            if on_first_press:
                on_first_press()
        self._previous = signal.signal(signal.SIGINT, handler)

    def uninstall(self):
        if self._previous is not None:
            signal.signal(signal.SIGINT, self._previous)

    def trigger(self, reason: str):
        if not self.event.is_set():
            self.reason = reason
            self.event.set()

    @property
    def stopped(self) -> bool:
        return self.event.is_set()


@dataclass
class Response:
    """The parts of an HTTP response the detectors need."""
    url: str
    status: int
    text: str
    elapsed: float
    timed_out: bool = False


def parse_cookie_string(raw: str) -> dict[str, str]:
    cookies = {}
    for part in raw.split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise ValueError(f"header must look like 'Name: value', got {raw!r}")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


class HttpClient:
    MAX_REDIRECTS = 5

    def __init__(self, scope: Scope, kill: KillSwitch, *, cookie: str = "", headers=None,
                 delay: float = 0.5, timeout: float = 15, max_requests: int = 500,
                 max_time: int = 600, audit_path: Path | None = None, on_request=None):
        self.scope = scope
        self.kill = kill
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.max_requests = max_requests
        self.deadline = time.monotonic() + max_time
        self.requests_sent = 0
        self.on_request = on_request  # optional callback for verbose output
        self._last_sent = 0.0
        self._audit = audit_path.open("a", encoding="utf-8") if audit_path else None

        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"{TOOL_NAME}/{__version__} (authorized security testing)"
        self.session.headers.update(headers or {})
        # Pin user-supplied cookies so the target cannot silently replace them.
        self._fixed_cookies = parse_cookie_string(cookie)

    def close(self):
        self.session.close()
        if self._audit:
            self._audit.close()

    def _check_budget(self):
        if self.kill.stopped:
            raise ScanStopped(self.kill.reason)
        if self.requests_sent >= self.max_requests:
            self.kill.trigger(f"request budget reached (--max-requests {self.max_requests})")
            raise ScanStopped(self.kill.reason)
        if time.monotonic() > self.deadline:
            self.kill.trigger("time limit reached (--max-time)")
            raise ScanStopped(self.kill.reason)

    def _wait_for_rate_limit(self):
        wait = self._last_sent + self.delay - time.monotonic()
        if wait > 0:
            # Event.wait returns early if Ctrl+C is pressed while sleeping.
            if self.kill.event.wait(wait):
                raise ScanStopped(self.kill.reason)

    def _log(self, method: str, url: str, status, elapsed: float, note: str = ""):
        stamp = datetime.now().isoformat(timespec="seconds")
        line = f"{stamp}\t{method}\t{status}\t{elapsed:.2f}s\t{url}"
        if note:
            line += f"\t{note}"
        if self._audit:
            self._audit.write(line + "\n")
            self._audit.flush()
        if self.on_request:
            self.on_request(line)

    def send(self, method: str, url: str, *, params=None, data=None,
             follow_redirects: bool = False) -> Response:
        """Send one request (plus in-scope redirects if asked). Raises ScanStopped/OutOfScope."""
        for _ in range(self.MAX_REDIRECTS + 1):
            if not self.scope.allows_url(url):
                raise OutOfScope(url)
            self._check_budget()
            self._wait_for_rate_limit()

            self.requests_sent += 1
            self._last_sent = time.monotonic()
            start = time.monotonic()
            try:
                resp = self.session.request(method, url, params=params, data=data,
                                            cookies=self._fixed_cookies, timeout=self.timeout,
                                            allow_redirects=False)
            except requests.Timeout:
                elapsed = time.monotonic() - start
                self._log(method, url, "TIMEOUT", elapsed)
                return Response(url, 0, "", elapsed, timed_out=True)
            except requests.RequestException as exc:
                elapsed = time.monotonic() - start
                self._log(method, url, "ERROR", elapsed, type(exc).__name__)
                return Response(url, 0, "", elapsed)

            elapsed = time.monotonic() - start
            self._log(method, resp.url, resp.status_code, elapsed)
            location = resp.headers.get("Location")
            if follow_redirects and resp.is_redirect and location:
                url, method, params, data = urljoin(resp.url, location), "GET", None, None
                continue
            return Response(resp.url, resp.status_code, resp.text, elapsed)
        return Response(url, 0, "", 0.0)
