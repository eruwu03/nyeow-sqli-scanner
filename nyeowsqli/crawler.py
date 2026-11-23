"""Discovers injection points (URL query parameters and HTML forms) inside the scope.

Safety rules applied while crawling:
  * only in-scope http(s) URLs are visited (enforced again by HttpClient),
  * pages that are dangerous to touch (logout, setup, reset, delete...) are skipped,
  * forms with password fields are skipped (login / change-password forms),
  * POST forms are only tested when --post is given, because POST usually
    changes server-side state.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from .http_client import HttpClient, OutOfScope

DEFAULT_EXCLUDES = [r"log.?out", r"log.?off", r"sign.?out", r"setup", r"install",
                    r"reset", r"delete", r"remove", r"destroy", r"drop"]
SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".pdf",
                   ".zip", ".gz", ".mp4", ".mp3", ".woff", ".woff2", ".ttf")
FORM_INPUT_TAGS = ("input", "select", "textarea", "button")


@dataclass
class InjectionPoint:
    """A request we can replay with one parameter replaced by a payload."""
    method: str             # "GET" or "POST"
    url: str                # URL without query string
    params: dict[str, str]  # all parameters with their original values
    source: str             # "link" or "form"
    found_on: str = ""      # page where it was discovered
    skip_params: set[str] = field(default_factory=set)  # e.g. submit buttons

    @property
    def key(self) -> tuple:
        """Identity used to avoid testing the same endpoint twice."""
        return (self.method, self.url, tuple(sorted(self.params)))

    @property
    def testable_params(self) -> list[str]:
        return [p for p in self.params if p not in self.skip_params]

    def request_args(self, param: str, value: str) -> dict:
        """Build send() keyword arguments with `param` set to `value`."""
        values = dict(self.params)
        values[param] = value
        return {"params": values} if self.method == "GET" else {"data": values}

    def describe(self) -> str:
        return f"{self.method} {self.url} [{', '.join(self.testable_params)}]"


def strip_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def point_from_url(url: str, found_on: str = "") -> InjectionPoint | None:
    params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if not params:
        return None
    return InjectionPoint("GET", strip_query(url), params, "link", found_on)


class Crawler:
    def __init__(self, client: HttpClient, *, max_depth: int = 2, include_post: bool = False,
                 extra_excludes=None, log=None):
        self.client = client
        self.max_depth = max_depth
        self.include_post = include_post
        self.excludes = [re.compile(p, re.I) for p in DEFAULT_EXCLUDES + list(extra_excludes or [])]
        self.log = log or (lambda msg: None)
        self.skipped: list[str] = []  # human-readable reasons, shown in the report

    def is_excluded(self, url: str) -> bool:
        return any(rx.search(url) for rx in self.excludes)

    def should_visit(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        return (self.client.scope.allows_url(url) and not path.endswith(SKIP_EXTENSIONS)
                and not self.is_excluded(url))

    def crawl(self, start_url: str) -> list[InjectionPoint]:
        """Breadth-first crawl from start_url; returns unique injection points."""
        points: dict[tuple, InjectionPoint] = {}
        seen: set[str] = set()
        queue = deque([(start_url, 0)])

        def add(point: InjectionPoint | None):
            if point and point.testable_params and point.key not in points:
                points[point.key] = point
                self.log(f"found {point.describe()}")

        add(point_from_url(start_url))
        while queue:
            url, depth = queue.popleft()
            url = urldefrag(url)[0]
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = self.client.send("GET", url, follow_redirects=True)
            except OutOfScope:
                continue
            if resp.status == 0 or not resp.text:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                add(self.parse_form(form, resp.url))

            if depth >= self.max_depth:
                continue
            for tag in soup.find_all("a", href=True):
                link = urldefrag(urljoin(resp.url, tag["href"]))[0]
                if link in seen or not self.should_visit(link):
                    continue
                add(point_from_url(link, found_on=resp.url))
                queue.append((link, depth + 1))
        return list(points.values())

    def parse_form(self, form, page_url: str) -> InjectionPoint | None:
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return None
        if not self.client.scope.allows_url(action) or self.is_excluded(action):
            return None
        if form.find("input", attrs={"type": re.compile("^password$", re.I)}):
            self.skipped.append(f"{method} {strip_query(action)}: form has a password field")
            return None
        if method == "POST" and not self.include_post:
            self.skipped.append(f"POST {strip_query(action)}: POST forms need --post")
            return None

        params, skip = {}, set()
        for field_tag in form.find_all(FORM_INPUT_TAGS):
            name = field_tag.get("name")
            if not name:
                continue
            ftype = (field_tag.get("type") or "").lower()
            if field_tag.name == "select":
                option = field_tag.find("option", selected=True) or field_tag.find("option")
                value = option.get("value", option.text) if option else ""
            elif field_tag.name == "textarea":
                value = field_tag.text
            else:
                value = field_tag.get("value", "")
            if ftype in ("submit", "button", "image", "reset", "hidden") or field_tag.name == "button":
                skip.add(name)  # sent as-is, but not injected
                value = value or name
            if ftype in ("checkbox", "radio") and name in params:
                continue
            params[name] = value or "1"
        # GET forms submit to the action URL; its existing query string is replaced.
        url = strip_query(action) if method == "GET" else action
        return InjectionPoint(method, url, params, "form", page_url, skip)
