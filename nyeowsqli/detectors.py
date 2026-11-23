"""SQL injection detection techniques.

Each technique compares how the application responds to a payload against
a BASELINE (the response to the parameter's original value). Comparing
against a baseline is what avoids false positives: e.g. a page that always
contains the word "SQL syntax" is not reported as vulnerable.
"""

import html
import re
from dataclasses import asdict, dataclass

from .crawler import InjectionPoint
from .http_client import HttpClient, Response
from .payloads import COMPILED_SIGNATURES, ERROR_PAYLOADS

TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class Finding:
    technique: str      # "error-based", "boolean-based blind", "time-based blind"
    method: str
    url: str
    parameter: str
    payload: str
    dbms: str           # fingerprinted DBMS or "unknown"
    confidence: str     # "high" / "medium"
    evidence: str       # short, non-sensitive proof (never full response bodies)
    severity: str = "High"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Baseline:
    """Response to the original, untouched parameter value."""
    response: Response
    stability: float  # similarity of two identical requests (1.0 = static page)


def visible_text(page: str) -> str:
    return html.unescape(TAG_RE.sub(" ", page))


def find_db_error(text: str) -> tuple[str, str] | None:
    """Return (dbms, matched_snippet) if the text contains a known DB error."""
    plain = " ".join(visible_text(text).split())
    for dbms, patterns in COMPILED_SIGNATURES.items():
        for pattern in patterns:
            match = pattern.search(plain)
            if match:
                start = max(0, match.start() - 40)
                return dbms, plain[start:match.end() + 80].strip()
    return None


class Detector:
    def __init__(self, client: HttpClient, *, time_delay: int = 5):
        self.client = client
        self.time_delay = time_delay

    def _send(self, point: InjectionPoint, param: str, value: str) -> Response:
        return self.client.send(point.method, point.url, **point.request_args(param, value))

    def _finding(self, technique, point, param, payload, dbms, confidence, evidence) -> Finding:
        return Finding(technique, point.method, point.url, param, payload,
                       dbms or "unknown", confidence, evidence[:300])

    # ----------------------------------------------------------- baseline
    def baseline(self, point: InjectionPoint, param: str) -> Baseline:
        original = point.params[param]
        first = self._send(point, param, original)
        second = self._send(point, param, original)
        return Baseline(first, similarity(first.text, second.text))

    # ------------------------------------------------------- error-based
    def error_based(self, point: InjectionPoint, param: str, base: Baseline) -> Finding | None:
        """Inject syntax-breaking characters and look for a NEW database error."""
        if find_db_error(base.response.text):
            return None  # page already shows a DB error; this test would be unreliable
        original = point.params[param]
        for suffix in ERROR_PAYLOADS:
            payload = original + suffix
            resp = self._send(point, param, payload)
            hit = find_db_error(resp.text)
            if hit:
                dbms, snippet = hit
                return self._finding("error-based", point, param, payload, dbms, "high",
                                     f"Database error returned: \"{snippet}\"")
        return None


def similarity(a: str, b: str) -> float:
    """Placeholder similarity until boolean-based detection is added."""
    return 1.0 if a == b else 0.0
