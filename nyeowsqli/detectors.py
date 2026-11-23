"""SQL injection detection techniques.

Each technique compares how the application responds to a payload against
a BASELINE (the response to the parameter's original value). Comparing
against a baseline is what avoids false positives: e.g. a page that always
contains the word "SQL syntax" is not reported as vulnerable.
"""

import difflib
import html
import random
import re
from dataclasses import asdict, dataclass

from .crawler import InjectionPoint
from .http_client import HttpClient, Response
from .payloads import BOOLEAN_PAIRS, COMPILED_SIGNATURES, ERROR_PAYLOADS

TAG_RE = re.compile(r"<[^>]+>")
# Minimum difference between TRUE and FALSE responses (0-1 scale). The real
# threshold grows with the page's natural noise (see Detector._boolean_round).
BOOLEAN_MIN_GAP = 0.01


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
        return Baseline(first, response_similarity(first, second))

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

    # --------------------------------------------- boolean-based blind
    def boolean_based(self, point: InjectionPoint, param: str, base: Baseline) -> Finding | None:
        """Send an always-TRUE and an always-FALSE condition.

        Vulnerable if: TRUE looks like the original page, FALSE looks different,
        and the same result repeats with new random numbers (confirmation round).
        """
        original = point.params[param]
        for true_tpl, false_tpl in BOOLEAN_PAIRS:
            first = self._boolean_round(point, param, original, true_tpl, false_tpl, base)
            if not first:
                continue
            second = self._boolean_round(point, param, original, true_tpl, false_tpl, base)
            if not second:
                continue  # did not repeat: probably dynamic content, not SQLi
            true_payload, false_payload, detail = second
            return self._finding("boolean-based blind", point, param,
                                 f"{true_payload}  |  {false_payload}", None, "high", detail)
        return None

    def _boolean_round(self, point, param, original, true_tpl, false_tpl, base):
        a, b = random.sample(range(100, 9999), 2)
        true_payload = original + true_tpl.format(a=a, b=b)
        false_payload = original + false_tpl.format(a=a, b=b)
        true_resp = self._send(point, param, true_payload)
        false_resp = self._send(point, param, false_payload)

        true_sim = response_similarity(base.response, true_resp, true_payload)
        false_sim = response_similarity(base.response, false_resp, false_payload)
        # noise = how much the page changes by itself between identical requests
        # (timestamps, ads, tokens). Thresholds scale with it, so a dynamic page
        # must show a much bigger TRUE/FALSE difference before we report it.
        noise = 1.0 - base.stability
        true_matches = true_sim >= 1.0 - (noise + 0.02)
        false_differs = true_sim - false_sim >= max(BOOLEAN_MIN_GAP, 2 * noise)
        if not (true_matches and false_differs):
            return None
        detail = (f"TRUE condition matched original page (similarity {true_sim:.2f}, "
                  f"HTTP {true_resp.status}); FALSE condition differed (similarity "
                  f"{false_sim:.2f}, HTTP {false_resp.status}); confirmed twice")
        return true_payload, false_payload, detail


def normalize(text: str, payload: str = "") -> str:
    """Visible text with whitespace collapsed and any reflected payload removed,
    so a page that simply echoes our input does not look 'different'."""
    plain = visible_text(text)
    if payload:
        for variant in {payload, html.escape(payload), html.escape(payload, quote=False)}:
            plain = plain.replace(variant, "")
    return " ".join(plain.split())


def similarity(a: str, b: str) -> float:
    """0.0 (completely different) .. 1.0 (identical)."""
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def response_similarity(base: Response, other: Response, payload: str = "") -> float:
    """Different status codes count as completely different responses."""
    if base.status != other.status:
        return 0.0
    return similarity(normalize(base.text), normalize(other.text, payload))
