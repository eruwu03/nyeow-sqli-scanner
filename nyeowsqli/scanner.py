"""Scan pipeline: runs the chosen techniques against every discovered parameter."""

from dataclasses import dataclass, field
from datetime import datetime

from rich.markup import escape

from .crawler import InjectionPoint
from .detectors import Detector, Finding
from .http_client import HttpClient, OutOfScope, ScanStopped

# Cheapest and most reliable first; once a parameter is confirmed vulnerable
# the remaining (slower, noisier) techniques are skipped for that parameter.
TECHNIQUE_ORDER = ("error", "boolean", "time")


@dataclass
class ScanResult:
    target: str
    scope: str
    techniques: list[str]
    started: datetime = field(default_factory=datetime.now)
    finished: datetime | None = None
    status: str = "running"
    points: list[InjectionPoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    params_tested: int = 0
    requests_sent: int = 0

    @property
    def duration(self) -> float:
        end = self.finished or datetime.now()
        return (end - self.started).total_seconds()


class Scanner:
    def __init__(self, client: HttpClient, detector: Detector, techniques, *,
                 on_finding=None, log=None):
        self.client = client
        self.detector = detector
        self.techniques = [t for t in TECHNIQUE_ORDER if t in techniques]
        self.on_finding = on_finding or (lambda finding: None)
        self.log = log or (lambda msg: None)

    def run(self, result: ScanResult) -> ScanResult:
        """Test every parameter of every injection point; never raises on stop."""
        try:
            for point in result.points:
                for param in point.testable_params:
                    finding = self.test_parameter(point, param)
                    result.params_tested += 1
                    if finding:
                        result.findings.append(finding)
                        self.on_finding(finding)
            result.status = "completed"
        except ScanStopped as stop:
            result.status = f"stopped: {stop}"
        finally:
            result.finished = datetime.now()
            result.requests_sent = self.client.requests_sent
        return result

    def test_parameter(self, point: InjectionPoint, param: str) -> Finding | None:
        self.log(f"testing [bold]{escape(param)}[/bold] on {point.method} {escape(point.url)}")
        try:
            base = self.detector.baseline(point, param)
        except OutOfScope:
            return None
        if base.response.status == 0:
            self.log(f"  [yellow]no response for baseline, skipping {escape(param)}[/yellow]")
            return None
        checks = {
            "error": self.detector.error_based,
            "boolean": self.detector.boolean_based,
            "time": self.detector.time_based,
        }
        for name in self.techniques:
            finding = checks[name](point, param, base)
            if finding:
                return finding
        return None
