"""Authorization scope: decides which hosts the scanner is allowed to contact.

Rules:
  * Without --scope, the target must be a "safe" lab host (loopback, private
    RFC 1918 ranges, or reserved test domains such as localhost, example.com,
    *.test, *.local) and the scan is locked to that single host.
  * With --scope, the target host MUST match one of the listed entries.
  * Every single request is re-checked against the scope, so crawling or
    redirects can never leave the authorized boundary.
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

SAFE_DOMAINS = ("localhost", "example.com", "example.org", "example.net")
SAFE_SUFFIXES = (".test", ".local", ".localhost", ".example", ".example.com")


class ScopeError(Exception):
    """Raised when a target is not authorized."""


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_safe_lab_host(host: str) -> bool:
    """True for loopback/private IPs and reserved testing domain names."""
    host = host.lower().strip("[]")
    ip = _as_ip(host)
    if ip is not None:
        return ip.is_loopback or ip.is_private
    return host in SAFE_DOMAINS or host.endswith(SAFE_SUFFIXES)


@dataclass
class ScopeRule:
    """One --scope entry: exact host, wildcard domain (*.x.com) or CIDR network."""
    raw: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    wildcard: str | None = None

    @classmethod
    def parse(cls, entry: str) -> "ScopeRule":
        entry = entry.strip().lower()
        if not entry:
            raise ScopeError("empty scope entry")
        if entry.startswith("*."):
            return cls(raw=entry, wildcard=entry[1:])  # keep leading dot: ".x.com"
        try:
            return cls(raw=entry, network=ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
        if "/" in entry or ":" in entry:
            raise ScopeError(f"scope entry must be a host, *.domain or CIDR, not a URL: {entry!r}")
        return cls(raw=entry)

    def matches(self, host: str) -> bool:
        host = host.lower().strip("[]")
        if self.network is not None:
            ip = _as_ip(host)
            return ip is not None and ip in self.network
        if self.wildcard is not None:
            return host.endswith(self.wildcard) or host == self.wildcard[1:]
        return host == self.raw


@dataclass
class Scope:
    rules: list[ScopeRule] = field(default_factory=list)
    explicit: bool = False  # True when the user supplied --scope

    def allows_host(self, host: str) -> bool:
        return bool(host) and any(rule.matches(host) for rule in self.rules)

    def allows_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and self.allows_host(parsed.hostname or "")

    def non_lab_entries(self) -> list[str]:
        """Scope entries that point outside localhost/private/test ranges."""
        out = []
        for rule in self.rules:
            if rule.network is not None:
                if not (rule.network.is_loopback or rule.network.is_private):
                    out.append(rule.raw)
            elif not is_safe_lab_host(rule.raw.lstrip("*.")):
                out.append(rule.raw)
        return out

    def describe(self) -> str:
        hosts = ", ".join(rule.raw for rule in self.rules)
        return hosts if self.explicit else f"{hosts} only (default local-lab scope)"


def build_scope(target_url: str, scope_arg: str) -> Scope:
    """Validate the target URL and build the scope that governs the whole scan."""
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScopeError(f"target must be an http(s) URL with a host: {target_url!r}")
    host = parsed.hostname

    entries = [e for e in scope_arg.split(",") if e.strip()]
    if not entries:
        if not is_safe_lab_host(host):
            raise ScopeError(
                f"'{host}' is not a local/test target. Non-local targets require --scope "
                f"listing hosts you have WRITTEN authorization to test.")
        return Scope(rules=[ScopeRule.parse(host)], explicit=False)

    scope = Scope(rules=[ScopeRule.parse(e) for e in entries], explicit=True)
    if not scope.allows_host(host):
        raise ScopeError(f"target host '{host}' is not inside the declared scope ({scope.describe()})")
    return scope


def resolve_warning(host: str) -> str | None:
    """Warn if a 'safe-looking' hostname actually resolves to a public IP."""
    try:
        resolved = socket.gethostbyname(host)
    except OSError:
        return None
    ip = ipaddress.ip_address(resolved)
    if _as_ip(host) is None and not (ip.is_loopback or ip.is_private):
        return f"{host} resolves to public address {resolved}"
    return None
