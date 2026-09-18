"""DNS access layer.

Three implementations share one interface:

  SystemResolver   – dnspython over UDP/TCP 53 (the normal path)
  DoHResolver      – DNS-over-HTTPS, for networks that block port 53
  FixtureResolver  – replays recorded answers, used by the test suite

Every lookup goes through a TTL cache and a per-domain rate limiter, so a scan
of one domain issues a bounded, small number of queries. Nothing here writes to
the target: DNS lookups are ordinary public reads.
"""
from __future__ import annotations

import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

try:
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _HAS_DNSPYTHON = False


class DNSError(Exception):
    """Lookup failed for a reason other than 'no such record'."""


class NoRecord(Exception):
    """The name resolves but holds no record of the requested type (NODATA),
    or the name does not exist (NXDOMAIN). Distinguished by `nxdomain`."""

    def __init__(self, message: str, nxdomain: bool = False):
        super().__init__(message)
        self.nxdomain = nxdomain


@dataclass
class _CacheEntry:
    value: Any
    expires_at: float


class _TTLCache:
    def __init__(self, ttl: float = 300.0, max_entries: int = 2048):
        self._ttl = ttl
        self._max = max_entries
        self._data: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expires_at < time.monotonic():
                del self._data[key]
                return None
            return entry.value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                # drop the oldest quarter rather than thrash on every insert
                oldest = sorted(self._data.items(), key=lambda kv: kv[1].expires_at)
                for k, _ in oldest[: self._max // 4]:
                    del self._data[k]
            self._data[key] = _CacheEntry(value, time.monotonic() + self._ttl)


class _RateLimiter:
    """Token bucket, applied per target domain.

    Keeps a scan looking like what it is — a handful of ordinary resolver
    queries — rather than anything resembling enumeration.
    """

    def __init__(self, rate: float = 25.0, burst: int = 30):
        self._rate = rate
        self._burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                tokens, last = self._buckets.get(key, (float(self._burst), now))
                tokens = min(self._burst, tokens + (now - last) * self._rate)
                if tokens >= 1.0:
                    self._buckets[key] = (tokens - 1.0, now)
                    return True
                self._buckets[key] = (tokens, now)
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)


class BaseResolver(ABC):
    """Interface every resolver implements."""

    def __init__(self, timeout: float = 5.0, cache_ttl: float = 300.0):
        self.timeout = timeout
        self._cache = _TTLCache(ttl=cache_ttl)
        self._limiter = _RateLimiter()
        self.query_log: list[str] = []

    def query(self, name: str, rdtype: str, registrable: str | None = None) -> list[str]:
        """Return record strings for `name`/`rdtype`.

        Raises NoRecord when there is nothing to return, DNSError on failure.
        """
        name = name.rstrip(".").lower()
        rdtype = rdtype.upper()
        key = f"{rdtype}:{name}"

        cached = self._cache.get(key)
        if cached is not None:
            if isinstance(cached, NoRecord):
                raise cached
            return cached

        if not self._limiter.acquire(registrable or name):
            raise DNSError(f"rate limit exceeded for {registrable or name}")

        self.query_log.append(key)
        try:
            answers = self._do_query(name, rdtype)
        except NoRecord as exc:
            self._cache.set(key, exc)
            raise
        self._cache.set(key, answers)
        return answers

    def query_optional(self, name: str, rdtype: str, registrable: str | None = None) -> list[str]:
        """Like `query` but returns [] instead of raising NoRecord."""
        try:
            return self.query(name, rdtype, registrable)
        except NoRecord:
            return []

    @abstractmethod
    def _do_query(self, name: str, rdtype: str) -> list[str]:
        ...


class SystemResolver(BaseResolver):
    """dnspython against the host's configured resolvers (or explicit ones)."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0, **kw):
        super().__init__(timeout=timeout, **kw)
        if not _HAS_DNSPYTHON:
            raise RuntimeError("dnspython is required for SystemResolver")
        self._r = dns.resolver.Resolver()
        if nameservers:
            self._r.nameservers = nameservers
        self._r.timeout = timeout
        self._r.lifetime = timeout

    def _do_query(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = self._r.resolve(name, rdtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            raise NoRecord(f"{name} does not exist", nxdomain=True)
        except dns.resolver.NoAnswer:
            raise NoRecord(f"no {rdtype} record for {name}")
        except dns.resolver.NoNameservers as exc:
            raise DNSError(f"no nameservers could answer for {name}: {exc}")
        except dns.exception.Timeout:
            raise DNSError(f"timeout resolving {rdtype} {name}")
        except dns.exception.DNSException as exc:
            raise DNSError(f"{type(exc).__name__} resolving {rdtype} {name}: {exc}")
        return [_render(rr, rdtype) for rr in answer]


class DoHResolver(BaseResolver):
    """DNS-over-HTTPS. Useful where UDP/53 is filtered (containers, some CI)."""

    def __init__(self, endpoint: str = "https://dns.google/resolve", timeout: float = 5.0, **kw):
        super().__init__(timeout=timeout, **kw)
        self.endpoint = endpoint

    def _do_query(self, name: str, rdtype: str) -> list[str]:
        import urllib.error
        import urllib.parse
        import urllib.request

        url = f"{self.endpoint}?{urllib.parse.urlencode({'name': name, 'type': rdtype})}"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.URLError as exc:
            raise DNSError(f"DoH request failed for {rdtype} {name}: {exc}")
        except json.JSONDecodeError as exc:
            raise DNSError(f"DoH returned malformed JSON for {rdtype} {name}: {exc}")

        rcode = payload.get("Status", 2)
        if rcode == 3:
            raise NoRecord(f"{name} does not exist", nxdomain=True)
        if rcode != 0:
            raise DNSError(f"DoH rcode {rcode} for {rdtype} {name}")

        wanted = _RDTYPE_CODES.get(rdtype)
        records = [
            _unquote_txt(a["data"]) if rdtype == "TXT" else a["data"]
            for a in payload.get("Answer", [])
            if wanted is None or a.get("type") == wanted
        ]
        if not records:
            raise NoRecord(f"no {rdtype} record for {name}")
        return records


class FixtureResolver(BaseResolver):
    """Replays a recorded zone. Test-only; never used at runtime.

    Fixture shape: {"TXT:example.com": ["v=spf1 -all"], "MX:example.com": [...]}
    A value of null marks NXDOMAIN; a missing key is NODATA.
    """

    def __init__(self, records: dict[str, list[str] | None], **kw):
        super().__init__(**kw)
        self.records = {k.upper() if ":" in k else k: v for k, v in records.items()}

    def _do_query(self, name: str, rdtype: str) -> list[str]:
        key = f"{rdtype}:{name}".upper()
        for k, v in self.records.items():
            if k.upper() == key:
                if v is None:
                    raise NoRecord(f"{name} does not exist", nxdomain=True)
                if not v:
                    raise NoRecord(f"no {rdtype} record for {name}")
                return list(v)
        raise NoRecord(f"no {rdtype} record for {name}")


_RDTYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _render(rr: Any, rdtype: str) -> str:
    """Normalise a dnspython rdata object to the string form checks expect."""
    if rdtype == "TXT":
        # A TXT record is a sequence of <=255-byte strings that must be
        # concatenated without separators before parsing (RFC 7208 §3.3).
        return b"".join(rr.strings).decode("utf-8", errors="replace")
    if rdtype == "MX":
        return f"{rr.preference} {str(rr.exchange).rstrip('.')}"
    return str(rr).strip('"')


def _unquote_txt(data: str) -> str:
    """DoH returns TXT chunks as quoted strings; join them the RFC 7208 way."""
    parts, buf, in_str, escaped = [], [], False, False
    for ch in data:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            if in_str:
                parts.append("".join(buf))
                buf = []
            in_str = not in_str
        elif in_str:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return "".join(parts) if parts else data.strip('"')


def build_resolver(mode: str = "auto", nameservers: list[str] | None = None,
                   timeout: float = 5.0) -> BaseResolver:
    """Pick a resolver. `auto` tries system DNS and falls back to DoH."""
    if mode == "doh":
        return DoHResolver(timeout=timeout)
    if mode == "system":
        return SystemResolver(nameservers=nameservers, timeout=timeout)

    if _HAS_DNSPYTHON:
        candidate = SystemResolver(nameservers=nameservers, timeout=min(timeout, 3.0))
        try:
            candidate.query("dns.google", "A")
            candidate.timeout = timeout
            return candidate
        except (DNSError, NoRecord):
            pass
    return DoHResolver(timeout=timeout)
