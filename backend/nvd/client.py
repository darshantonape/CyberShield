"""NVD REST API 2.0 client.

Rate limits are self-enforced. NVD publishes 5 requests / 30s without an API
key and 50 / 30s with one, and returns no `x-ratelimit-*` headers to negotiate
against — confirmed by inspection during planning — so the client must pace
itself or start receiving 403/429 responses.

Two query modes, and the difference between them is a research result rather
than an implementation detail:

    search_by_cpe()      ?cpeName=cpe:2.3:...   PRIMARY
    search_by_keyword()  ?keywordSearch=...     FALLBACK, under-reports badly

Measured 2026-08-30: Apache httpd 2.4.49 returns **81** CVEs by cpeName and
**0** by keywordSearch. The keyword path exists only for products absent from
the curated map, and everything it produces is labelled LOW confidence.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from backend.nvd.cache import NvdCache

__all__ = ["NvdClient", "NvdError", "NvdResponse", "CVE_API_URL"]

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's documented allowances, with a safety margin.
_WINDOW_SECONDS = 30.0
_MAX_REQUESTS_UNKEYED = 5
_MAX_REQUESTS_KEYED = 50


class NvdError(Exception):
    """Raised when NVD cannot be queried or returns an unusable response."""


@dataclass
class NvdResponse:
    cves: list[dict[str, Any]] = field(default_factory=list)
    total_results: int = 0
    from_cache: bool = False
    query: dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def __len__(self) -> int:
        return len(self.cves)


class _RateLimiter:
    """Sliding-window limiter shared across threads."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a request slot is free. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [
                    t for t in self._timestamps if now - t < self.window_seconds
                ]
                if len(self._timestamps) < self.max_requests:
                    self._timestamps.append(now)
                    return waited
                sleep_for = self.window_seconds - (now - self._timestamps[0]) + 0.1

            time.sleep(max(sleep_for, 0.1))
            waited += max(sleep_for, 0.1)


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        cache: NvdCache | None = None,
        cache_dir: Path | None = None,
        timeout: float = 45.0,
        max_retries: int = 3,
        offline: bool = False,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        # When offline, only cached responses are used; a miss raises rather
        # than silently returning zero CVEs, which would look like "no
        # vulnerabilities found".
        self.offline = offline
        self.cache = cache or NvdCache(cache_dir)
        self._limiter = _RateLimiter(
            _MAX_REQUESTS_KEYED if api_key else _MAX_REQUESTS_UNKEYED, _WINDOW_SECONDS
        )
        self.request_count = 0
        self.total_wait_seconds = 0.0

    # -- HTTP -------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "CyberShield/0.1 (academic research)"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _fetch(self, params: dict[str, Any]) -> dict[str, Any]:
        last_error: str | None = None

        for attempt in range(1, self.max_retries + 1):
            self.total_wait_seconds += self._limiter.acquire()
            try:
                response = httpx.get(
                    CVE_API_URL, params=params, headers=self._headers(), timeout=self.timeout
                )
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(min(2**attempt, 20))
                continue

            self.request_count += 1

            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as exc:
                    raise NvdError(f"NVD returned a non-JSON body: {exc}") from exc

            # 403 is what NVD returns when a rate limit is exceeded.
            if response.status_code in (403, 429, 503, 504):
                last_error = f"HTTP {response.status_code}"
                backoff = min(2**attempt * 5, 60)
                time.sleep(backoff)
                continue

            raise NvdError(
                f"NVD returned HTTP {response.status_code} for {params}: "
                f"{response.text[:200]}"
            )

        raise NvdError(
            f"NVD request failed after {self.max_retries} attempts ({last_error}) "
            f"for {params}."
        )

    def _query(self, params: dict[str, Any]) -> NvdResponse:
        started = time.monotonic()

        cached = self.cache.get(params)
        if cached is not None:
            payload = cached.payload
            return NvdResponse(
                cves=[v.get("cve", {}) for v in payload.get("vulnerabilities", [])],
                total_results=int(payload.get("totalResults", 0)),
                from_cache=True,
                query=params,
                elapsed_seconds=time.monotonic() - started,
            )

        if self.offline:
            raise NvdError(
                f"Offline mode: no cached NVD response for {params}. Refusing to "
                "return an empty result, which would be indistinguishable from "
                "'no vulnerabilities found'."
            )

        payload = self._fetch(params)
        self.cache.put(params, payload)

        return NvdResponse(
            cves=[v.get("cve", {}) for v in payload.get("vulnerabilities", [])],
            total_results=int(payload.get("totalResults", 0)),
            from_cache=False,
            query=params,
            elapsed_seconds=time.monotonic() - started,
        )

    # -- Public queries ---------------------------------------------------

    def search_by_cpe(self, cpe23: str, *, results_per_page: int = 200) -> NvdResponse:
        """PRIMARY correlation path: exact CPE match.

        NVD returns every CVE whose applicability configuration matches this
        CPE. That includes over-broad historical ranges, so results are
        candidates requiring review, not confirmed findings.
        """
        if not cpe23 or not cpe23.startswith("cpe:2.3:"):
            raise NvdError(
                f"search_by_cpe requires a CPE 2.3 formatted string, got {cpe23!r}. "
                "Nmap's 2.2 URIs must be converted first."
            )
        return self._query({"cpeName": cpe23, "resultsPerPage": results_per_page})

    def search_by_keyword(self, keyword: str, *, results_per_page: int = 50) -> NvdResponse:
        """FALLBACK correlation path. Under-reports; never treat as exact.

        Used only when no verified CPE could be constructed. Callers must label
        every result as keyword-derived and LOW confidence.
        """
        text = (keyword or "").strip()
        if not text:
            raise NvdError("search_by_keyword requires a non-empty keyword.")
        return self._query(
            {"keywordSearch": text, "resultsPerPage": results_per_page}
        )

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        response = self._query({"cveId": cve_id.strip().upper()})
        return response.cves[0] if response.cves else None

    def stats(self) -> dict[str, Any]:
        return {
            "requests_made": self.request_count,
            "rate_limit_wait_seconds": round(self.total_wait_seconds, 2),
            "api_key_configured": self.api_key is not None,
            "cache": self.cache.stats(),
        }
