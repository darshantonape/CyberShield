"""On-disk cache for NVD responses.

Two purposes, both about the research rather than performance:

  * **Reproducibility.** An experiment can be re-analysed months later against
    the exact NVD responses that produced the original findings, even though
    NVD data changes continuously (CVEs are re-scored and re-scoped).
  * **Rate limits.** Without an API key NVD allows 5 requests / 30s, so a scan
    of several services would otherwise take minutes of pure waiting.

Each entry stores the response body together with the query that produced it
and the time it was fetched, so a cached result is always attributable.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.core.config import DATA_DIR

__all__ = ["NvdCache", "CacheEntry", "DEFAULT_TTL_SECONDS"]

# NVD data is not static, but a week is short enough to stay current and long
# enough to make repeated experiment runs cheap.
DEFAULT_TTL_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class CacheEntry:
    payload: dict[str, Any]
    fetched_at: float
    query: dict[str, Any]

    def age_seconds(self, now: float | None = None) -> float:
        return (now if now is not None else time.time()) - self.fetched_at

    def is_fresh(self, ttl_seconds: int, now: float | None = None) -> bool:
        return self.age_seconds(now) < ttl_seconds


class NvdCache:
    def __init__(
        self, directory: Path | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> None:
        self.directory = directory or (DATA_DIR / "nvd_cache")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key_for(params: dict[str, Any]) -> str:
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, params: dict[str, Any]) -> CacheEntry | None:
        """Return a fresh cached entry, or None on miss or expiry."""
        path = self._path(self.key_for(params))
        if not path.exists():
            self.misses += 1
            return None

        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            # A corrupt cache file is a miss, never a crash.
            self.misses += 1
            return None

        entry = CacheEntry(
            payload=raw.get("payload") or {},
            fetched_at=float(raw.get("fetched_at") or 0.0),
            query=raw.get("query") or {},
        )
        if not entry.is_fresh(self.ttl_seconds):
            self.misses += 1
            return None

        self.hits += 1
        return entry

    def put(self, params: dict[str, Any], payload: dict[str, Any]) -> Path:
        path = self._path(self.key_for(params))
        path.write_text(
            json.dumps(
                {"query": params, "fetched_at": time.time(), "payload": payload},
                indent=2,
                sort_keys=True,
            )
        )
        return path

    @property
    def hit_rate(self) -> float | None:
        total = self.hits + self.misses
        return (self.hits / total) if total else None

    def stats(self) -> dict[str, Any]:
        return {"hits": self.hits, "misses": self.misses, "hit_rate": self.hit_rate}
