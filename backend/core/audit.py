"""Tamper-evident audit log.

Every scan and every remediation action appends one JSON object per line to
`data/audit.jsonl`. Each entry carries the SHA-256 of the previous entry, so the
file forms a hash chain: altering or deleting any historical record invalidates
every entry after it, and `verify_chain()` reports exactly where.

This matters for the research write-up. "The tool logged it" is weak evidence;
"the log is a verifiable chain and here is the verification output" is stronger,
and it is cheap to implement.

The chain detects tampering. It does not *prevent* it — anyone who can write the
file can rewrite the whole chain. That limitation is stated in
docs/threats-to-validity.md rather than glossed over.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

__all__ = [
    "AuditEvent",
    "AuditLog",
    "ChainVerification",
    "GENESIS_HASH",
]

# Hash recorded as `prev_hash` on the first entry.
GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    timestamp: str
    action: str
    actor: str
    outcome: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "outcome": self.outcome,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    entries_checked: int
    first_invalid_sequence: int | None
    message: str


def _canonical_payload(
    sequence: int,
    timestamp: str,
    action: str,
    actor: str,
    outcome: str,
    detail: dict[str, Any],
    prev_hash: str,
) -> str:
    """Deterministic serialisation of the hashed fields.

    `sort_keys` and fixed separators guarantee the same bytes are produced on
    every platform and Python version, so a chain stays verifiable over time.
    """
    return json.dumps(
        {
            "sequence": sequence,
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "outcome": outcome,
            "detail": detail,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _hash_entry(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL log."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- writing ----------------------------------------------------------

    def record(
        self,
        action: str,
        *,
        outcome: str,
        actor: str = "operator",
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append one event and return it.

        Args:
            action: Machine-readable verb, e.g. "scan.start", "remediation.apply".
            outcome: One of "success", "failure", "refused", "pending".
            detail: Structured context. Must be JSON-serialisable.
        """
        with self._lock:
            last = self._last_entry_unlocked()
            sequence = (last.sequence + 1) if last else 1
            prev_hash = last.entry_hash if last else GENESIS_HASH

            timestamp = _utc_now_iso()
            payload_detail = detail or {}

            payload = _canonical_payload(
                sequence, timestamp, action, actor, outcome, payload_detail, prev_hash
            )
            entry_hash = _hash_entry(payload)

            event = AuditEvent(
                sequence=sequence,
                timestamp=timestamp,
                action=action,
                actor=actor,
                outcome=outcome,
                detail=payload_detail,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )

            line = json.dumps(event.to_dict(), sort_keys=True, default=str)
            # Append, flush, and fsync: a crash mid-remediation must not lose the
            # record of what was already applied to the target.
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            return event

    # -- reading ----------------------------------------------------------

    def _iter_raw(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    yield json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{self.path} line {line_number} is not valid JSON: {exc}"
                    ) from exc

    def entries(self) -> list[AuditEvent]:
        return [
            AuditEvent(
                sequence=int(row["sequence"]),
                timestamp=str(row["timestamp"]),
                action=str(row["action"]),
                actor=str(row["actor"]),
                outcome=str(row["outcome"]),
                detail=dict(row.get("detail") or {}),
                prev_hash=str(row["prev_hash"]),
                entry_hash=str(row["entry_hash"]),
            )
            for row in self._iter_raw()
        ]

    def _last_entry_unlocked(self) -> AuditEvent | None:
        last: AuditEvent | None = None
        for event in self.entries():
            last = event
        return last

    # -- verification -----------------------------------------------------

    def verify_chain(self) -> ChainVerification:
        """Recompute every hash and confirm the chain is intact."""
        expected_prev = GENESIS_HASH
        expected_sequence = 1
        checked = 0

        for event in self.entries():
            if event.sequence != expected_sequence:
                return ChainVerification(
                    valid=False,
                    entries_checked=checked,
                    first_invalid_sequence=event.sequence,
                    message=(
                        f"Sequence gap: expected {expected_sequence}, found "
                        f"{event.sequence}. An entry was removed or reordered."
                    ),
                )

            if event.prev_hash != expected_prev:
                return ChainVerification(
                    valid=False,
                    entries_checked=checked,
                    first_invalid_sequence=event.sequence,
                    message=(
                        f"Broken link at entry {event.sequence}: prev_hash does not "
                        "match the preceding entry's hash."
                    ),
                )

            recomputed = _hash_entry(
                _canonical_payload(
                    event.sequence,
                    event.timestamp,
                    event.action,
                    event.actor,
                    event.outcome,
                    event.detail,
                    event.prev_hash,
                )
            )
            if recomputed != event.entry_hash:
                return ChainVerification(
                    valid=False,
                    entries_checked=checked,
                    first_invalid_sequence=event.sequence,
                    message=(
                        f"Entry {event.sequence} was modified: recomputed hash does "
                        "not match the stored entry_hash."
                    ),
                )

            expected_prev = event.entry_hash
            expected_sequence += 1
            checked += 1

        return ChainVerification(
            valid=True,
            entries_checked=checked,
            first_invalid_sequence=None,
            message=(
                f"Chain intact: {checked} "
                f"{'entry' if checked == 1 else 'entries'} verified."
            ),
        )
