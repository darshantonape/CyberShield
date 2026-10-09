"""Audit log hash chain (spec §6E)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.core.audit import GENESIS_HASH, AuditLog


@pytest.fixture
def log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


class TestRecording:
    def test_first_entry_links_to_genesis(self, log: AuditLog) -> None:
        event = log.record("scan.start", outcome="success", detail={"target": "192.168.56.10"})
        assert event.sequence == 1
        assert event.prev_hash == GENESIS_HASH

    def test_entries_form_a_chain(self, log: AuditLog) -> None:
        first = log.record("scan.start", outcome="success")
        second = log.record("scan.finish", outcome="success")
        third = log.record("remediation.apply", outcome="success")

        assert [first.sequence, second.sequence, third.sequence] == [1, 2, 3]
        assert second.prev_hash == first.entry_hash
        assert third.prev_hash == second.entry_hash

    def test_detail_round_trips(self, log: AuditLog) -> None:
        detail = {"target": "192.168.56.10", "port": 21, "verdict": "ALLOW"}
        log.record("remediation.apply", outcome="success", detail=detail)
        assert log.entries()[0].detail == detail

    def test_empty_log_verifies(self, log: AuditLog) -> None:
        result = log.verify_chain()
        assert result.valid
        assert result.entries_checked == 0


class TestVerification:
    def test_intact_chain_verifies(self, log: AuditLog) -> None:
        for i in range(5):
            log.record(f"event.{i}", outcome="success", detail={"i": i})
        result = log.verify_chain()
        assert result.valid
        assert result.entries_checked == 5

    def test_modified_entry_is_detected(self, log: AuditLog) -> None:
        for i in range(3):
            log.record(f"event.{i}", outcome="success", detail={"i": i})

        # Tamper: flip an outcome without recomputing its hash.
        lines = log.path.read_text().splitlines()
        row = json.loads(lines[1])
        row["outcome"] = "failure"
        lines[1] = json.dumps(row, sort_keys=True)
        log.path.write_text("\n".join(lines) + "\n")

        result = log.verify_chain()
        assert not result.valid
        assert result.first_invalid_sequence == 2
        assert "modified" in result.message.lower()

    def test_deleted_entry_is_detected(self, log: AuditLog) -> None:
        for i in range(4):
            log.record(f"event.{i}", outcome="success")

        lines = log.path.read_text().splitlines()
        del lines[1]
        log.path.write_text("\n".join(lines) + "\n")

        result = log.verify_chain()
        assert not result.valid
        assert "sequence gap" in result.message.lower()

    def test_detail_tampering_is_detected(self, log: AuditLog) -> None:
        # The case that matters most: rewriting which port was actually isolated.
        log.record("remediation.apply", outcome="success", detail={"port": 21})
        log.record("remediation.verify", outcome="success")

        lines = log.path.read_text().splitlines()
        row = json.loads(lines[0])
        row["detail"]["port"] = 3306
        lines[0] = json.dumps(row, sort_keys=True)
        log.path.write_text("\n".join(lines) + "\n")

        assert not log.verify_chain().valid

    def test_appending_a_forged_entry_breaks_the_link(self, log: AuditLog) -> None:
        log.record("event.real", outcome="success")
        forged = {
            "sequence": 2,
            "timestamp": "2026-08-30T00:00:00.000+00:00",
            "action": "remediation.rollback",
            "actor": "attacker",
            "outcome": "success",
            "detail": {},
            "prev_hash": "0" * 64,
            "entry_hash": "f" * 64,
        }
        with log.path.open("a") as handle:
            handle.write(json.dumps(forged, sort_keys=True) + "\n")

        result = log.verify_chain()
        assert not result.valid
        assert result.first_invalid_sequence == 2


class TestPersistence:
    def test_reopening_continues_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        first = AuditLog(path)
        first.record("event.one", outcome="success")

        second = AuditLog(path)
        event = second.record("event.two", outcome="success")

        assert event.sequence == 2
        assert second.verify_chain().valid
