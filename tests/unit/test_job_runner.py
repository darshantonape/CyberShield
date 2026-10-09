"""Background job runner state tracking."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from backend.database.models import Job
from backend.database.session import init_db, session_scope
from backend.jobs import runner as runner_module
from backend.jobs.runner import JobRunner, reap_stale_jobs


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the runner's session_scope at a throwaway database."""
    db_path = tmp_path / "jobs.db"
    init_db(db_path)

    from contextlib import contextmanager

    @contextmanager
    def scoped(_path=None):
        with session_scope(db_path) as db:
            yield db

    monkeypatch.setattr(runner_module, "session_scope", scoped)
    return db_path


def wait_for(runner: JobRunner, job_id: str, states: set[str], timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = runner.status(job_id)
        if status and status["state"] in states:
            return status
        time.sleep(0.05)
    pytest.fail(f"job {job_id} never reached {states}")


class TestJobLifecycle:
    def test_successful_job_reaches_completed(self, isolated_db) -> None:
        runner = JobRunner(max_workers=1)
        try:
            job_id = runner.submit("test.ok", lambda value: value * 2, value=21)
            status = wait_for(runner, job_id, {"completed", "failed"})
            assert status["state"] == "completed"
            assert status["error"] is None
            assert status["finished_at"] is not None
        finally:
            runner.shutdown()

    def test_failing_job_records_the_error(self, isolated_db) -> None:
        def boom() -> None:
            raise ValueError("scan exploded")

        runner = JobRunner(max_workers=1)
        try:
            job_id = runner.submit("test.fail", boom)
            status = wait_for(runner, job_id, {"completed", "failed"})
            assert status["state"] == "failed"
            # The exception is recorded, not swallowed.
            assert "ValueError" in status["error"]
            assert "scan exploded" in status["error"]
        finally:
            runner.shutdown()

    def test_payload_is_retained(self, isolated_db) -> None:
        runner = JobRunner(max_workers=1)
        try:
            job_id = runner.submit(
                "test.payload", lambda: None, payload={"target": "192.168.56.10"}
            )
            wait_for(runner, job_id, {"completed", "failed"})
            assert runner.status(job_id)["payload"] == {"target": "192.168.56.10"}
        finally:
            runner.shutdown()

    def test_unknown_job_returns_none(self, isolated_db) -> None:
        runner = JobRunner(max_workers=1)
        try:
            assert runner.status("does-not-exist") is None
        finally:
            runner.shutdown()


class TestStaleJobReaping:
    def test_interrupted_jobs_are_marked_failed(self, isolated_db) -> None:
        # A job left "running" by a killed process must not read as in progress.
        with session_scope(isolated_db) as db:
            db.add(Job(job_id="stale1", kind="scan", state="running"))
            db.add(Job(job_id="stale2", kind="scan", state="queued"))
            db.add(Job(job_id="done", kind="scan", state="completed"))

        assert reap_stale_jobs() == 2

        with session_scope(isolated_db) as db:
            states = {j.job_id: j.state for j in db.query(Job).all()}
            assert states == {"stale1": "failed", "stale2": "failed", "done": "completed"}

            stale = db.query(Job).filter_by(job_id="stale1").one()
            assert "restarted" in stale.error
