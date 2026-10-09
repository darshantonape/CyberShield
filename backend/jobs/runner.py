"""Background job runner.

Scans routinely outlive an HTTP request, so `POST /api/scans` queues work here
and returns a job id immediately.

Job state lives in the database rather than in memory, so a crashed or
restarted process leaves an honest record: a job stuck in `running` after a
restart is visibly stale, not silently lost. `reap_stale_jobs()` marks those
`failed` at startup instead of leaving them to look like they are still working.

Deliberately small: a single-user research tool does not need Celery or Redis.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

from backend.database.models import Job
from backend.database.session import session_scope

__all__ = ["JobRunner", "get_runner"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class JobRunner:
    """Runs callables on a small thread pool, tracking state in the database."""

    def __init__(self, max_workers: int = 2) -> None:
        # Deliberately small: concurrent Nmap scans of the same lab distort each
        # other's timing, and scan duration is a reported research metric.
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cs-job")
        self._futures: dict[str, Future[Any]] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        kind: str,
        function: Callable[..., Any],
        *,
        payload: dict[str, Any] | None = None,
        owner_id: int | None = None,
        **kwargs: Any,
    ) -> str:
        """Queue work and return its job id.

        `owner_id` is the operator the job belongs to, stored so job status and
        result summaries are visible only to their owner. It is separate from
        `kwargs` (which are passed to the work function).
        """
        job_id = uuid.uuid4().hex[:16]

        with session_scope() as db:
            db.add(Job(
                job_id=job_id, kind=kind, state="queued",
                payload=payload or {}, user_id=owner_id,
            ))

        future = self._pool.submit(self._run, job_id, function, kwargs)
        with self._lock:
            self._futures[job_id] = future
        return job_id

    def _run(self, job_id: str, function: Callable[..., Any], kwargs: dict[str, Any]) -> Any:
        self._update(job_id, state="running", started_at=_utcnow())
        try:
            result = function(**kwargs)
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            self._update(
                job_id,
                state="failed",
                finished_at=_utcnow(),
                error=f"{type(exc).__name__}: {exc}",
            )
            raise

        summary = result.summary() if hasattr(result, "summary") else {"result": str(result)}
        self._update(job_id, state="completed", finished_at=_utcnow(), result=summary)
        return result

    def _update(self, job_id: str, **fields: Any) -> None:
        with session_scope() as db:
            job = db.query(Job).filter_by(job_id=job_id).one_or_none()
            if job is None:
                return
            for key, value in fields.items():
                setattr(job, key, value)

    def status(self, job_id: str) -> dict[str, Any] | None:
        with session_scope() as db:
            job = db.query(Job).filter_by(job_id=job_id).one_or_none()
            if job is None:
                return None
            return {
                "job_id": job.job_id,
                "user_id": job.user_id,
                "kind": job.kind,
                "state": job.state,
                "payload": job.payload,
                "result": job.result,
                "error": job.error,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            }

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def reap_stale_jobs() -> int:
    """Mark jobs left `queued`/`running` by a previous process as failed.

    Without this a job interrupted by a restart would sit in `running` forever
    and read as still in progress.
    """
    with session_scope() as db:
        stale = db.query(Job).filter(Job.state.in_(["queued", "running"])).all()
        for job in stale:
            job.state = "failed"
            job.finished_at = _utcnow()
            job.error = "Interrupted: the process restarted while this job was in flight."
        return len(stale)


_runner: JobRunner | None = None


def get_runner() -> JobRunner:
    global _runner
    if _runner is None:
        _runner = JobRunner()
    return _runner
