"""SQLite engine and session management.

WAL mode is enabled so the web process can read while a background scan writes.
Foreign keys are enabled explicitly — SQLite does not enforce them by default,
which would silently allow orphaned findings.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import DATA_DIR
from backend.database.models import Base

__all__ = ["get_engine", "get_sessionmaker", "session_scope", "init_db", "DB_PATH"]

DB_PATH = DATA_DIR / "cybershield.db"

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_connection, _connection_record) -> None:
    """Per-connection pragmas applied on every new SQLite connection."""
    cursor = dbapi_connection.cursor()
    # Without this SQLite ignores FK constraints entirely.
    cursor.execute("PRAGMA foreign_keys=ON")
    # Concurrent reader + writer, which the scan-while-browsing flow needs.
    cursor.execute("PRAGMA journal_mode=WAL")
    # Durable enough for a research tool without fsync on every write.
    cursor.execute("PRAGMA synchronous=NORMAL")
    # Wait rather than immediately raising "database is locked".
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def get_engine(db_path: Path | None = None, *, echo: bool = False) -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is not None and db_path is None:
        return _engine

    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        f"sqlite:///{path}",
        echo=echo,
        future=True,
        # Scans run on worker threads; the connection must be usable there.
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _configure_sqlite)

    if db_path is None:
        _engine = engine
    return engine


def get_sessionmaker(db_path: Path | None = None) -> sessionmaker[Session]:
    global _Session
    if _Session is not None and db_path is None:
        return _Session

    factory = sessionmaker(bind=get_engine(db_path), expire_on_commit=False, future=True)
    if db_path is None:
        _Session = factory
    return factory


@contextmanager
def session_scope(db_path: Path | None = None) -> Iterator[Session]:
    """Transactional scope. Commits on success, rolls back on any exception."""
    session = get_sessionmaker(db_path)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(db_path: Path | None = None) -> Path:
    """Create missing tables and columns. Returns the database path.

    `create_all` only creates tables that do not exist; it never alters one that
    does. Columns added to a model after its table was created are applied by
    `apply_additive_migrations`, which is ADD COLUMN only and never destructive.
    The existing database and its data are preserved.
    """
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)

    # Imported here rather than at module scope: migrate.py imports get_engine
    # from this module, and a top-level import would be circular.
    from backend.database.migrate import apply_additive_migrations, backfill_ownership

    applied = apply_additive_migrations(db_path)
    if applied:
        print(f"schema: added missing column(s) {', '.join(applied)}")

    # One-time (idempotent) ownership backfill for the multi-tenant migration:
    # legacy rows with no owner are attributed to the earliest operator account.
    backfilled = backfill_ownership(db_path)
    if backfilled:
        summary = ", ".join(f"{t}={n}" for t, n in backfilled.items())
        print(f"ownership: backfilled legacy rows to earliest operator ({summary})")

    return db_path or DB_PATH
