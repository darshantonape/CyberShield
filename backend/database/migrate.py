"""Additive schema migrations for the existing SQLite database.

Why this exists rather than Alembic: `alembic` is a declared dependency but the
project never generated a migration environment, and every table so far was
created by `Base.metadata.create_all`. Introducing Alembic now would require
stamping the live database with a baseline revision it never had, and a wrong
stamp is exactly the kind of mistake that ends in a dropped table.

So this module does the things `create_all` cannot on a table that already
exists. It is deliberately limited and every step is idempotent:

  * ADD COLUMN only (nullable), so existing rows stay valid.
  * CREATE INDEX IF NOT EXISTS, to match indexes the models declare.
  * A one-time ownership backfill for the multi-tenant migration: rows created
    before the `user_id` columns existed are assigned to the earliest operator
    account (the original single operator). It only ever touches rows whose
    owner is NULL, so re-running it changes nothing.

Nothing here drops, renames, rewrites, or deletes. Anything beyond the above
should be done with a real migration tool and a backup.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, inspect, text

from backend.database.session import get_engine

__all__ = [
    "PENDING_COLUMNS",
    "PENDING_INDEXES",
    "apply_additive_migrations",
    "backfill_ownership",
]

# (table, column, SQL type) — must be nullable, and must match the type the
# SQLAlchemy model declares. SQLite cannot ADD COLUMN with a UNIQUE constraint,
# so uniqueness (e.g. users.email) is enforced by an index in PENDING_INDEXES.
PENDING_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("scan_sessions", "initiated_by", "VARCHAR(64)"),
    ("scan_sessions", "hosts_up", "INTEGER"),
    ("scan_sessions", "open_services", "INTEGER"),
    ("scan_sessions", "reachability", "VARCHAR(16)"),
    ("scan_sessions", "reachability_note", "TEXT"),
    # Multi-tenant ownership.
    ("users", "email", "VARCHAR(254)"),
    ("scan_sessions", "user_id", "INTEGER"),
    ("discovered_hosts", "user_id", "INTEGER"),
    ("discovered_services", "user_id", "INTEGER"),
    ("vulnerabilities", "user_id", "INTEGER"),
    ("remediation_actions", "user_id", "INTEGER"),
    ("jobs", "user_id", "INTEGER"),
)

# (index name, table, column expression, unique) — created IF NOT EXISTS so a
# fresh database (where create_all already made them) is unaffected.
PENDING_INDEXES: tuple[tuple[str, str, str, bool], ...] = (
    ("ix_users_email", "users", "email", True),
    ("ix_scan_sessions_user_id", "scan_sessions", "user_id", False),
    ("ix_discovered_hosts_user_id", "discovered_hosts", "user_id", False),
    ("ix_discovered_services_user_id", "discovered_services", "user_id", False),
    ("ix_vulnerabilities_user_id", "vulnerabilities", "user_id", False),
    ("ix_remediation_actions_user_id", "remediation_actions", "user_id", False),
    ("ix_jobs_user_id", "jobs", "user_id", False),
)

# Tables that gained a user_id owner and need their legacy rows backfilled.
_OWNED_TABLES: tuple[str, ...] = (
    "scan_sessions",
    "discovered_hosts",
    "discovered_services",
    "vulnerabilities",
    "remediation_actions",
    "jobs",
)


def apply_additive_migrations(db_path: Path | None = None) -> list[str]:
    """Add any missing columns and indexes. Returns what was applied."""
    engine: Engine = get_engine(db_path)
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    applied: list[str] = []
    with engine.begin() as connection:
        for table, column, sql_type in PENDING_COLUMNS:
            # A table that does not exist yet will be created complete by
            # create_all; there is nothing to migrate.
            if table not in existing_tables:
                continue
            columns = {c["name"] for c in inspector.get_columns(table)}
            if column in columns:
                continue
            # Names come from the literals above, never from user input.
            connection.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")
            )
            applied.append(f"{table}.{column}")

        # Indexes are created after the columns they cover exist.
        for name, table, expr, unique in PENDING_INDEXES:
            if table not in existing_tables:
                continue
            unique_kw = "UNIQUE " if unique else ""
            connection.execute(
                text(f"CREATE {unique_kw}INDEX IF NOT EXISTS {name} ON {table} ({expr})")
            )

    return applied


def backfill_ownership(db_path: Path | None = None) -> dict[str, int]:
    """Assign legacy (NULL-owner) rows to the earliest operator account.

    All data created before the multi-tenant migration belonged to the single
    operator this tool was built for. The earliest surviving `users` row is that
    operator, so NULL-owner rows are assigned to it. Only NULL owners are
    touched, so this is safe to run on every startup and does nothing once done.
    Returns a per-table count of rows updated.
    """
    engine: Engine = get_engine(db_path)
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    if "users" not in existing_tables:
        return {}

    updated: dict[str, int] = {}
    with engine.begin() as connection:
        row = connection.execute(
            text("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        ).first()
        if row is None:  # no accounts yet — nothing to attribute legacy data to
            return {}
        owner_id = int(row[0])

        for table in _OWNED_TABLES:
            if table not in existing_tables:
                continue
            columns = {c["name"] for c in inspector.get_columns(table)}
            if "user_id" not in columns:
                continue
            result = connection.execute(
                text(f"UPDATE {table} SET user_id = :uid WHERE user_id IS NULL"),
                {"uid": owner_id},
            )
            if result.rowcount:
                updated[table] = result.rowcount

    return updated
