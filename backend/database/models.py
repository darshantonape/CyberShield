"""Database schema (spec §17).

Entities: scan_sessions, discovered_hosts, discovered_services,
software_signatures, vulnerabilities, remediation_actions, audit_logs.

Design decisions that matter for the research write-up:

  * A row in `vulnerabilities` is a CVE *candidate*, not a confirmed finding.
    There is no `confirmed_vulnerable` state, because nothing in this system can
    establish one. Review states are set by a human only.
  * `version_confidence` distinguishes "no version detected" from "version
    detected, no CVE candidates returned". Collapsing those into "clean" would
    overstate what the scan actually demonstrated.
  * Every remediation row stores its rollback command *before* the rule is
    applied, so a crash between apply and record still leaves a way back.
  * `cvss_version` is always recorded alongside the score, so v2-only and
    v3.1-scored records are never silently compared (spec §10).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# 1. Scan sessions
# ---------------------------------------------------------------------------


class ScanSession(Base):
    """One invocation of the scanning pipeline."""

    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    target_spec: Mapped[str] = mapped_column(String(128))
    profile: Mapped[str] = mapped_column(String(64))
    # assessment | verification_before | verification_after | verification_rollback
    scan_kind: Mapped[str] = mapped_column(String(32), default="assessment")

    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Reproducibility metadata, copied into every experiment manifest (spec §23).
    nmap_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nmap_argv: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    config_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_xml_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Operator who started the scan. "system" for TTL sweeps and verification
    # rescans triggered by the executor rather than by a person.
    initiated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Owning user. Nullable so pre-multi-tenant rows remain valid until backfilled;
    # every read path filters on it so one operator never sees another's scans.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)

    # Denormalised outcome counts. A scan that FAILED has no host rows at all,
    # so these are the only way the history page can distinguish "failed before
    # Nmap produced anything" from "ran and found nothing".
    hosts_up: Mapped[int | None] = mapped_column(Integer, nullable=True)
    open_services: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # reachable | unreachable | unknown
    # Set from the scan itself: an authorized target that answered no probe is
    # recorded as UNREACHABLE, never as a host with zero vulnerabilities.
    reachability: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Plain-language explanation of the reachability verdict, shown in the UI.
    reachability_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    hosts: Mapped[list["DiscoveredHost"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# 2. Discovered hosts
# ---------------------------------------------------------------------------


class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"
    __table_args__ = (
        UniqueConstraint("session_id", "address", name="uq_host_per_session"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), index=True)
    # Denormalised owner (== the scan's user_id) so host/service/vuln lists can be
    # filtered by user without a three-table join on every request.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)

    address: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="unknown")
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)

    session: Mapped[ScanSession] = relationship(back_populates="hosts")
    services: Mapped[list["DiscoveredService"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# 3. Discovered services
# ---------------------------------------------------------------------------


class DiscoveredService(Base):
    """A detected port and whatever Nmap could infer about it.

    Fields here are raw evidence — stored exactly as Nmap reported them, so the
    normalization step can be audited against its input (spec §7).
    """

    __tablename__ = "discovered_services"
    __table_args__ = (
        UniqueConstraint("host_id", "port", "proto", name="uq_service_per_host"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("discovered_hosts.id"), index=True)
    # Denormalised owner (== the host's user_id), so the services and
    # vulnerabilities list endpoints can filter by user directly.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)

    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="unknown")

    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Nmap's own service-detection confidence, 1-10. Carried into reports so a
    # weak banner match is visibly weak rather than silently trusted.
    nmap_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # CPE strings Nmap emitted itself, when it emits any.
    nmap_cpes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # "known" when a version string was detected, "unknown" otherwise (spec §8).
    # Never inferred or filled in by the normalizer.
    version_confidence: Mapped[str] = mapped_column(String(16), default="unknown")

    # identified | product_only | undetermined
    # Never "clean": absence of a detected version is not absence of a vulnerability.
    identification_status: Mapped[str] = mapped_column(String(32), default="undetermined")

    host: Mapped[DiscoveredHost] = relationship(back_populates="services")
    signatures: Mapped[list["SoftwareSignature"]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# 4. Software signatures (normalization output)
# ---------------------------------------------------------------------------


class SoftwareSignature(Base):
    """A normalized software identity derived from a detected service.

    One service can yield several signatures when the product string is
    ambiguous; each keeps its own confidence and provenance so an ambiguous
    normalization is visible rather than silently resolved.
    """

    __tablename__ = "software_signatures"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(
        ForeignKey("discovered_services.id"), index=True
    )

    vendor: Mapped[str] = mapped_column(String(128))
    product: Mapped[str] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    part: Mapped[str] = mapped_column(String(8), default="a")

    # Full CPE 2.3 string, null when a reliable CPE could not be constructed.
    cpe23: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # nmap_cpe | curated_map | nvd_cpe_dictionary
    mapping_source: Mapped[str] = mapped_column(String(32))
    # HIGH | MEDIUM | LOW
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    service: Mapped[DiscoveredService] = relationship(back_populates="signatures")


# ---------------------------------------------------------------------------
# 5. Vulnerabilities (CVE candidates)
# ---------------------------------------------------------------------------


class CveRecord(Base):
    """A CVE as returned by NVD, cached so experiments can be re-run offline."""

    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vuln_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Resolved by backend/nvd/severity.py. v3.1 is preferred (spec §10); the
    # version actually used is always recorded so scores are never compared
    # across CVSS generations without a label. All null when NVD gives no score.
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    base_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    base_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    vector_string: Mapped[str | None] = mapped_column(String(160), nullable=True)
    # Every score NVD supplied, keyed by version — kept for the paper's
    # CVSS-coverage analysis.
    all_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    cwe_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    reference_urls: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    raw_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="cve")


class Vulnerability(Base):
    """A correlation between a detected service and a CVE record.

    This asserts that a detected version string resembles software named in a
    CVE's applicability data. It does NOT assert that the service is vulnerable
    or exploitable (spec §9).
    """

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("service_id", "cve_id", name="uq_vuln_per_service_cve"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(
        ForeignKey("discovered_services.id"), index=True
    )
    cve_id: Mapped[str] = mapped_column(ForeignKey("cve_records.cve_id"), index=True)
    signature_id: Mapped[int | None] = mapped_column(
        ForeignKey("software_signatures.id"), nullable=True
    )
    # Denormalised owner (== the service's user_id). cve_records stays global — it
    # is a shared cache of NVD data, not user-owned — but a Vulnerability links a
    # CVE to one user's detected service and is therefore owned.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)

    # cpe_exact - matched via NVD cpeName query (primary path)
    # keyword   - matched via NVD keywordSearch (fallback; under-reports badly)
    matching_method: Mapped[str] = mapped_column(String(32))
    # HIGH | MEDIUM | LOW  (spec §11)
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")

    detected_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # candidate | reviewed_true_positive | reviewed_false_positive
    # Review states are set by a human only, never by the pipeline.
    status: Mapped[str] = mapped_column(String(32), default="candidate")
    reviewer_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # What the match was based on, and why it might be wrong. Both are rendered
    # next to every finding in the UI and in exported reports.
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    caveats: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    nvd_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    service: Mapped[DiscoveredService] = relationship(back_populates="vulnerabilities")
    cve: Mapped[CveRecord] = relationship(back_populates="vulnerabilities")


# ---------------------------------------------------------------------------
# 6. Remediation actions
# ---------------------------------------------------------------------------


class RemediationAction(Base):
    """A controlled, reversible network-level exposure-reduction action.

    Terminology is deliberate: this isolates a port. It does not patch, fix, or
    remove a vulnerability (spec §1, §13, §16).
    """

    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id"), nullable=True
    )

    target_address: Mapped[str] = mapped_column(String(45), index=True)
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")
    # Owning user. `operator` remains the attribution string; user_id is the
    # authorization/ownership key every read path filters on.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)

    backend: Mapped[str] = mapped_column(String(16))  # dryrun | nftables | ufw
    action: Mapped[str] = mapped_column(String(32), default="isolate_port")

    # Both stored as argv arrays BEFORE anything is applied.
    apply_argv: Mapped[list[str]] = mapped_column(JSON)
    rollback_argv: Mapped[list[str]] = mapped_column(JSON)
    rule_tag: Mapped[str] = mapped_column(String(64), index=True)

    # planned | awaiting_confirmation | applied | rolled_back | failed | expired
    state: Mapped[str] = mapped_column(String(32), default="planned")

    # Full ALLOW / DENY / REVIEW_REQUIRED decision record, every rule and reason.
    decision: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    operator: Mapped[str] = mapped_column(String(64), default="operator")

    planned_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Verification evidence — port state only. See backend/verification/.
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    rollback_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    exposure_reduced: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    rollback_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Anti-lockout evidence: was the management channel still reachable after
    # the action? (spec §14, §16)
    management_channel_intact: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ---------------------------------------------------------------------------
# 7. Audit logs
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """Reserved queryable mirror of data/audit.jsonl (spec §17, entity 7).

    The JSONL file is the authoritative hash-chained record and is the ONLY
    audit source read at runtime: the dashboard and /audit page load it via
    `backend.core.audit.AuditLog` (a different class of the same name) and
    re-verify the chain on every read. This table is defined so the schema
    matches the spec's entity list and so a future indexed-query path can be
    added, but it is intentionally not populated yet — nothing writes to it.
    Do not read it as a data source; it will be empty.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    timestamp: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


# ---------------------------------------------------------------------------
# Background jobs (infrastructure, not a spec entity)
# ---------------------------------------------------------------------------


class Job(Base):
    """Background work item. DB-backed so state survives a restart."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Owning operator, so one user's background-job activity and result summaries
    # are not visible to another. Nullable for system jobs and legacy rows.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="queued")
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# 8. Operators (authentication)
# ---------------------------------------------------------------------------


class User(Base):
    """An operator account.

    Only a bcrypt hash is stored. There is no column capable of holding a
    plaintext password, and no code path that logs `password_hash`.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Email address. Unique when present; nullable so accounts created before the
    # column existed remain valid. SQLite treats multiple NULLs as distinct, so
    # the unique index does not force a value onto legacy rows.
    email: Mapped[str | None] = mapped_column(String(254), unique=True, index=True, nullable=True)
    # bcrypt output, always 60 chars. Never rendered in a template or logged.
    password_hash: Mapped[str] = mapped_column(String(128))
    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Consecutive failures since the last success. Used only for throttling.
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserSession(Base):
    """A logged-in browser session.

    The cookie carries an opaque random token; only its SHA-256 is stored, so a
    stolen database does not yield usable session cookies. Sessions live in the
    database rather than a signed cookie so that logout is a real revocation and
    so no additional dependency is required.
    """

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Recorded for the audit trail. Never used for authentication decisions.
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_host: Mapped[str | None] = mapped_column(String(45), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class PasswordResetToken(Base):
    """A single-use, short-lived password-reset credential.

    Same storage rule as UserSession: the emailed link carries an opaque random
    token and only its SHA-256 is stored, so a stolen database yields no usable
    reset links. A row is spent by setting `used_at`; it is never reused.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    # Set when the token is redeemed OR superseded by a newer request.
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Recorded for the audit trail. Never used for authorization decisions.
    client_host: Mapped[str | None] = mapped_column(String(45), nullable=True)


# ---------------------------------------------------------------------------
# 9. Per-user authorized targets
# ---------------------------------------------------------------------------


class Target(Base):
    """A scan target a user has authorized for their own account.

    This is the per-user layer of the scope model. The install-wide
    `config/authorized_targets.yaml` remains the SAFETY CEILING (it defines the
    laboratory and any public opt-in, and still gates every scan); this table
    records which private targets each operator has personally added and
    confirmed. A target is scannable by a user only if it is in this table for
    that user AND it passes the install-wide safety checks. Adding a row here
    never widens the ceiling — it cannot authorize a public range, and is_lab
    stays false for anything added through the UI.
    """

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("user_id", "cidr", name="uq_target_per_user"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    name: Mapped[str] = mapped_column(String(64))
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    # UI-added targets are always assessment-only (is_lab stays False); only a
    # deliberate config edit can mark a range as a remediable lab target.
    is_lab: Mapped[bool] = mapped_column(Boolean, default=False)

    ssh_host: Mapped[str | None] = mapped_column(String(253), nullable=True)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_user: Mapped[str | None] = mapped_column(String(64), nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped["User"] = relationship()
