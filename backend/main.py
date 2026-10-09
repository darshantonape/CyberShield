"""CyberShield backend entry point.

Run with:
    uvicorn backend.main:app --reload --port 8000

Only endpoints backed by working implementations are registered. Routes for
scanning, correlation and remediation execution appear as those milestones land;
there are deliberately no placeholder endpoints returning invented data.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from backend.auth.middleware import AuthenticationMiddleware
from backend.auth.routes import router as auth_router
from backend.auth.service import purge_expired_sessions
from backend.core.audit import AuditLog
from backend.core.authorization import AuthorizationDenied, check_in_scope
from backend.core.errors import scope_refusal
from backend.core.config import (
    DATA_DIR,
    PROJECT_ROOT,
    ConfigError,
    load_authorization,
    load_config,
)
from backend.database.models import (
    CveRecord,
    RemediationAction,
    DiscoveredHost,
    DiscoveredService,
    ScanSession,
    SoftwareSignature,
    Vulnerability,
)
from backend.database.session import init_db, session_scope
from backend.jobs.runner import get_runner, reap_stale_jobs
from backend.nvd.pipeline import run_correlation
from backend.remediation.executor import (
    ExecutionError,
    TtlWatchdog,
    apply_plan,
    rollback,
    sweep_expired,
)
from backend.remediation.plan import PlanError, build_plan
from backend.risk.decision import IsolationRequest, evaluate
from backend.core.netinfo import detect_local_interfaces
# Scope administration for the shared, install-wide config scope. The
# add/remove helpers here write config/authorized_targets.yaml and are no
# longer reachable from the web layer: per-operator targets go through
# backend.core.user_targets instead, and editing the shared scope is a
# deliberate file edit. Only the read-side helpers are imported.
from backend.core.scope_admin import (
    describe_target_scope,
    suggest_scope_entries,
)
from backend.scanner.pipeline import run_discovery, run_service_detection
from backend.web.views import router as web_router

FRONTEND_DIR = PROJECT_ROOT / "frontend"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
audit_log = AuditLog(DATA_DIR / "audit.jsonl")
# In-process TTL timers do not survive a restart, so the lifespan hook also
# sweeps actions that expired while the process was down.
_watchdog = TtlWatchdog()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    # Jobs left in flight by a previous process must not read as still running.
    reap_stale_jobs()
    purge_expired_sessions()
    try:
        reverted = sweep_expired(load_config())
        if reverted:
            print(f'TTL sweep rolled back {len(reverted)} expired isolation(s).')
    except ConfigError:
        pass  # preflight and /api/safety/status report configuration problems
    yield
    _watchdog.shutdown()
    get_runner().shutdown()


app = FastAPI(
    title="CyberShield",
    description=(
        "Lightweight vulnerability scanner with controlled, reversible "
        "network-level exposure reduction. Authorized laboratory use only."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Authentication gate. Registered as middleware rather than as a dependency on
# each route so that a route added later is protected by default: the exemption
# list in backend/auth/middleware.py is short and explicit, and everything not
# on it requires a session. Unauthenticated HTML requests redirect to /login;
# unauthenticated /api/* requests get 401 JSON.
app.add_middleware(AuthenticationMiddleware)

# Login, signup, logout. The only routes reachable without a session.
app.include_router(auth_router)

# Server-rendered dashboard (spec §18). Registered after the API routes so
# /api/* is matched first.
app.include_router(web_router)


def _actor(request: Request) -> str:
    """Username for the audit trail.

    Every mutating endpoint records who asked. "unauthenticated" can only ever
    appear for a public route, since the middleware refuses everything else.
    """
    user = getattr(request.state, "user", None)
    return user.username if user is not None else "unauthenticated"


def _uid(request: Request) -> int:
    """The authenticated user's id, from the session — never from the request body.

    Every user-scoped API query filters on this, so changing an id in a URL or
    payload cannot reach another operator's data.
    """
    user = getattr(request.state, "user", None)
    if user is None:  # unreachable behind the auth middleware; fail closed
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user.id


# ---------------------------------------------------------------------------
# Health and safety status
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "cybershield", "version": app.version}


@app.get("/api/safety/status")
def safety_status() -> dict[str, Any]:
    """Report the active safety posture.

    Surfaced on the dashboard so the operator can see at a glance whether live
    enforcement is armed and what scope is loaded.
    """
    authorization = load_authorization()

    try:
        config = load_config()
    except ConfigError as exc:
        return {
            "config_loaded": False,
            "config_error": str(exc),
            "authorization_signed": authorization.is_valid,
            "authorization_problems": list(authorization.problems),
        }

    return {
        "config_loaded": True,
        "config_hash": config.config_hash,
        "authorization_signed": authorization.is_valid,
        "authorization_problems": list(authorization.problems),
        "authorized_targets": [
            {
                "name": t.name,
                "range": str(t.target),
                "is_lab": t.is_lab,
                "ssh_port": t.ssh_port,
            }
            for t in config.authorized_targets
        ],
        "protected_ports": [
            {"port": p.port, "proto": p.proto, "reason": p.reason}
            for p in config.protected_ports
        ],
        "protect_active_management_channel": config.protect_active_management_channel,
        "remediation_backend": config.settings.remediation_backend,
        "live_remediation_enabled": config.settings.live_remediation_enabled,
        "remediation_ttl_minutes": config.settings.remediation_ttl_minutes,
        "minimum_severity_for_eligibility": config.minimum_severity_for_eligibility,
        "minimum_confidence_for_eligibility": config.minimum_confidence_for_eligibility,
        "nvd_api_key_configured": config.settings.nvd_api_key is not None,
    }


# ---------------------------------------------------------------------------
# Authorized targets (scope management)
# ---------------------------------------------------------------------------


class AuthorizeTargetRequest(BaseModel):
    """A request to bring a private IPv4 target into scope.

    Note what is absent: no `is_lab`, no `allow_public`, no `force`. A target
    authorized here is assessment-only, and a routable address cannot be
    authorized through this endpoint at all. Both require a deliberate edit to
    config/authorized_targets.yaml.
    """

    target: str = Field(..., description="Private IPv4 address or CIDR, e.g. 192.168.1.25")
    name: str = Field("", description="Optional label used in reports.")
    notes: str = Field("", description="Optional free text recorded in the manifest.")
    confirm: bool = Field(
        False,
        description=(
            "Must be true. The operator's explicit statement that they own this "
            "target or hold written permission to assess it."
        ),
    )


@app.get("/api/targets")
def list_targets(request: Request) -> dict[str, Any]:
    """The caller's own authorized targets, plus the shared install-wide scope.

    Per-user, matching the console: `your_targets` are private to this account;
    `shared_scope` is the install-wide config scope (lab and admin-authorized
    ranges) that every operator shares. Suggestions are informational —
    detecting a subnet authorizes nothing.
    """
    from backend.core.user_targets import list_user_targets

    uid = _uid(request)
    your_targets = list_user_targets(uid)
    try:
        config = load_config()
        shared = describe_target_scope(config)
        interfaces = [i.to_dict() for i in detect_local_interfaces()]
        suggestions = suggest_scope_entries(config)
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    return {
        "your_targets": [
            {
                "id": t["id"], "name": t["name"], "cidr": t["cidr"],
                "is_lab": t["is_lab"], "notes": t["notes"],
            }
            for t in your_targets
        ],
        "shared_scope": shared,
        "local_interfaces": interfaces,
        "suggestions": suggestions,
        "note": (
            "A target is scanned only if it is in your own authorized targets or "
            "the shared scope. Being reachable, or on the same network, is never "
            "sufficient."
        ),
    }


@app.post("/api/targets", status_code=201)
def authorize_target(body: AuthorizeTargetRequest, request: Request) -> dict[str, Any]:
    """Add a private IPv4 address or range to THIS operator's authorized scope."""
    from backend.core.user_targets import UserTargetError, add_user_target

    actor = _actor(request)
    try:
        change = add_user_target(
            _uid(request),
            body.target,
            name=body.name,
            notes=body.notes,
            confirmed=body.confirm,
        )
    except UserTargetError as exc:
        audit_log.record(
            "scope.target_refused", outcome="refused", actor=actor,
            detail={"target": body.target, "reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_log.record(
        "scope.target_authorized", outcome="success", actor=actor,
        detail={"target": change["cidr"], "name": change["name"], "is_lab": False},
    )
    return {
        "authorized": change,
        "is_lab": False,
        "note": (
            "This target may now be scanned under your account. Firewall "
            "remediation is refused on it: only laboratory targets configured "
            "with is_lab: true and SSH details can be modified."
        ),
    }


# `{identifier:path}` and not `{identifier}`: a CIDR contains a slash, and a
# plain path parameter matches a single segment only. DELETE
# /api/targets/192.168.1.77/32 therefore matched no route and returned 404 —
# so the "or CIDR" half of this endpoint's contract did not work at all, in raw
# or percent-encoded form. Names still match as before.
@app.delete("/api/targets/{identifier:path}")
def revoke_target(identifier: str, request: Request) -> dict[str, Any]:
    """Remove one of the caller's own targets, by its name or CIDR.

    Scoped to the caller: a user can only ever remove their own targets. The
    shared/config scope is not editable here — that is a deliberate file edit.
    """
    from backend.core.user_targets import (
        UserTargetError,
        list_user_targets,
        remove_user_target,
    )

    uid = _uid(request)
    match = next(
        (t for t in list_user_targets(uid)
         if identifier in (t["name"], t["cidr"])),
        None,
    )
    if match is None:
        raise HTTPException(
            status_code=404,
            detail=f"No target {identifier!r} in your account.",
        )
    try:
        change = remove_user_target(uid, match["id"])
    except UserTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_log.record(
        "scope.target_revoked", outcome="success", actor=_actor(request),
        detail={"target": change["cidr"]},
    )
    return {"revoked": change}


# ---------------------------------------------------------------------------
# Scans  (spec §19)
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str = Field(..., description="IPv4 address or CIDR range, already in scope.")
    # A profile NAME, never raw Nmap flags. Unknown names are rejected below.
    profile: str | None = Field(None, description="Profile from config/scan_profiles.yaml.")
    kind: str = Field("service_detect", description="'discovery' or 'service_detect'.")


@app.post("/api/scans", status_code=202)
def create_scan(body: ScanRequest, request: Request) -> dict[str, Any]:
    """Queue a scan and return its job id.

    Scope is checked synchronously so an unauthorized target is refused
    immediately with 403, rather than being accepted and failing later in a
    background job where the operator might not notice.
    """
    try:
        config = load_config()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    if body.kind not in ("discovery", "service_detect"):
        raise HTTPException(
            status_code=400, detail="kind must be 'discovery' or 'service_detect'."
        )

    if body.profile is not None and body.profile not in config.scan_profiles:
        known = ", ".join(sorted(config.scan_profiles))
        raise HTTPException(
            status_code=400, detail=f"Unknown profile {body.profile!r}. Available: {known}."
        )

    actor = _actor(request)
    uid = _uid(request)
    from backend.core.user_targets import user_target_pairs

    user_targets = user_target_pairs(uid)
    decision = check_in_scope(config, body.target, user_targets=user_targets)
    if not decision.allowed:
        audit_log.record(
            "scan.refused",
            outcome="refused",
            actor=actor,
            detail={"target": body.target, "reason": decision.reason},
        )
        friendly = scope_refusal(
            body.target,
            decision.reason,
            [str(t.target) for t in config.authorized_targets] + [c for _, c in user_targets],
        )
        # 403 with both the explanation and the original reason: a script gets
        # a machine-readable message, an operator gets an actionable one.
        raise HTTPException(status_code=403, detail=friendly.to_dict())

    runner = get_runner()
    if body.kind == "discovery":
        job_id = runner.submit(
            "scan.discovery",
            run_discovery,
            payload={"target": body.target, "kind": body.kind, "profile": body.profile},
            owner_id=uid,
            config=config,
            target_spec=body.target,
            profile_name=body.profile,
            actor=actor,
            user_id=uid,
            authorized_user_targets=user_targets,
        )
    else:
        job_id = runner.submit(
            "scan.service_detect",
            run_service_detection,
            payload={"target": body.target, "kind": body.kind, "profile": body.profile},
            owner_id=uid,
            config=config,
            target_spec=body.target,
            profile_name=body.profile,
            actor=actor,
            user_id=uid,
            authorized_user_targets=user_targets,
        )

    return {"job_id": job_id, "state": "queued", "target": body.target, "kind": body.kind}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, request: Request) -> dict[str, Any]:
    uid = _uid(request)
    status = get_runner().status(job_id)
    # Owner-scoped: another user's job id is indistinguishable from a missing one,
    # so a job's state and result summary never leak across accounts.
    if status is None or status.get("user_id") != uid:
        raise HTTPException(status_code=404, detail=f"No job {job_id!r}.")
    return status


@app.get("/api/scans")
def list_scans(request: Request, limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    uid = _uid(request)
    with session_scope() as db:
        rows = (
            db.query(ScanSession)
            .filter(ScanSession.user_id == uid)
            .order_by(ScanSession.started_at.desc()).limit(limit).all()
        )
        return {
            "count": len(rows),
            "scans": [
                {
                    "session_id": r.session_id,
                    "target": r.target_spec,
                    "profile": r.profile,
                    "scan_kind": r.scan_kind,
                    "status": r.status,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "duration_seconds": r.duration_seconds,
                    "nmap_version": r.nmap_version,
                    "config_hash": r.config_hash,
                    "initiated_by": r.initiated_by,
                    "hosts_up": r.hosts_up,
                    "open_services": r.open_services,
                    # An authorized target that answered nothing is reported as
                    # unreachable, never as a host with no findings.
                    "reachability": r.reachability,
                    "reachability_note": r.reachability_note,
                    "error": r.error,
                }
                for r in rows
            ],
        }


@app.get("/api/scans/{session_id}")
def get_scan(session_id: str, request: Request) -> dict[str, Any]:
    uid = _uid(request)
    with session_scope() as db:
        scan = db.query(ScanSession).filter_by(session_id=session_id, user_id=uid).one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail=f"No scan {session_id!r}.")

        hosts = db.query(DiscoveredHost).filter_by(session_id=scan.id).all()
        host_payload = []
        for host in hosts:
            services = db.query(DiscoveredService).filter_by(host_id=host.id).all()
            host_payload.append(
                {
                    "address": host.address,
                    "hostname": host.hostname,
                    "state": host.state,
                    "services": [_service_dict(s) for s in services],
                }
            )

        return {
            "session_id": scan.session_id,
            "target": scan.target_spec,
            "profile": scan.profile,
            "scan_kind": scan.scan_kind,
            "status": scan.status,
            "duration_seconds": scan.duration_seconds,
            "nmap_version": scan.nmap_version,
            "nmap_argv": scan.nmap_argv,
            "config_hash": scan.config_hash,
            "raw_xml_path": scan.raw_xml_path,
            "initiated_by": scan.initiated_by,
            "hosts_up": scan.hosts_up,
            "open_services": scan.open_services,
            "reachability": scan.reachability,
            "reachability_note": scan.reachability_note,
            "error": scan.error,
            "hosts": host_payload,
        }


def _service_dict(service: DiscoveredService) -> dict[str, Any]:
    return {
        "id": service.id,
        "port": service.port,
        "protocol": service.proto,
        "state": service.state,
        "service": service.service_name,
        "product": service.product,
        "version": service.version,
        "extra_info": service.extra_info,
        "nmap_confidence": service.nmap_confidence,
        "nmap_cpes": service.nmap_cpes,
        # Explicitly surfaced: "unknown" version is not the same as "no
        # vulnerability", and the UI must be able to say so.
        "version_confidence": service.version_confidence,
        "identification_status": service.identification_status,
    }


@app.get("/api/hosts")
def list_hosts(request: Request, limit: int = 200) -> dict[str, Any]:
    limit = max(1, min(limit, 1000))
    uid = _uid(request)
    with session_scope() as db:
        rows = (
            db.query(DiscoveredHost)
            .filter(DiscoveredHost.user_id == uid)
            .order_by(DiscoveredHost.id.desc()).limit(limit).all()
        )
        return {
            "count": len(rows),
            "hosts": [
                {
                    "id": h.id,
                    "address": h.address,
                    "hostname": h.hostname,
                    "state": h.state,
                    "mac_address": h.mac_address,
                    "session_id": h.session_id,
                }
                for h in rows
            ],
        }


@app.get("/api/services")
def list_services(request: Request, open_only: bool = True, limit: int = 500) -> dict[str, Any]:
    limit = max(1, min(limit, 2000))
    uid = _uid(request)
    with session_scope() as db:
        query = db.query(DiscoveredService).filter(DiscoveredService.user_id == uid)
        if open_only:
            query = query.filter(DiscoveredService.state == "open")
        rows = query.order_by(DiscoveredService.id.desc()).limit(limit).all()

        payload = []
        for service in rows:
            host = db.get(DiscoveredHost, service.host_id)
            entry = _service_dict(service)
            entry["host"] = host.address if host else None
            payload.append(entry)

        return {"count": len(payload), "open_only": open_only, "services": payload}


# ---------------------------------------------------------------------------
# Vulnerabilities  (spec §19)
# ---------------------------------------------------------------------------


@app.post("/api/scans/{session_id}/correlate", status_code=202)
def correlate_scan(session_id: str, request: Request) -> dict[str, Any]:
    """Queue CVE correlation for a completed scan."""
    try:
        config = load_config()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    uid = _uid(request)
    with session_scope() as db:
        scan = db.query(ScanSession).filter_by(session_id=session_id, user_id=uid).one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail=f"No scan {session_id!r}.")
        if scan.status == "failed":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Scan {session_id!r} failed and produced no results, so "
                    "there is nothing to correlate. Re-run the scan."
                ),
            )
        if not scan.status.startswith("completed"):
            raise HTTPException(
                status_code=409,
                detail=f"Scan {session_id!r} is {scan.status!r}; correlate a completed scan.",
            )

    job_id = get_runner().submit(
        "correlation",
        run_correlation,
        payload={"session_id": session_id},
        config=config,
        session_id=session_id,
        actor=_actor(request),
        owner_id=uid,
        user_id=uid,
    )
    return {"job_id": job_id, "state": "queued", "session_id": session_id}


def _vulnerability_dict(
    vuln: Vulnerability, cve: CveRecord | None, service: DiscoveredService | None,
    host: DiscoveredHost | None,
) -> dict[str, Any]:
    return {
        "id": vuln.id,
        "cve_id": vuln.cve_id,
        "host": host.address if host else None,
        "port": service.port if service else None,
        "protocol": service.proto if service else None,
        "detected_product": vuln.detected_product,
        "detected_version": vuln.detected_version,
        # Spec §9/§11: how it matched and how much to trust it, always together.
        "matching_method": vuln.matching_method,
        "confidence": vuln.confidence,
        "status": vuln.status,
        # Spec §10: score and its CVSS version are never separated.
        "cvss_version": cve.cvss_version if cve else None,
        "base_score": cve.base_score if cve else None,
        "severity": cve.base_severity if cve else None,
        "vector_string": cve.vector_string if cve else None,
        "description": cve.description if cve else None,
        "cwe_ids": cve.cwe_ids if cve else None,
        "nvd_reference": vuln.nvd_reference,
        "evidence": vuln.evidence,
        "caveats": vuln.caveats,
        # Surfaced explicitly so the UI can mark probable false positives.
        "probable_false_positive": (vuln.evidence or {}).get("vulnerable_match_count") == 0,
    }


@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    request: Request,
    severity: str | None = None,
    confidence: str | None = None,
    exclude_probable_false_positives: bool = False,
    limit: int = 500,
) -> dict[str, Any]:
    limit = max(1, min(limit, 2000))
    uid = _uid(request)
    with session_scope() as db:
        query = db.query(Vulnerability).filter(Vulnerability.user_id == uid)
        if confidence:
            query = query.filter(Vulnerability.confidence == confidence.upper())
        # The severity and false-positive filters below cannot be expressed in
        # SQL here (severity lives on the joined CVE record, and the FP flag is
        # derived from a JSON column), so `limit` is applied AFTER them rather
        # than in the query. Applying it first took the newest `limit` rows and
        # then filtered those, so `?severity=CRITICAL&limit=50` returned only
        # the criticals that happened to fall in the newest 50 findings — and
        # reported that as the count.
        rows = query.order_by(Vulnerability.id.desc()).all()

        payload = []
        for vuln in rows:
            if len(payload) >= limit:
                break
            cve = db.get(CveRecord, vuln.cve_id)
            if severity and (not cve or cve.base_severity != severity.upper()):
                continue
            service = db.get(DiscoveredService, vuln.service_id)
            host = db.get(DiscoveredHost, service.host_id) if service else None
            entry = _vulnerability_dict(vuln, cve, service, host)
            if exclude_probable_false_positives and entry["probable_false_positive"]:
                continue
            payload.append(entry)

        return {
            "count": len(payload),
            "note": (
                "All entries are CVE candidates. A version string resembling a "
                "CVE's affected software is not proof of vulnerability or "
                "exploitability; no exploitation is attempted."
            ),
            "vulnerabilities": payload,
        }


@app.get("/api/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: int, request: Request) -> dict[str, Any]:
    uid = _uid(request)
    with session_scope() as db:
        vuln = db.get(Vulnerability, vulnerability_id)
        if vuln is None or vuln.user_id != uid:
            raise HTTPException(status_code=404, detail=f"No vulnerability {vulnerability_id}.")

        cve = db.get(CveRecord, vuln.cve_id)
        service = db.get(DiscoveredService, vuln.service_id)
        host = db.get(DiscoveredHost, service.host_id) if service else None

        payload = _vulnerability_dict(vuln, cve, service, host)
        if service:
            signatures = db.query(SoftwareSignature).filter_by(service_id=service.id).all()
            payload["signatures"] = [
                {
                    "vendor": s.vendor,
                    "product": s.product,
                    "version": s.version,
                    "cpe23": s.cpe23,
                    "mapping_source": s.mapping_source,
                    "confidence": s.confidence,
                    "notes": s.notes,
                }
                for s in signatures
            ]
            payload["version_confidence"] = service.version_confidence
            payload["identification_status"] = service.identification_status
        return payload


# ---------------------------------------------------------------------------
# Remediation preview  (spec §19: POST /api/remediation/preview)
# ---------------------------------------------------------------------------


class PreviewRequest(BaseModel):
    """Note the absence of any override field. There is no `force` (spec §6B)."""

    target_address: str = Field(..., description="IPv4 address of the lab target.")
    port: int = Field(..., ge=1, le=65535)
    proto: str = Field("tcp")
    max_severity: str | None = Field(
        None, description="Highest CVE candidate severity: LOW|MEDIUM|HIGH|CRITICAL."
    )
    max_confidence: str | None = Field(
        None, description="Best correlation confidence: LOW|MEDIUM|HIGH."
    )
    vulnerability_id: int | None = None


def _isolation_request(body: "PreviewRequest | ApplyRequest") -> IsolationRequest:
    return IsolationRequest(
        target_address=body.target_address,
        port=body.port,
        proto=body.proto,
        max_severity=body.max_severity,
        max_confidence=body.max_confidence,
        vulnerability_id=body.vulnerability_id,
    )


class ApplyRequest(PreviewRequest):
    """Note what is absent: no force, override, or skip-checks field.

    `confirm` is not an override — it is the mandatory human acknowledgement
    required by spec §13.6. It cannot turn a DENY into an ALLOW; the executor
    refuses any verdict other than ALLOW regardless of its value.
    """

    confirm: bool = Field(
        False, description="Must be true. Explicit operator confirmation."
    )


@app.post("/api/remediation/apply", status_code=201)
def remediation_apply(body: ApplyRequest, request: Request) -> dict[str, Any]:
    """Apply a controlled, reversible isolation, then verify by rescanning."""
    try:
        config = load_config()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Refusing to apply: 'confirm' must be true. There is no "
                   "automatic remediation path.",
        )

    try:
        plan = build_plan(config, _isolation_request(body), vulnerability_id=body.vulnerability_id)
    except PlanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not plan.allowed:
        # A refusal is part of the safety record, so it is logged before the
        # response is raised. Without this, only successful actions appeared in
        # the audit trail and a series of blocked attempts left no trace.
        audit_log.record(
            "remediation.refused",
            outcome="refused",
            actor=_actor(request),
            detail={
                "target_address": plan.target_address,
                "port": plan.port,
                "proto": plan.proto,
                "verdict": plan.decision.verdict.value,
                "reason": plan.decision.blocking_reason,
            },
        )
        # 409, not 403: the request is well-formed and authenticated, but the
        # target's current state and policy make it ineligible.
        raise HTTPException(
            status_code=409,
            detail={
                "verdict": plan.decision.verdict.value,
                "reason": plan.decision.blocking_reason,
                "rules": [r.to_dict() for r in plan.decision.rules],
            },
        )

    try:
        outcome = apply_plan(
            config, plan, confirmed=True, watchdog=_watchdog,
            actor=_actor(request), user_id=_uid(request),
        )
    except (ExecutionError, AuthorizationDenied) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "request_id": outcome.request_id,
        "state": outcome.state,
        "plan": plan.to_dict(),
        "verification": outcome.verification,
        "target_firewall_state": outcome.target_firewall_state,
        "summary": outcome.summary(),
    }


@app.post("/api/remediation/{request_id}/rollback")
def remediation_rollback(request_id: str, request: Request) -> dict[str, Any]:
    """Revert an applied isolation and verify the port is reachable again."""
    try:
        config = load_config()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    uid = _uid(request)
    with session_scope() as db:
        owned = (
            db.query(RemediationAction)
            .filter_by(request_id=request_id, user_id=uid)
            .one_or_none()
        )
    if owned is None:
        raise HTTPException(status_code=404, detail=f"No remediation action {request_id!r}.")

    _watchdog.cancel(request_id)
    try:
        return rollback(config, request_id, actor=_actor(request), user_id=uid)
    except ExecutionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/remediation")
def list_remediation(request: Request, limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    uid = _uid(request)
    with session_scope() as db:
        rows = (
            db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid)
            .order_by(RemediationAction.id.desc())
            .limit(limit)
            .all()
        )
        return {
            "count": len(rows),
            "note": (
                "Isolation reduces network exposure. It does not patch or remove "
                "the underlying vulnerability, and the service keeps running."
            ),
            "actions": [
                {
                    "request_id": r.request_id,
                    "target": r.target_address,
                    "port": r.port,
                    "proto": r.proto,
                    "backend": r.backend,
                    "state": r.state,
                    "apply_command": " ".join(r.apply_argv or []),
                    "rollback_command": " ".join(r.rollback_argv or []),
                    "exposure_reduced": r.exposure_reduced,
                    "rollback_verified": r.rollback_verified,
                    "management_channel_intact": r.management_channel_intact,
                    "planned_at": r.planned_at.isoformat() if r.planned_at else None,
                    "applied_at": r.applied_at.isoformat() if r.applied_at else None,
                    "rolled_back_at": r.rolled_back_at.isoformat() if r.rolled_back_at else None,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "before_state": r.before_state,
                    "after_state": r.after_state,
                    "error": r.error,
                }
                for r in rows
            ],
        }


@app.post("/api/remediation/preview")
def remediation_preview(body: PreviewRequest, request: Request) -> dict[str, Any]:
    """Evaluate an isolation request without applying anything.

    This is read-only: it runs the decision chain and returns the verdict with
    every rule's reasoning. Nothing is written to the target.
    """
    try:
        config = load_config()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=f"Configuration error: {exc}") from exc

    decision = evaluate(
        config,
        IsolationRequest(
            target_address=body.target_address,
            port=body.port,
            proto=body.proto,
            max_severity=body.max_severity,
            max_confidence=body.max_confidence,
            vulnerability_id=body.vulnerability_id,
        ),
    )

    audit_log.record(
        "remediation.preview",
        outcome="success",
        actor=_actor(request),
        detail={"decision": decision.to_dict()},
    )

    return {"decision": decision.to_dict(), "summary": decision.summary()}


# ---------------------------------------------------------------------------
# Audit  (spec §19: GET /api/audit)
# ---------------------------------------------------------------------------


@app.get("/api/audit")
def get_audit(request: Request, limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 1000))
    username = _actor(request)
    # Chain verification runs over the whole install-wide log (a hash chain is
    # only meaningful entire); the returned entries are this operator's own.
    verification = audit_log.verify_chain()
    entries = [e for e in audit_log.entries() if e.actor == username]
    return {
        "chain_valid": verification.valid,
        "chain_message": verification.message,
        "entries_total": len(entries),
        "entries": [e.to_dict() for e in entries[-limit:]][::-1],
    }


@app.get("/api/audit/verify")
def verify_audit() -> dict[str, Any]:
    result = audit_log.verify_chain()
    return {
        "valid": result.valid,
        "entries_checked": result.entries_checked,
        "first_invalid_sequence": result.first_invalid_sequence,
        "message": result.message,
    }
