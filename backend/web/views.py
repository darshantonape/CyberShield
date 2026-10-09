"""Server-rendered dashboard (spec §18).

Plain Jinja2 over the same code paths the JSON API uses — no separate build
step, no vendored JS framework, nothing fetched from a CDN.

Every page is written so a reader cannot mistake a candidate for a confirmed
vulnerability, or exposure reduction for a patch. That wording is part of the
deliverable, not decoration.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from backend.core.audit import AuditLog
from backend.core.config import (
    DATA_DIR,
    PROJECT_ROOT,
    ConfigError,
    load_authorization,
    load_config,
)
from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    Job,
    RemediationAction,
    ScanSession,
    SoftwareSignature,
    Vulnerability,
)
from backend.core.errors import explain, scope_refusal
# Scope administration for the shared, install-wide config scope. The
# add/remove helpers here write config/authorized_targets.yaml and are no
# longer reachable from the web layer: per-operator targets go through
# backend.core.user_targets instead, and editing the shared scope is a
# deliberate file edit. Only the read-side helpers are imported.
from backend.core.scope_admin import (
    describe_target_scope,
    suggest_scope_entries,
)
from backend.database.session import session_scope
from backend.core.user_targets import (
    UserTargetError,
    add_user_target,
    list_user_targets,
    remove_user_target,
    user_target_pairs,
)
from backend.risk.decision import IsolationRequest, evaluate
from backend.scanner.reachability import LAN_UNREACHABLE_CAUSES

router = APIRouter()
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))
audit_log = AuditLog(DATA_DIR / "audit.jsonl")

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _safety() -> dict[str, Any]:
    """Context every template needs for the banner. Never raises."""
    authorization = load_authorization()
    base: dict[str, Any] = {
        "authorization_signed": authorization.is_valid,
        "authorized_targets": [],
        "protected_ports": [],
        "live_remediation_enabled": False,
        "remediation_backend": "unknown",
        "remediation_ttl_minutes": 0,
    }
    try:
        config = load_config()
    except ConfigError:
        return base

    base.update(
        {
            "authorized_targets": [
                {"name": t.name, "range": str(t.target), "is_lab": t.is_lab}
                for t in config.authorized_targets
            ],
            "protected_ports": [
                {"port": p.port, "proto": p.proto, "reason": p.reason}
                for p in config.protected_ports
            ],
            "live_remediation_enabled": config.settings.live_remediation_enabled,
            "remediation_backend": config.settings.remediation_backend,
            "remediation_ttl_minutes": config.settings.remediation_ttl_minutes,
        }
    )
    return base


def _my_target_count(request: Request) -> int:
    """How many targets the signed-in operator has authorized themselves.

    The sidebar badge and the dashboard tile both read this. They used to read
    `safety.authorized_targets`, which is the install-wide config scope shared
    by every account — so a brand-new operator with no targets of their own was
    shown "Targets 2", and an operator who added three of their own was still
    shown 2. The number now matches what the Targets page calls "your targets".
    """
    user = getattr(request.state, "user", None)
    if user is None:
        return 0
    try:
        return len(list_user_targets(user.id))
    except Exception:  # noqa: BLE001 - a badge must never break a page
        return 0


def _render(
    request: Request, template: str, page: str, status_code: int = 200, **ctx: Any
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template,
        status_code=status_code,
        context={
            "page": page,
            "safety": _safety(),
            # The operator's own scope size, for the sidebar badge. Distinct
            # from safety.authorized_targets, which is the shared config scope.
            "my_target_count": _my_target_count(request),
            # Set by the authentication middleware. Never None on these routes:
            # an unauthenticated request is redirected before it reaches here.
            "user": getattr(request.state, "user", None),
            **ctx,
        },
    )


def _actor(request: Request) -> str:
    """Operator name recorded against an action taken from the UI."""
    user = getattr(request.state, "user", None)
    return user.username if user is not None else "unauthenticated"


def _uid(request: Request) -> int:
    """The authenticated user's id, from the session — never from a form or URL.

    The middleware guarantees a user on every protected route, so this is the one
    trusted source of "who is asking". Every user-scoped query filters on it.
    """
    user = getattr(request.state, "user", None)
    if user is None:  # unreachable on protected routes; fail closed regardless
        raise RuntimeError("No authenticated user on a protected route.")
    return user.id


def _service_risk(db, service_id: int) -> tuple[int, str | None, str | None, int | None]:
    """Highest severity and confidence among a service's CVE candidates."""
    vulns = db.query(Vulnerability).filter_by(service_id=service_id).all()
    if not vulns:
        return 0, None, None, None

    severities = [
        db.get(CveRecord, v.cve_id).base_severity
        for v in vulns
        if db.get(CveRecord, v.cve_id) is not None
    ]
    severities = [s for s in severities if s in SEVERITY_ORDER]
    max_sev = max(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else None
    max_conf = max((v.confidence for v in vulns), key=lambda c: CONFIDENCE_ORDER[c])
    return len(vulns), max_sev, max_conf, vulns[0].id


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """Public landing page for visitors; the dashboard for signed-in operators.

    `/` is intentionally public (see the auth middleware): an anonymous request
    gets the product overview and sign-in/up calls to action, never any scope,
    finding, or configuration. As soon as a session exists, the same URL is the
    operator's own dashboard.
    """
    if getattr(request.state, "user", None) is None:
        from backend.auth.service import user_count

        return templates.TemplateResponse(
            request=request,
            name="landing.html",
            context={"has_accounts": user_count() > 0},
        )
    return _dashboard(request)


def _dashboard(request: Request) -> HTMLResponse:
    uid = _uid(request)
    username = _actor(request)
    with session_scope() as db:
        actions = (
            db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid)
            .order_by(RemediationAction.id.desc()).limit(10).all()
        )
        # Host and service counts come from the latest ASSESSMENT scan only.
        # Counting every row would include verification rescans, which probe a
        # single port on one host and would inflate the totals — 12 hosts and 18
        # services were reported for a lab that actually has 4 and 12.
        latest_assessment = (
            db.query(ScanSession)
            .filter_by(scan_kind="assessment", user_id=uid)
            .order_by(ScanSession.id.desc())
            .first()
        )
        if latest_assessment is not None:
            host_ids = [
                h.id
                for h in db.query(DiscoveredHost).filter_by(
                    session_id=latest_assessment.id
                )
            ]
            host_count = len(host_ids)
            open_service_count = (
                db.query(DiscoveredService)
                .filter(
                    DiscoveredService.host_id.in_(host_ids),
                    DiscoveredService.state == "open",
                )
                .count()
                if host_ids
                else 0
            )
        else:
            host_count = open_service_count = 0
            host_ids = []

        # CVE statistics must be scoped the same way. Correlating two different
        # scan sessions creates two independent sets of Vulnerability rows, so
        # counting them all double-reported 278 candidates as 556 and 14 flagged
        # false positives as 28.
        service_ids = (
            [
                s.id
                for s in db.query(DiscoveredService).filter(
                    DiscoveredService.host_id.in_(host_ids)
                )
            ]
            if host_ids
            else []
        )
        vulns = (
            db.query(Vulnerability).filter(Vulnerability.service_id.in_(service_ids)).all()
            if service_ids
            else []
        )
        flagged = sum(
            1 for v in vulns if (v.evidence or {}).get("vulnerable_match_count") == 0
        )

        severity_counts: dict[str | None, int] = {}
        cvss_counts: dict[str | None, int] = {}
        for v in vulns:
            cve = db.get(CveRecord, v.cve_id)
            severity_counts[cve.base_severity if cve else None] = (
                severity_counts.get(cve.base_severity if cve else None, 0) + 1
            )
            cvss_counts[cve.cvss_version if cve else None] = (
                cvss_counts.get(cve.cvss_version if cve else None, 0) + 1
            )

        # Scan outcomes across the whole history. Failed and unreachable scans
        # are counted separately and never folded into "completed": a scan that
        # could not read its target is not a scan that found nothing.
        all_scans = db.query(ScanSession).filter(ScanSession.user_id == uid).all()
        completed = sum(1 for r in all_scans if r.status == "completed")
        partial = sum(1 for r in all_scans if r.status == "completed_with_timeouts")
        unreachable = sum(1 for r in all_scans if r.status == "completed_unreachable")
        failed = sum(1 for r in all_scans if r.status == "failed")

        # The operator's OWN authorized targets. Counting the install-wide
        # config scope here meant a new account's dashboard opened on
        # "Authorized targets: 2" before it had authorized anything, and never
        # moved when the operator added targets of their own. The shared config
        # scope is still shown, separately and labelled as shared, on the
        # Targets page.
        authorized_target_count = len(list_user_targets(uid))
        try:
            shared_scope_count = len(load_config().authorized_targets)
        except ConfigError:
            shared_scope_count = 0

        severity_lookup = dict(severity_counts)

        stats = {
            "scan_count": len(all_scans),
            "assessment_session": latest_assessment.session_id if latest_assessment else None,
            "assessment_status": latest_assessment.status if latest_assessment else None,
            "assessment_reachability": (
                latest_assessment.reachability if latest_assessment else None
            ),
            "assessment_reachability_note": (
                latest_assessment.reachability_note if latest_assessment else None
            ),
            "assessment_target": latest_assessment.target_spec if latest_assessment else None,
            "host_count": host_count,
            "open_service_count": open_service_count,
            "vuln_count": len(vulns),
            "flagged_fp_count": flagged,
            "authorized_target_count": authorized_target_count,
            "shared_scope_count": shared_scope_count,
            "completed_count": completed,
            "partial_count": partial,
            "unreachable_count": unreachable,
            "failed_count": failed,
            "critical_count": severity_lookup.get("CRITICAL", 0),
            "high_count": severity_lookup.get("HIGH", 0),
            "medium_count": severity_lookup.get("MEDIUM", 0),
            "low_count": severity_lookup.get("LOW", 0),
            "unscored_count": severity_lookup.get(None, 0),
            "remediation_count": db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid).count(),
            "remediation_applied": db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid, RemediationAction.state == "applied")
            .count(),
            "remediation_rolled_back": db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid, RemediationAction.state == "rolled_back")
            .count(),
            "remediation_failed": db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid, RemediationAction.state == "failed")
            .count(),
            "exposure_reduced_count": db.query(RemediationAction)
            .filter(RemediationAction.user_id == uid, RemediationAction.exposure_reduced.is_(True))
            .count(),
            "severity": sorted(
                severity_counts.items(),
                key=lambda r: -SEVERITY_ORDER.get(r[0] or "", -1),
            ),
            "cvss_versions": sorted(
                cvss_counts.items(), key=lambda r: str(r[0])
            ),
        }
        scans = (
            db.query(ScanSession).filter(ScanSession.user_id == uid)
            .order_by(ScanSession.id.desc()).limit(8).all()
        )

    # Read outside the DB session: the audit log is a file, not a table.
    # Filter to this operator's own actions — one user never sees another's trail.
    recent_events = []
    try:
        own_entries = [e for e in audit_log.entries() if e.actor == username]
        for entry in reversed(own_entries[-8:]):
            recent_events.append(
                {
                    "sequence": entry.sequence,
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "outcome": entry.outcome,
                    "actor": entry.actor,
                    "target": (entry.detail or {}).get("target")
                    or (entry.detail or {}).get("target_address"),
                    "summary_text": _summarise(entry),
                }
            )
    except (OSError, ValueError) as exc:  # a damaged log must not break the page
        recent_events = []
        print(f"warning: could not read audit log for dashboard: {exc}")

    return _render(
        request, "dashboard.html", "dashboard",
        stats=stats, scans=scans, actions=actions, recent_events=recent_events,
    )


# ---------------------------------------------------------------------------
# Authorized targets
# ---------------------------------------------------------------------------


@router.get("/targets", response_class=HTMLResponse)
def targets_page(
    request: Request, message: str | None = None, error: str | None = None
) -> HTMLResponse:
    """Scope management: what is authorized, and what could be.

    The local-network panel exists so the operator can see which subnet this
    machine is actually on — different Wi-Fi networks use different subnets, so
    nothing here is hardcoded. Detection authorizes nothing: every entry still
    has to be added and confirmed.
    """
    from backend.core.netinfo import detect_local_interfaces

    uid = _uid(request)
    my_targets = list_user_targets(uid)

    try:
        config = load_config()
        shared_scope = describe_target_scope(config)
    except ConfigError as exc:
        friendly = explain(exc)
        return _render(
            request, "targets.html", "targets",
            my_targets=my_targets, shared_scope=[], interfaces=[], suggestions=[],
            message=message, error=friendly.to_dict(),
        )

    return _render(
        request, "targets.html", "targets",
        my_targets=my_targets,
        shared_scope=shared_scope,
        interfaces=[i.to_dict() for i in detect_local_interfaces()],
        suggestions=suggest_scope_entries(config),
        message=message,
        error={"title": "Could not update scope", "message": error, "hint": "", "technical": ""}
        if error
        else None,
    )


@router.post("/targets")
def add_target_form(
    request: Request,
    target: str = Form(...),
    name: str = Form(""),
    notes: str = Form(""),
    confirm: str = Form(""),
) -> RedirectResponse:
    """Authorize a private IPv4 address or range for assessment.

    Note what this form cannot do: it cannot authorize a public address, cannot
    set `is_lab`, and cannot skip the confirmation. Those are all enforced in
    `scope_admin`, not here, so the API and the UI share one set of rules.
    """
    actor = _actor(request)
    uid = _uid(request)
    try:
        change = add_user_target(
            uid,
            target,
            name=name,
            notes=notes,
            confirmed=confirm == "yes",
        )
    except UserTargetError as exc:
        audit_log.record(
            "scope.target_refused",
            outcome="refused",
            actor=actor,
            detail={"target": target, "reason": str(exc)},
        )
        return RedirectResponse(f"/targets?error={quote(str(exc))}", status_code=303)

    audit_log.record(
        "scope.target_authorized",
        outcome="success",
        actor=actor,
        detail={"target": change["cidr"], "name": change["name"], "is_lab": False},
    )
    note = (
        f"{change['cidr']} is now authorized for assessment as "
        f"'{change['name']}'. {change['note']}"
    )
    return RedirectResponse(f"/targets?message={quote(note)}", status_code=303)


@router.post("/targets/{target_id}/remove")
def remove_target_form(request: Request, target_id: int) -> RedirectResponse:
    actor = _actor(request)
    try:
        change = remove_user_target(_uid(request), target_id)
    except UserTargetError as exc:
        return RedirectResponse(f"/targets?error={quote(str(exc))}", status_code=303)
    audit_log.record(
        "scope.target_revoked",
        outcome="success",
        actor=actor,
        detail={"target": change["cidr"]},
    )
    return RedirectResponse(f"/targets?message={quote(change['note'])}", status_code=303)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


# Which profiles belong to which kind of scan. Presenting a single flat list
# let the operator pick kind=service_detect with profile=discovery, which ran a
# host-discovery scan and recorded it as an assessment — a scan that found "0
# open services" because it never looked for any. The pairing is now explicit.
DISCOVERY_PROFILE_NAMES = ("discovery", "lan_discovery")


def _profile_options(config) -> dict[str, list[dict[str, Any]]]:
    """Profiles grouped by scan kind, with their description and target advice."""
    advice = {
        "discovery": "Laboratory bridge. Probes the ports the lab targets publish.",
        "lan_discovery": "Real Wi-Fi/LAN. Wider probe set for Windows, macOS and IoT devices.",
        "service_detect": "Laboratory bridge. Explicit port list, host discovery on.",
        "lan_service_detect": (
            "Authorized LAN device. Skips host discovery (-Pn) so a firewalled "
            "laptop is still examined instead of being declared down."
        ),
        "service_detect_full": "All 65535 ports. Very slow; use on one host only.",
    }
    groups: dict[str, list[dict[str, Any]]] = {"discovery": [], "service_detect": []}
    for name, profile in sorted(config.scan_profiles.items()):
        if name == "verify_port":
            # Internal: used by remediation verification, never chosen by hand.
            continue
        kind = "discovery" if name in DISCOVERY_PROFILE_NAMES else "service_detect"
        groups[kind].append(
            {
                "name": name,
                "description": profile.description,
                "advice": advice.get(name, ""),
                "timeout_seconds": profile.timeout_seconds,
                "port_count": _port_count(profile.args),
                "skips_host_discovery": "-Pn" in profile.args,
            }
        )
    return groups


def _port_count(args: tuple[str, ...]) -> int | None:
    """How many ports a profile scans, for display. None when not enumerable."""
    for index, arg in enumerate(args):
        if arg == "-p" and index + 1 < len(args):
            value = args[index + 1]
            if value == "-":
                return 65535
            return len([p for p in value.split(",") if p])
        if arg == "-p-":
            return 65535
    return None


def _authorization_preview(
    config, target: str, user_targets: tuple[tuple[str, str], ...] = ()
) -> dict[str, Any] | None:
    """Pre-scan status for a typed target: authorized or not, and why.

    Reachability is deliberately NOT probed here. Probing a host to render a
    form would mean touching the network before the operator pressed Run, and
    before the scope check has been recorded. It is shown as UNKNOWN until a
    scan actually runs.
    """
    candidate = (target or "").strip()
    if not candidate:
        return None

    from backend.core.authorization import check_in_scope

    decision = check_in_scope(config, candidate, user_targets=user_targets)
    entry = config.find_authorized_target(candidate) if decision.allowed else None
    return {
        "target": candidate,
        "authorized": decision.allowed,
        "reason": decision.reason,
        "authorizing_entry": decision.authorizing_entry,
        "is_lab": bool(entry.is_lab) if entry else False,
        "friendly": None
        if decision.allowed
        else scope_refusal(
            candidate,
            decision.reason,
            [str(t.target) for t in config.authorized_targets] + [c for _, c in user_targets],
        ).to_dict(),
    }


@router.get("/scans", response_class=HTMLResponse)
def scans_page(
    request: Request,
    queued: str | None = None,
    error: str | None = None,
    target: str = "",
    kind: str = "service_detect",
    profile: str = "",
) -> HTMLResponse:
    friendly: dict[str, Any] | None = None
    profile_groups: dict[str, list[dict[str, Any]]] = {"discovery": [], "service_detect": []}
    default_profile = ""
    preview = None
    uid = _uid(request)

    # Everything this operator may scan, in the order they are most likely to
    # want it: their own targets first, then the shared install-wide scope.
    # The page previously offered only `config.authorized_targets`, so a target
    # the operator had just added on the Targets page appeared nowhere on this
    # page and the box stayed pre-filled with the laboratory range — which read
    # as "the lab is the only thing I am allowed to scan".
    my_targets = list_user_targets(uid)
    selectable: list[dict[str, Any]] = [
        {"cidr": t["cidr"], "name": t["name"], "scope": "yours", "is_lab": False}
        for t in my_targets
    ]

    try:
        config = load_config()
        profile_groups = _profile_options(config)
        default_profile = config.default_profile
        selectable += [
            {
                "cidr": str(t.target),
                "name": t.name,
                "scope": "shared",
                "is_lab": t.is_lab,
            }
            for t in config.authorized_targets
        ]
        # The form pre-fills a target the operator can actually scan, so the
        # pre-scan status is computed for that value too. Otherwise the target
        # box showed an address with no authorization verdict beside it until
        # the operator retyped it.
        prefilled = target or (selectable[0]["cidr"] if selectable else "")
        preview = _authorization_preview(config, prefilled, user_target_pairs(uid))
    except ConfigError as exc:
        friendly = explain(exc).to_dict()

    if error:
        # `error` arrives from a redirect after a refused submission. It is
        # already an operator-facing sentence; re-explaining it would double up.
        friendly = explain(error).to_dict()

    with session_scope() as db:
        scans = (
            db.query(ScanSession).filter(ScanSession.user_id == uid)
            .order_by(ScanSession.id.desc()).limit(25).all()
        )
        jobs = db.query(Job).filter(Job.user_id == uid).order_by(Job.id.desc()).limit(6).all()
        running = any(j.state in ("queued", "running") for j in jobs)

        # The most recently finished scan, so the page can show a result summary
        # rather than only a history row.
        last_finished = (
            db.query(ScanSession)
            .filter(ScanSession.user_id == uid, ScanSession.status != "pending")
            .order_by(ScanSession.id.desc())
            .first()
        )
        last_summary = None
        if last_finished is not None:
            last_summary = {
                "session_id": last_finished.session_id,
                "target": last_finished.target_spec,
                "profile": last_finished.profile,
                "scan_kind": last_finished.scan_kind,
                "status": last_finished.status,
                "duration_seconds": last_finished.duration_seconds,
                "hosts_up": last_finished.hosts_up,
                "open_services": last_finished.open_services,
                "reachability": last_finished.reachability,
                "reachability_note": last_finished.reachability_note,
                "error": last_finished.error,
                "started_at": last_finished.started_at,
                "services_detected": _services_identified(db, last_finished.id),
                "vulnerabilities": _vulnerability_count(db, last_finished.id),
            }

        return _render(
            request, "scans.html", "scans",
            scans=scans, jobs=jobs, running=running, queued=queued,
            error=friendly, profile_groups=profile_groups,
            default_profile=default_profile, preview=preview,
            typed_target=target, last_summary=last_summary,
            selectable_targets=selectable,
            # Echoed back so re-rendering after a target change does not silently
            # reset the operator's scan type and profile to the defaults.
            selected_kind=kind if kind in ("discovery", "service_detect") else "service_detect",
            selected_profile=profile,
            unreachable_causes=LAN_UNREACHABLE_CAUSES,
        )


def _services_identified(db, scan_row_id: int) -> int:
    """Open services on which a product was actually identified."""
    host_ids = [h.id for h in db.query(DiscoveredHost).filter_by(session_id=scan_row_id)]
    if not host_ids:
        return 0
    return (
        db.query(DiscoveredService)
        .filter(
            DiscoveredService.host_id.in_(host_ids),
            DiscoveredService.state == "open",
            DiscoveredService.product.isnot(None),
        )
        .count()
    )


def _vulnerability_count(db, scan_row_id: int) -> int:
    """CVE candidates correlated for one scan's services."""
    host_ids = [h.id for h in db.query(DiscoveredHost).filter_by(session_id=scan_row_id)]
    if not host_ids:
        return 0
    service_ids = [
        s.id
        for s in db.query(DiscoveredService).filter(
            DiscoveredService.host_id.in_(host_ids)
        )
    ]
    if not service_ids:
        return 0
    return (
        db.query(Vulnerability)
        .filter(Vulnerability.service_id.in_(service_ids))
        .count()
    )


@router.post("/scans")
def start_scan(
    request: Request,
    target: str = Form(...),
    kind: str = Form("service_detect"),
    profile: str = Form(None),
    correlate_after: str = Form(""),
) -> RedirectResponse:
    from backend.core.authorization import check_in_scope
    from backend.core.user_targets import user_target_pairs
    from backend.jobs.runner import get_runner
    from backend.scanner.pipeline import run_discovery, run_service_detection

    actor = _actor(request)
    uid = _uid(request)
    target = (target or "").strip()

    try:
        config = load_config()
    except ConfigError as exc:
        return RedirectResponse(f"/scans?error={quote(str(exc))}", status_code=303)

    # The operator's own authorized targets, added to the install-wide scope.
    user_targets = user_target_pairs(uid)

    # --- Scope check first. Nothing touches the network before this. ---------
    decision = check_in_scope(config, target, user_targets=user_targets)
    if not decision.allowed:
        audit_log.record(
            "scan.refused",
            outcome="refused",
            actor=actor,
            detail={"target": target, "reason": decision.reason, "source": "console"},
        )
        friendly = scope_refusal(
            target, decision.reason, [str(t.target) for t in config.authorized_targets]
        )
        # Send the operator back with the target still in the form, so they can
        # see the refusal next to what they typed and act on it.
        return RedirectResponse(
            f"/scans?target={quote(target)}&error={quote(friendly.flat())}",
            status_code=303,
        )

    # --- Profile must match the requested kind ------------------------------
    chosen = (profile or "").strip() or None
    if chosen is not None and chosen not in config.scan_profiles:
        return RedirectResponse(
            f"/scans?target={quote(target)}"
            f"&error={quote(f'Unknown scan profile {chosen!r}.')}",
            status_code=303,
        )

    if kind == "discovery":
        if chosen is not None and chosen not in DISCOVERY_PROFILE_NAMES:
            return RedirectResponse(
                f"/scans?target={quote(target)}&error="
                + quote(
                    f"Profile {chosen!r} is not a host-discovery profile. A "
                    "discovery scan does not scan ports, so pairing it with a "
                    "service-detection profile would record a port scan that "
                    "never happened."
                ),
                status_code=303,
            )
        job_id = get_runner().submit(
            "scan.discovery", run_discovery,
            payload={"target": target, "kind": kind, "profile": chosen or "discovery"},
            config=config, target_spec=target, profile_name=chosen, actor=actor,
            owner_id=uid,
            user_id=uid,
            authorized_user_targets=user_targets,
        )
    else:
        if chosen is not None and chosen in DISCOVERY_PROFILE_NAMES:
            return RedirectResponse(
                f"/scans?target={quote(target)}&error="
                + quote(
                    f"Profile {chosen!r} performs host discovery only and scans "
                    "no ports. Selecting it for a service-detection scan would "
                    'report "0 open services" without having looked for any. '
                    "Choose service_detect or lan_service_detect."
                ),
                status_code=303,
            )
        job_id = get_runner().submit(
            "scan.service_detect", run_service_detection,
            payload={
                "target": target,
                "kind": kind,
                "profile": chosen or config.default_profile,
                "correlate_after": correlate_after == "yes",
            },
            config=config, target_spec=target, profile_name=chosen, actor=actor,
            correlate_after=correlate_after == "yes",
            owner_id=uid,
            user_id=uid,
            authorized_user_targets=user_targets,
        )
    return RedirectResponse(f"/scans?queued={job_id}", status_code=303)


@router.get("/scans/{session_id}", response_class=HTMLResponse)
def scan_detail(request: Request, session_id: str) -> HTMLResponse:
    uid = _uid(request)
    with session_scope() as db:
        # Scoped by owner: another user's session id is indistinguishable from a
        # non-existent one, so changing the id in the URL reveals nothing.
        scan = db.query(ScanSession).filter_by(session_id=session_id, user_id=uid).one_or_none()
        if scan is None:
            # 404 like the report pages: a scan that does not exist, and one
            # owned by another operator, are the same answer — and neither is a
            # scan with no content, which is what a 200 claimed.
            return _render(
                request, "scan_detail.html", "scans",
                scan=None, hosts=[], policies={}, status_code=404,
            )

        hosts = []
        for host in db.query(DiscoveredHost).filter_by(session_id=scan.id).order_by(
            DiscoveredHost.address
        ):
            services = (
                db.query(DiscoveredService)
                .filter_by(host_id=host.id)
                .order_by(DiscoveredService.port)
                .all()
            )
            hosts.append({
                "address": host.address, "hostname": host.hostname,
                "state": host.state, "services": services,
            })

        policies: dict[tuple[int, str], str] = {}
        try:
            config = load_config()
            for entry in hosts:
                for svc in entry["services"]:
                    policies[(svc.port, svc.proto)] = config.policy_for(
                        svc.port, svc.proto
                    ).policy
        except ConfigError:
            # Policy badges are decoration on this page; the scan results are
            # not. A broken config file is already reported by the safety banner
            # and by /api/safety/status, so the page renders without the badges
            # rather than hiding the evidence the operator came here to read.
            pass

        return _render(
            request, "scan_detail.html", "scans",
            scan=scan, hosts=hosts, policies=policies,
        )


@router.post("/scans/{session_id}/correlate")
def correlate(request: Request, session_id: str) -> RedirectResponse:
    from backend.jobs.runner import get_runner
    from backend.nvd.pipeline import run_correlation

    try:
        config = load_config()
    except ConfigError as exc:
        return RedirectResponse(f"/scans?error={quote(str(exc))}", status_code=303)

    uid = _uid(request)
    # Only the scan's owner may correlate it.
    with session_scope() as db:
        owned = (
            db.query(ScanSession)
            .filter_by(session_id=session_id, user_id=uid)
            .one_or_none()
        )
    if owned is None:
        return RedirectResponse(
            f"/scans?error={quote('No such scan in your account.')}", status_code=303
        )

    job_id = get_runner().submit(
        "correlation", run_correlation,
        payload={"session_id": session_id}, config=config, session_id=session_id,
        actor=_actor(request), owner_id=uid, user_id=uid,
    )
    return RedirectResponse(f"/scans?queued={job_id}", status_code=303)


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


# Remediation advice per service class. Deliberately generic and phrased as a
# recommendation: CyberShield can reduce network exposure, and it cannot patch
# software, so telling an operator "upgrade to 2.4.52" would be advice it has no
# way to carry out or verify.
_REMEDIATION_ADVICE: dict[int, str] = {
    21: "FTP transmits credentials in cleartext. Replace with SFTP, or restrict "
        "the port to trusted hosts. Isolation is available for lab targets.",
    23: "Telnet is cleartext and unauthenticated in transit. Disable it and use SSH.",
    3306: "Database ports should not be exposed to a general network. Bind to "
          "localhost or restrict by source address.",
    5432: "Database ports should not be exposed to a general network. Bind to "
          "localhost or restrict by source address.",
    6379: "Redis has no authentication by default and should never be reachable "
          "from a general network. Bind to localhost and enable requirepass.",
    11211: "Memcached is unauthenticated and is a known amplification vector. "
           "Bind to localhost.",
    27017: "MongoDB should not be network-exposed. Bind to localhost and enable "
           "authentication.",
    5900: "VNC is frequently weakly authenticated. Tunnel it over SSH instead.",
    3389: "RDP is a common attack target. Restrict by source address and require "
          "network-level authentication.",
    445: "SMB should not be exposed beyond a trusted segment.",
    139: "NetBIOS/SMB should not be exposed beyond a trusted segment.",
}

_DEFAULT_ADVICE = (
    "Review whether this service needs to be reachable from this network at "
    "all. Where the vendor has published a fixed version, apply it — CyberShield "
    "does not patch software and cannot do this for you. For an eligible "
    "laboratory target, controlled network isolation is available on the "
    "Remediation page."
)


def _remediation_advice(port: int, product: str | None, version: str | None) -> str:
    """Recommendation text for a finding. Never an automated action."""
    base = _REMEDIATION_ADVICE.get(port, _DEFAULT_ADVICE)
    if product and version:
        return (
            f"{base} Detected {product} {version}: confirm against the vendor's "
            "advisory whether this specific build is affected before acting."
        )
    if product:
        return (
            f"{base} Detected {product} with no version string: the version could "
            "not be established, so the CVE match is weaker, not absent."
        )
    return base


@router.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities_page(
    request: Request,
    severity: str = "",
    confidence: str = "",
    hide_fp: str = "",
    cve: str = "",
    host: str = "",
    port: str = "",
    service: str = "",
    status: str = "",
    scope: str = "latest",
) -> HTMLResponse:
    """CVE candidates from the database.

    `scope` defaults to the latest assessment scan for the same reason the
    dashboard counts are scoped that way: correlating two scans creates two
    independent sets of Vulnerability rows for the same services, and an
    unscoped list reported 834 candidates for a laboratory that produced 278.
    "all" is still available, labelled, for looking across history.
    """
    cve_query = cve.strip().upper()
    host_query = host.strip()
    service_query = service.strip().lower()
    port_query = port.strip()
    uid = _uid(request)

    with session_scope() as db:
        latest_assessment = (
            db.query(ScanSession)
            .filter_by(scan_kind="assessment", user_id=uid)
            .order_by(ScanSession.id.desc())
            .first()
        )

        # Base query is always constrained to this user's own findings; the
        # scope filter below narrows further to a single assessment.
        query = db.query(Vulnerability).filter(Vulnerability.user_id == uid)
        scoped_session_id = None
        if scope != "all" and latest_assessment is not None:
            host_ids = [
                h.id
                for h in db.query(DiscoveredHost).filter_by(
                    session_id=latest_assessment.id
                )
            ]
            service_ids = (
                [
                    svc.id
                    for svc in db.query(DiscoveredService).filter(
                        DiscoveredService.host_id.in_(host_ids)
                    )
                ]
                if host_ids
                else []
            )
            query = query.filter(Vulnerability.service_id.in_(service_ids or [-1]))
            scoped_session_id = latest_assessment.session_id

        all_vulns = query.order_by(Vulnerability.id.desc()).all()
        flagged = sum(
            1 for v in all_vulns if (v.evidence or {}).get("vulnerable_match_count") == 0
        )

        rows = []
        hosts_seen: set[str] = set()
        services_seen: set[str] = set()

        for v in all_vulns:
            cve_record = db.get(CveRecord, v.cve_id)
            is_fp = (v.evidence or {}).get("vulnerable_match_count") == 0
            service_row = db.get(DiscoveredService, v.service_id)
            host_row = (
                db.get(DiscoveredHost, service_row.host_id) if service_row else None
            )

            if host_row:
                hosts_seen.add(host_row.address)
            if service_row and service_row.service_name:
                services_seen.add(service_row.service_name)

            if severity and (cve_record is None or cve_record.base_severity != severity):
                continue
            if confidence and v.confidence != confidence:
                continue
            if hide_fp and is_fp:
                continue
            if cve_query and cve_query not in v.cve_id.upper():
                continue
            if host_query and (not host_row or host_query not in host_row.address):
                continue
            if port_query and (
                not service_row or port_query != str(service_row.port)
            ):
                continue
            if service_query and (
                not service_row
                or service_query not in (service_row.service_name or "").lower()
            ):
                continue
            if status and v.status != status:
                continue

            rows.append({
                "id": v.id, "cve_id": v.cve_id,
                "host": host_row.address if host_row else "—",
                "port": service_row.port if service_row else "—",
                "proto": service_row.proto if service_row else "tcp",
                "service_name": service_row.service_name if service_row else None,
                "detected_product": v.detected_product,
                "detected_version": v.detected_version,
                "severity": cve_record.base_severity if cve_record else None,
                "base_score": cve_record.base_score if cve_record else None,
                "cvss_version": cve_record.cvss_version if cve_record else None,
                "matching_method": v.matching_method,
                "confidence": v.confidence,
                "status": v.status,
                "probable_false_positive": is_fp,
                "advice": _remediation_advice(
                    service_row.port if service_row else 0,
                    v.detected_product,
                    v.detected_version,
                ),
            })

        return _render(
            request, "vulnerabilities.html", "vulns",
            rows=rows[:500], total=len(all_vulns), flagged=flagged,
            matched=len(rows),
            severity=severity, confidence=confidence, hide_fp=hide_fp,
            cve=cve, host=host, port=port, service=service, status=status,
            scope=scope, scoped_session_id=scoped_session_id,
            scoped_target=(
                latest_assessment.target_spec if latest_assessment else None
            ),
            known_hosts=sorted(hosts_seen),
            known_services=sorted(services_seen),
        )


# Review states an operator may set. Deliberately does NOT include anything
# meaning "proven exploitable": nothing in this system can establish that, so no
# such state exists to be set. "verified_true_positive" records a HUMAN
# judgement that the CVE plausibly applies here — it is not machine-confirmed.
REVIEW_STATES = {
    "candidate": "Unreviewed candidate",
    "reviewed_true_positive": "Reviewed — plausibly applies here",
    "reviewed_false_positive": "Reviewed — does not apply here",
}


@router.post("/vulnerabilities/{vuln_id}/review")
def review_vulnerability(
    request: Request,
    vuln_id: int,
    status: str = Form(...),
    note: str = Form(""),
) -> RedirectResponse:
    """Record a human review verdict on a CVE candidate.

    This is the only way the `status` column changes. The correlation pipeline
    writes `candidate` and never promotes a finding itself, because a version
    string resembling a CVE's applicability data is not evidence of
    exploitability. Marking a candidate reviewed is an operator's judgement and
    is attributed to them in the audit log.
    """
    actor = _actor(request)
    if status not in REVIEW_STATES:
        return RedirectResponse(
            f"/vulnerabilities/{vuln_id}?error="
            + quote(f"Unknown review state {status!r}."),
            status_code=303,
        )

    uid = _uid(request)
    with session_scope() as db:
        vuln = db.get(Vulnerability, vuln_id)
        if vuln is None or vuln.user_id != uid:
            return RedirectResponse("/vulnerabilities", status_code=303)
        previous = vuln.status
        vuln.status = status
        vuln.reviewer_note = (note or "").strip()[:2000] or None
        cve_id = vuln.cve_id

    audit_log.record(
        "vulnerability.reviewed",
        outcome="success",
        actor=actor,
        detail={
            "vulnerability_id": vuln_id,
            "cve_id": cve_id,
            "from_status": previous,
            "to_status": status,
            "has_note": bool((note or "").strip()),
        },
    )
    return RedirectResponse(f"/vulnerabilities/{vuln_id}", status_code=303)


@router.get("/vulnerabilities/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(request: Request, vuln_id: int) -> HTMLResponse:
    uid = _uid(request)
    with session_scope() as db:
        vuln = db.get(Vulnerability, vuln_id)
        # Ownership check: another user's finding reads as "not found".
        if vuln is None or vuln.user_id != uid:
            return _render(
                request, "vulnerability_detail.html", "vulns",
                v=None, decision=None, status_code=404,
            )

        cve = db.get(CveRecord, vuln.cve_id)
        service = db.get(DiscoveredService, vuln.service_id)
        host = db.get(DiscoveredHost, service.host_id) if service else None
        signatures = (
            db.query(SoftwareSignature).filter_by(service_id=service.id).all()
            if service else []
        )

        count, max_sev, max_conf, _ = _service_risk(db, vuln.service_id)
        view = {
            "id": vuln.id, "cve_id": vuln.cve_id,
            "host": host.address if host else "—",
            "port": service.port if service else "—",
            "proto": service.proto if service else "tcp",
            "detected_product": vuln.detected_product,
            "detected_version": vuln.detected_version,
            "severity": cve.base_severity if cve else None,
            "base_score": cve.base_score if cve else None,
            "cvss_version": cve.cvss_version if cve else None,
            "vector_string": cve.vector_string if cve else None,
            "description": cve.description if cve else None,
            "cwe_ids": cve.cwe_ids if cve else None,
            "matching_method": vuln.matching_method,
            "confidence": vuln.confidence,
            "status": vuln.status,
            "nvd_reference": vuln.nvd_reference,
            "evidence": vuln.evidence,
            "caveats": vuln.caveats,
            "probable_false_positive": (vuln.evidence or {}).get("vulnerable_match_count") == 0,
            "reviewer_note": vuln.reviewer_note,
            "advice": _remediation_advice(
                service.port if service else 0,
                vuln.detected_product,
                vuln.detected_version,
            ),
            "signatures": [
                {
                    "vendor": s.vendor, "product": s.product, "version": s.version,
                    "cpe23": s.cpe23, "mapping_source": s.mapping_source,
                    "confidence": s.confidence,
                }
                for s in signatures
            ],
        }

        decision_payload: dict[str, Any] = {"verdict": "DENY", "rules": [], "blocking_reason": None}
        if host and service:
            try:
                decision_payload = evaluate(
                    load_config(),
                    IsolationRequest(
                        target_address=host.address, port=service.port,
                        proto=service.proto, max_severity=max_sev, max_confidence=max_conf,
                    ),
                ).to_dict()
            except ConfigError as exc:
                decision_payload["blocking_reason"] = str(exc)

        return _render(
            request, "vulnerability_detail.html", "vulns",
            v=view, decision=decision_payload, review_states=REVIEW_STATES,
        )


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@router.get("/remediation", response_class=HTMLResponse)
def remediation_page(
    request: Request, message: str | None = None, error: str | None = None
) -> HTMLResponse:
    candidates: list[dict[str, Any]] = []
    uid = _uid(request)
    try:
        config = load_config()
    except ConfigError as exc:
        return _render(
            request, "remediation.html", "remediation",
            candidates=[], actions=[], message=None, error=str(exc),
        )

    with session_scope() as db:
        # Only assessment scans: verification rescans probe a single port and
        # carry no correlation, so including them would produce phantom rows.
        latest = (
            db.query(ScanSession)
            .filter_by(scan_kind="assessment", user_id=uid)
            .order_by(ScanSession.id.desc())
            .first()
        )
        if latest is not None:
            for host in db.query(DiscoveredHost).filter_by(session_id=latest.id):
                for svc in (
                    db.query(DiscoveredService)
                    .filter_by(host_id=host.id, state="open")
                    .order_by(DiscoveredService.port)
                ):
                    count, max_sev, max_conf, vuln_id = _service_risk(db, svc.id)
                    if not count:
                        continue
                    decision = evaluate(
                        config,
                        IsolationRequest(
                            target_address=host.address, port=svc.port, proto=svc.proto,
                            max_severity=max_sev, max_confidence=max_conf,
                        ),
                    )
                    candidates.append({
                        "host": host.address, "port": svc.port, "proto": svc.proto,
                        "product": svc.product, "version": svc.version,
                        "cve_count": count, "max_severity": max_sev,
                        "max_confidence": max_conf,
                        "verdict": decision.verdict.value,
                        "reason": decision.blocking_reason,
                        "vulnerability_id": vuln_id,
                    })

        # ALLOW first, then most severe.
        candidates.sort(
            key=lambda c: (
                c["verdict"] != "ALLOW",
                -SEVERITY_ORDER.get(c["max_severity"] or "", -1),
            )
        )
        actions = (
            db.query(RemediationAction).filter(RemediationAction.user_id == uid)
            .order_by(RemediationAction.id.desc()).limit(25).all()
        )
        return _render(
            request, "remediation.html", "remediation",
            candidates=candidates, actions=actions, message=message, error=error,
        )


def _candidate_context(db, config, target: str, port: int, uid: int) -> dict[str, Any] | None:
    """Look up the detected service behind a remediation candidate.

    Returns None when the address/port pair does not correspond to an open
    service in the latest assessment scan. Isolation is only offered for
    services this system actually observed, so a hand-typed pair that was never
    scanned has no candidate to review.
    """
    latest = (
        db.query(ScanSession)
        .filter_by(scan_kind="assessment", user_id=uid)
        .order_by(ScanSession.id.desc())
        .first()
    )
    if latest is None:
        return None

    for host in db.query(DiscoveredHost).filter_by(session_id=latest.id):
        if host.address != target:
            continue
        svc = (
            db.query(DiscoveredService)
            .filter_by(host_id=host.id, port=port, state="open")
            .one_or_none()
        )
        if svc is None:
            continue
        count, max_sev, max_conf, vuln_id = _service_risk(db, svc.id)
        return {
            "host": host.address,
            "port": svc.port,
            "proto": svc.proto,
            "service_name": svc.service_name,
            "product": svc.product,
            "version": svc.version,
            "cve_count": count,
            "max_severity": max_sev,
            "max_confidence": max_conf,
            "vulnerability_id": vuln_id,
            "session_id": latest.session_id,
        }
    return None


@router.get("/remediation/review", response_class=HTMLResponse)
def remediation_review(
    request: Request, target: str = "", port: int = 0
) -> HTMLResponse:
    """Step 3 of the flow: the operator reviews the exact action before approving.

    Read-only. `build_plan` evaluates the decision chain and renders the argv it
    *would* run; nothing is persisted, nothing is sent to the target, and no
    audit event is written by loading this page. The plan shown here is
    rebuilt from scratch when the operator confirms, so a scope or policy edit
    between review and approval is caught at execution time rather than
    trusted from this page.
    """
    from backend.remediation.plan import PlanError, build_plan

    try:
        config = load_config()
    except ConfigError as exc:
        return _render(
            request, "remediation_review.html", "remediation",
            candidate=None, plan=None, decision=None, error=explain(exc).to_dict(),
        )

    with session_scope() as db:
        candidate = _candidate_context(db, config, target.strip(), port, _uid(request))

    if candidate is None:
        return _render(
            request, "remediation_review.html", "remediation",
            candidate=None, plan=None, decision=None,
            error={
                "title": "No such remediation candidate",
                "message": (
                    f"tcp/{port} on {target or '(no target)'} is not an open "
                    "service in the latest assessment scan, so there is nothing "
                    "to review. Isolation is only offered for services this "
                    "system actually observed."
                ),
                "hint": "Run a scan, correlate it, then return to Remediation.",
                "technical": f"target={target!r} port={port!r}",
            },
        )

    isolation = IsolationRequest(
        target_address=candidate["host"],
        port=candidate["port"],
        proto=candidate["proto"],
        max_severity=candidate["max_severity"],
        max_confidence=candidate["max_confidence"],
        vulnerability_id=candidate["vulnerability_id"],
    )

    try:
        plan = build_plan(config, isolation, vulnerability_id=candidate["vulnerability_id"])
    except PlanError as exc:
        # A plan could not even be constructed — e.g. the configured backend
        # cannot express this action. Show it as a refusal, not a crash.
        return _render(
            request, "remediation_review.html", "remediation",
            candidate=candidate, plan=None,
            decision=evaluate(config, isolation).to_dict(),
            error=explain(exc).to_dict(),
        )

    return _render(
        request, "remediation_review.html", "remediation",
        candidate=candidate, plan=plan.to_dict(),
        decision=plan.decision.to_dict(), error=None,
    )


@router.post("/remediation/apply")
def remediation_apply_form(
    request: Request,
    target: str = Form(...),
    port: int = Form(...),
    severity: str = Form(""),
    confidence: str = Form(""),
    vulnerability_id: str = Form(""),
    confirm: str = Form(""),
    acknowledge: str = Form(""),
) -> RedirectResponse:
    """Step 4-8: explicit confirmation, then plan, execute, verify, audit.

    Two independent confirmations are required and neither is defaulted:
    `confirm=yes` (the form was submitted deliberately) and `acknowledge=yes`
    (the operator ticked the box stating they understand isolation is not a
    patch). Either missing is a refusal.
    """
    from backend.main import _watchdog
    from backend.remediation.executor import ExecutionError, apply_plan
    from backend.remediation.plan import PlanError, build_plan

    actor = _actor(request)
    back = f"/remediation/review?target={quote(target)}&port={port}"

    if confirm != "yes" or acknowledge != "yes":
        audit_log.record(
            "remediation.refused",
            outcome="refused",
            actor=actor,
            detail={
                "target_address": target,
                "port": port,
                "reason": "Operator confirmation was not given.",
            },
        )
        return RedirectResponse(
            f"{back}&error="
            + quote(
                "Refused: explicit confirmation is required. Both the "
                "acknowledgement box and the Apply button must be used."
            ),
            status_code=303,
        )

    try:
        config = load_config()
        plan = build_plan(
            config,
            IsolationRequest(
                target_address=target, port=port, proto="tcp",
                max_severity=severity or None, max_confidence=confidence or None,
            ),
            vulnerability_id=int(vulnerability_id) if vulnerability_id.isdigit() else None,
        )
        outcome = apply_plan(
            config, plan, confirmed=True, watchdog=_watchdog, actor=actor,
            user_id=_uid(request),
        )
    except (ConfigError, PlanError, ExecutionError) as exc:
        # A refusal from the decision engine or the executor. apply_plan has
        # already written the audit entry; the operator gets the explanation.
        friendly = explain(exc)
        return RedirectResponse(
            f"{back}&error={quote(friendly.flat())}", status_code=303
        )

    # Step 9-10: the result view carries the verification evidence.
    return RedirectResponse(
        f"/remediation/action/{outcome.request_id}", status_code=303
    )


@router.get("/remediation/action/{request_id}", response_class=HTMLResponse)
def remediation_action(request: Request, request_id: str) -> HTMLResponse:
    """Outcome of one remediation action, with its verification evidence."""
    uid = _uid(request)
    with session_scope() as db:
        row = (
            db.query(RemediationAction)
            .filter_by(request_id=request_id, user_id=uid)
            .one_or_none()
        )
        if row is None:
            # 404 for consistency with the scan, vulnerability and report
            # pages: an action that does not exist and one owned by another
            # operator are the same answer, and neither is an action with no
            # content.
            return _render(
                request, "remediation_action.html", "remediation",
                action=None, verification_scans=[], events=[], status_code=404,
            )

        action = {
            "request_id": row.request_id,
            "target": row.target_address,
            "port": row.port,
            "proto": row.proto,
            "backend": row.backend,
            "state": row.state,
            "operator": row.operator,
            "apply_argv": row.apply_argv or [],
            "rollback_argv": row.rollback_argv or [],
            "rule_tag": row.rule_tag,
            "decision": row.decision,
            "before_state": row.before_state,
            "after_state": row.after_state,
            "rollback_state": row.rollback_state,
            "exposure_reduced": row.exposure_reduced,
            "rollback_verified": row.rollback_verified,
            "management_channel_intact": row.management_channel_intact,
            "planned_at": row.planned_at,
            "applied_at": row.applied_at,
            "rolled_back_at": row.rolled_back_at,
            "expires_at": row.expires_at,
            "error": row.error,
            "is_dry_run": row.backend == "dryrun",
        }

        # The verification rescans this action triggered, so the operator can
        # open the raw Nmap evidence behind the before/after claim.
        scans = (
            db.query(ScanSession)
            .filter(
                ScanSession.scan_kind.like("verification%"),
                ScanSession.target_spec == f"{row.target_address}/32",
            )
            .order_by(ScanSession.id.desc())
            .limit(6)
            .all()
        )
        verification_scans = [
            {
                "session_id": s.session_id,
                "scan_kind": s.scan_kind,
                "status": s.status,
                "open_services": s.open_services,
                "started_at": s.started_at,
            }
            for s in scans
        ]

    # Audit events naming this request, so the page shows its own trail.
    events = []
    try:
        for entry in audit_log.entries():
            detail = entry.detail or {}
            if detail.get("request_id") == request_id:
                events.append(
                    {
                        "sequence": entry.sequence,
                        "timestamp": entry.timestamp,
                        "action": entry.action,
                        "outcome": entry.outcome,
                        "actor": entry.actor,
                        "summary_text": _summarise(entry),
                    }
                )
    except (OSError, ValueError):
        events = []

    return _render(
        request, "remediation_action.html", "remediation",
        action=action, verification_scans=verification_scans, events=events,
    )


@router.post("/remediation/{request_id}/rollback")
def remediation_rollback_form(request: Request, request_id: str) -> RedirectResponse:
    from backend.main import _watchdog
    from backend.remediation.executor import ExecutionError, rollback

    uid = _uid(request)
    with session_scope() as db:
        owned = (
            db.query(RemediationAction)
            .filter_by(request_id=request_id, user_id=uid)
            .one_or_none()
        )
    if owned is None:
        return RedirectResponse(
            f"/remediation?error={quote('No such remediation action in your account.')}",
            status_code=303,
        )

    try:
        config = load_config()
        _watchdog.cancel(request_id)
        result = rollback(config, request_id, actor=_actor(request), user_id=uid)
    except (ConfigError, ExecutionError) as exc:
        return RedirectResponse(f"/remediation?error={quote(str(exc))}", status_code=303)

    return RedirectResponse(f"/remediation?message={result['note']}", status_code=303)


# ---------------------------------------------------------------------------
# SSH management channel
# ---------------------------------------------------------------------------


@router.get("/ssh", response_class=HTMLResponse)
def ssh_page(
    request: Request, message: str | None = None, error: str | None = None
) -> HTMLResponse:
    """Management-channel status. Opens no connection by itself."""
    from backend.remediation.ssh_status import describe_channels

    try:
        config = load_config()
    except ConfigError as exc:
        return _render(
            request, "ssh.html", "ssh",
            channels=[], lab_hosts=[], message=None, error=explain(exc).to_dict(),
        )

    channels = [c.to_dict() for c in describe_channels(config)]

    # Addresses an operator can actually test: hosts seen by the latest
    # assessment scan that fall inside an is_lab range.
    lab_hosts: list[str] = []
    with session_scope() as db:
        latest = (
            db.query(ScanSession)
            .filter_by(scan_kind="assessment", user_id=_uid(request))
            .order_by(ScanSession.id.desc())
            .first()
        )
        if latest is not None:
            for host in db.query(DiscoveredHost).filter_by(session_id=latest.id):
                entry = config.find_authorized_target(host.address)
                if entry is not None and entry.is_lab:
                    lab_hosts.append(host.address)

    return _render(
        request, "ssh.html", "ssh",
        channels=channels, lab_hosts=sorted(set(lab_hosts)),
        message=message,
        error={"title": "SSH test failed", "message": error, "hint": "", "technical": ""}
        if error
        else None,
    )


@router.post("/ssh/test")
def ssh_test(request: Request, address: str = Form(...)) -> RedirectResponse:
    """Test one lab target's management channel.

    The address is validated against the authorized scope by
    `test_channel` before any socket is opened, so this cannot be used to
    reach an arbitrary host.
    """
    from backend.core.authorization import AuthorizationDenied
    from backend.remediation.ssh_status import probe_channel

    try:
        config = load_config()
        status = probe_channel(config, address.strip(), actor=_actor(request))
    except (ConfigError, AuthorizationDenied) as exc:
        return RedirectResponse(f"/ssh?error={quote(str(exc))}", status_code=303)

    if status.reachable:
        note = (
            f"Management channel to {status.user}@{address}:{status.port} is "
            f"working ({status.latency_ms} ms). Rollback of an applied rule is "
            "possible on this target."
        )
        return RedirectResponse(f"/ssh?message={quote(note)}", status_code=303)

    # Lead with the category, keep the technical detail after it. The four
    # failures need different actions from the operator — a rejected key is not
    # a dead host — and the raw paramiko text alone does not make that obvious.
    headline = {
        "auth": "Authentication failed: the target rejected the configured key.",
        "timeout": "Timed out: the target accepted no connection in time.",
        "connect": "Could not connect: nothing is listening, or the host is unreachable.",
        "config": "Not configured: CyberShield cannot open a channel at all.",
        "command": "Connected, but the probe command could not be run.",
    }.get(status.failure_kind or "", "Management channel test failed.")
    return RedirectResponse(
        f"/ssh?error={quote(headline + ' ' + (status.detail or 'unknown'))}",
        status_code=303,
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def _summarise(entry) -> str:
    """One-line human summary of an audit entry's detail."""
    d = entry.detail or {}
    action = entry.action
    if action == "scan.finish":
        return (
            f"{d.get('hosts_up', '?')} hosts up, {d.get('open_services', '?')} "
            f"open services in {d.get('duration_seconds', '?')}s"
            + ("  [TRUNCATED]" if d.get("results_complete") is False else "")
        )
    if action == "scan.refused":
        return str(d.get("reason", ""))[:180]
    if action == "correlation.finish":
        return (
            f"{d.get('cve_candidates', 0)} candidates from "
            f"{d.get('services_correlated', 0)} services, "
            f"{d.get('flagged_probable_false_positives', 0)} flagged"
        )
    if action in ("remediation.apply", "remediation.rollback"):
        return str(d.get("command", ""))
    if action == "remediation.verify":
        v = d.get("verification", {})
        return f"exposure_reduced={v.get('exposure_reduced')}, mgmt_intact={v.get('management_channel_intact')}"
    if action == "remediation.refused":
        return str(d.get("reason", ""))[:180]
    if action == "remediation.plan":
        return f"{d.get('verdict', '')} — {d.get('apply_command', '')}"
    if action == "auth.login":
        return f"signed in from {d.get('client_host') or 'unknown host'}"
    if action == "auth.login_failed":
        return str(d.get("reason", "authentication refused"))
    if action == "auth.logout":
        return "signed out"
    if action == "auth.signup":
        return f"operator account created ({d.get('role', 'operator')})"
    if action == "scope.target_authorized":
        return (
            f"{d.get('target')} authorized for assessment "
            f"({d.get('address_count', '?')} address(es)), is_lab="
            f"{str(d.get('is_lab', False)).lower()}"
        )
    if action == "scope.target_revoked":
        return f"{d.get('target')} removed from scope"
    if action == "scope.target_refused":
        return str(d.get("reason", ""))[:180]
    if action == "correlation.failed":
        return str(d.get("error", "CVE lookup failed"))[:180]
    if action == "scan.failed":
        return f"{d.get('stage', 'scan')}: {str(d.get('error', ''))[:150]}"
    if action == "ssh.test":
        return str(d.get("result") or d.get("reason") or "")[:170]
    if action == "vulnerability.reviewed":
        return (
            f"{d.get('cve_id')}: {d.get('from_status')} -> {d.get('to_status')}"
            + (" (note recorded)" if d.get("has_note") else "")
        )
    if action == "remediation.lockout_risk":
        return str(
            d.get("automatic_rollback_error") or d.get("action") or ""
        )[:170]
    return ""


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request, limit: int = 200, action: str = "", outcome: str = ""
) -> HTMLResponse:
    username = _actor(request)
    # The chain is verified over the COMPLETE, install-wide log — a hash chain
    # is only meaningful whole, and verifying a per-user subset would report
    # breaks that are not real. The VIEW, however, shows only this operator's own
    # actions, so one user never reads another's audit trail.
    all_entries = audit_log.entries()
    chain = audit_log.verify_chain()

    entries = [e for e in all_entries if e.actor == username]
    known_actions = sorted({e.action for e in entries})
    selected = [
        e
        for e in entries
        if (not action or e.action == action) and (not outcome or e.outcome == outcome)
    ]

    view = []
    for entry in reversed(selected[-limit:]):
        view.append({
            "sequence": entry.sequence, "timestamp": entry.timestamp,
            "action": entry.action, "outcome": entry.outcome, "actor": entry.actor,
            "detail": entry.detail, "summary_text": _summarise(entry),
        })

    return _render(
        request, "audit.html", "audit",
        entries=view, total=len(entries), matched=len(selected),
        known_actions=known_actions, action=action, outcome=outcome,
        chain={
            "valid": chain.valid,
            "message": chain.message,
            "first_invalid_sequence": chain.first_invalid_sequence,
        },
    )


# ---------------------------------------------------------------------------
# Profile & account settings
#
# These routes let an operator manage their own account. They are authenticated
# like every other console page (the middleware attaches request.state.user),
# so they act only on the signed-in operator: the user id always comes from the
# session, never from a form field, and there is no path to view or edit another
# operator's account here.
# ---------------------------------------------------------------------------


def _account_info(db, user_id: int) -> dict[str, Any] | None:
    """Read the persisted account row for the profile view."""
    from backend.database.models import User

    row = db.get(User, user_id)
    if row is None:
        return None
    return {
        "username": row.username,
        "email": row.email,
        "full_name": row.full_name,
        "role": row.role,
        "is_active": row.is_active,
        "created_at": row.created_at,
        "last_login_at": row.last_login_at,
    }


@router.get("/profile", response_class=HTMLResponse)
def profile_page(
    request: Request, message: str | None = None, error: str | None = None
) -> HTMLResponse:
    """View the signed-in operator's account and edit their own details."""
    from backend.auth.service import SESSION_COOKIE, list_active_sessions

    user = getattr(request.state, "user", None)
    token = request.cookies.get(SESSION_COOKIE)

    with session_scope() as db:
        info = _account_info(db, user.id) if user else None

    sessions = list_active_sessions(user.id, current_token=token) if user else []

    return _render(
        request, "profile.html", "profile",
        info=info,
        session_count=len(sessions),
        message=message,
        error={"title": "Could not update profile", "message": error, "hint": "", "technical": ""}
        if error
        else None,
    )


@router.post("/profile/edit")
def profile_edit(request: Request, full_name: str = Form("")) -> RedirectResponse:
    """Update the operator's own full name. Username and role are immutable."""
    from backend.auth.service import update_profile

    user = getattr(request.state, "user", None)
    if user is None:  # middleware guarantees this, but fail closed anyway
        return RedirectResponse("/login", status_code=303)
    update_profile(user.id, full_name=full_name)
    return RedirectResponse(
        f"/profile?message={quote('Your profile has been updated.')}", status_code=303
    )


@router.post("/profile/password")
def profile_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> RedirectResponse:
    """Change the operator's own password after verifying the current one.

    On success every OTHER session is revoked: a password change should sign
    out any other device, while keeping the operator signed in here.
    """
    from backend.auth.service import (
        SESSION_COOKIE,
        AuthError,
        change_password,
        revoke_other_sessions,
    )

    user = getattr(request.state, "user", None)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    if new_password != confirm_password:
        return RedirectResponse(
            f"/profile?error={quote('The two new passwords do not match.')}",
            status_code=303,
        )

    try:
        change_password(user.id, current_password, new_password)
    except AuthError as exc:
        return RedirectResponse(f"/profile?error={quote(str(exc))}", status_code=303)

    token = request.cookies.get(SESSION_COOKIE)
    revoke_other_sessions(user.id, token)
    return RedirectResponse(
        f"/profile?message={quote('Password changed. Other sessions have been signed out.')}",
        status_code=303,
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request, message: str | None = None, error: str | None = None
) -> HTMLResponse:
    """Account settings: active sessions, safety posture, and account deletion."""
    from backend.auth.service import SESSION_COOKIE, list_active_sessions

    user = getattr(request.state, "user", None)
    token = request.cookies.get(SESSION_COOKIE)
    sessions = list_active_sessions(user.id, current_token=token) if user else []

    with session_scope() as db:
        info = _account_info(db, user.id) if user else None
        from backend.database.models import User

        operator_count = db.query(User).count()

    return _render(
        request, "settings.html", "settings",
        info=info,
        sessions=sessions,
        operator_count=operator_count,
        message=message,
        error={"title": "Could not update settings", "message": error, "hint": "", "technical": ""}
        if error
        else None,
    )


@router.post("/settings/sessions/revoke-others")
def settings_revoke_others(request: Request) -> RedirectResponse:
    """Sign out every other session belonging to this operator."""
    from backend.auth.service import SESSION_COOKIE, revoke_other_sessions

    user = getattr(request.state, "user", None)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    token = request.cookies.get(SESSION_COOKIE)
    revoked = revoke_other_sessions(user.id, token)
    note = (
        f"Signed out {revoked} other session(s)."
        if revoked
        else "No other active sessions to sign out."
    )
    return RedirectResponse(f"/settings?message={quote(note)}", status_code=303)


@router.post("/settings/delete")
def settings_delete_account(
    request: Request, confirm: str = Form(""), password: str = Form(...)
) -> RedirectResponse:
    """Delete the operator's own account after confirmation and re-authentication.

    Requires the account password so a hijacked session cannot destroy the
    account. Refuses to delete the last remaining operator (handled in the
    service). Historical scan, remediation and audit records naming this
    operator are retained: deleting an account never rewrites what was done.
    """
    from backend.auth.service import (
        SESSION_COOKIE,
        AuthError,
        authenticate,
        delete_user,
    )
    from backend.auth.routes import clear_session_cookie

    user = getattr(request.state, "user", None)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    if confirm != "delete":
        return RedirectResponse(
            f"/settings?error={quote('Type delete to confirm account removal.')}",
            status_code=303,
        )

    try:
        authenticate(user.username, password)
    except AuthError:
        return RedirectResponse(
            f"/settings?error={quote('Password incorrect; account was not deleted.')}",
            status_code=303,
        )

    try:
        delete_user(user.username)
    except AuthError as exc:
        return RedirectResponse(f"/settings?error={quote(str(exc))}", status_code=303)

    response = RedirectResponse(
        "/login?notice=Your+account+has+been+deleted.", status_code=303
    )
    clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Reports
#
# A report is a per-scan assembly of stored evidence, rendered as HTML and
# downloadable as PDF. Both come from the same builder, so the two presentations
# cannot drift apart. The report's overall summary is the honesty guarantee:
# a failed, unreachable, partial or uncorrelated scan is never presented as a
# clean result (see backend/reports/builder.summarise).
# ---------------------------------------------------------------------------


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request) -> HTMLResponse:
    """List assessment scans a report can be generated for."""
    from backend.reports import list_reportable_scans

    scans = list_reportable_scans(user_id=_uid(request))
    return _render(request, "reports.html", "reports", scans=scans)


@router.get("/reports/{session_id}", response_class=HTMLResponse)
def report_detail(request: Request, session_id: str) -> HTMLResponse:
    """Render the full assessment report for one scan session."""
    from backend.reports import build_report

    try:
        config = load_config()
    except ConfigError:
        config = None
    report = build_report(session_id, user_id=_uid(request), config=config)
    # 404, not 200: a scan that does not exist — or belongs to another operator,
    # which build_report treats identically — is not a report with no content.
    return _render(
        request, "report.html", "reports",
        report=report, session_id=session_id,
        status_code=200 if report is not None else 404,
    )


@router.get("/reports/{session_id}/pdf")
def report_pdf(request: Request, session_id: str):
    """Download the assessment report for one scan session as PDF."""
    from fastapi.responses import Response

    from backend.reports import build_report
    from backend.reports.pdf import render_pdf

    try:
        config = load_config()
    except ConfigError:
        config = None
    report = build_report(session_id, user_id=_uid(request), config=config)
    if report is None:
        return _render(
            request, "report.html", "reports",
            report=None, session_id=session_id, status_code=404,
        )

    pdf_bytes = render_pdf(report)
    filename = f"cybershield-report-{session_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
