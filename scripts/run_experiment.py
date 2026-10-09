#!/usr/bin/env python3
"""Run a full CyberShield experiment and record the results (spec §21-§22).

    python scripts/run_experiment.py [--repetitions 3] [--no-remediation]

Phases:
    A  repeated service-detection scans (timing)
    B  CVE correlation on the final scan
    C  detection accuracy against experiments/ground_truth.yaml
    D  remediation eligibility decision for every open service
    E  isolate -> verify -> roll back -> verify, for each eligible service
    F  metrics and report

Every number in the report is computed from data this run produced. Nothing is
estimated, and a metric that cannot be computed is reported as null with the
reason, rather than filled in.

Remediation (phase E) requires CYBERSHIELD_REMEDIATION_BACKEND=nftables. Under
the default dry-run backend the phase is skipped and reported as skipped.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from backend.core.audit import AuditLog  # noqa: E402
from backend.core.config import (  # noqa: E402
    DATA_DIR,
    EXPERIMENTS_DIR,
    load_authorization,
    load_config,
)
from backend.database.models import (  # noqa: E402
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    RemediationAction,
    SoftwareSignature,
    Vulnerability,
)
from backend.database.session import init_db, session_scope  # noqa: E402
from backend.normalization.version import normalize_version  # noqa: E402
from backend.nvd.pipeline import run_correlation  # noqa: E402
from backend.remediation.executor import ExecutionError, apply_plan, rollback  # noqa: E402
from backend.remediation.plan import build_plan  # noqa: E402
from backend.risk.decision import IsolationRequest, Verdict, evaluate  # noqa: E402
from backend.scanner.pipeline import run_service_detection  # noqa: E402

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# The Colima VM's own sshd answers on every lab alias. One service seen four
# times; counting it per-host would distort every metric below.
ARTIFACT_PORT = 22


def log(message: str) -> None:
    print(message, flush=True)


def service_risk(db, service_id: int):
    vulns = db.query(Vulnerability).filter_by(service_id=service_id).all()
    if not vulns:
        return 0, None, None, None, 0
    severities = []
    for v in vulns:
        cve = db.get(CveRecord, v.cve_id)
        if cve is not None and cve.base_severity in SEVERITY_ORDER:
            severities.append(cve.base_severity)
    max_sev = max(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else None
    max_conf = max((v.confidence for v in vulns), key=lambda c: CONFIDENCE_ORDER[c])
    flagged = sum(1 for v in vulns if (v.evidence or {}).get("vulnerable_match_count") == 0)
    return len(vulns), max_sev, max_conf, vulns[0].id, flagged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=None, help="Override the scan target.")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--no-remediation", action="store_true")
    args = parser.parse_args()

    started = datetime.now(timezone.utc)
    init_db()
    config = load_config()
    authorization = load_authorization()

    if not authorization.is_valid:
        log("AUTHORIZATION.md is not signed. Refusing to run.")
        return 1

    target = args.target or str(config.authorized_targets[0].target)
    truth_path = EXPERIMENTS_DIR / "ground_truth.yaml"
    truth = yaml.safe_load(truth_path.read_text()) if truth_path.exists() else {}
    truth_index = {
        (s["host"], s["port"]): s for s in (truth.get("services") or [])
    }

    report: dict = {
        "experiment": {
            "started_at": started.isoformat(timespec="seconds"),
            "target": target,
            "repetitions": args.repetitions,
            "operator": authorization.operator_name,
            "institution": authorization.institution,
            "config_hash": config.config_hash,
            "remediation_backend": config.settings.remediation_backend,
            "ground_truth_source": str(truth_path),
        }
    }

    # -- Phase A: repeated scans ------------------------------------------
    log(f"\n=== PHASE A: {args.repetitions} service-detection scans of {target} ===")
    durations, sessions = [], []
    for i in range(1, args.repetitions + 1):
        result = run_service_detection(config, target, actor="experiment")
        durations.append(result.duration_seconds)
        sessions.append(result.session_id)
        log(
            f"  run {i}: {result.hosts_up} hosts up, {result.open_services} open "
            f"services, {result.duration_seconds:.2f}s  ({result.session_id})"
        )

    final_session = sessions[-1]
    report["scan_timing"] = {
        "repetitions": args.repetitions,
        "sessions": sessions,
        "durations_seconds": [round(d, 3) for d in durations],
        "mean_seconds": round(statistics.fmean(durations), 3),
        "min_seconds": round(min(durations), 3),
        "max_seconds": round(max(durations), 3),
        "stdev_seconds": (
            round(statistics.stdev(durations), 3) if len(durations) > 1 else None
        ),
        "note": (
            f"n={args.repetitions}. Too small for a confidence interval; reported "
            "as observed values, not as a performance claim."
        ),
    }

    # -- Phase B: correlation ---------------------------------------------
    log("\n=== PHASE B: CVE correlation ===")
    correlation = run_correlation(config, final_session, actor="experiment")
    for key, value in correlation.summary().items():
        log(f"  {key}: {value}")
    report["correlation"] = correlation.summary()

    # -- Phase C + D: detection accuracy and eligibility --------------------
    log("\n=== PHASE C: detection accuracy vs ground truth ===")
    detected: list[dict] = []
    with session_scope() as db:
        from backend.database.models import ScanSession

        scan = db.query(ScanSession).filter_by(session_id=final_session).one()
        for host in db.query(DiscoveredHost).filter_by(session_id=scan.id).order_by(
            DiscoveredHost.address
        ):
            for svc in (
                db.query(DiscoveredService)
                .filter_by(host_id=host.id, state="open")
                .order_by(DiscoveredService.port)
            ):
                count, max_sev, max_conf, vuln_id, flagged = service_risk(db, svc.id)
                sigs = db.query(SoftwareSignature).filter_by(service_id=svc.id).all()
                expected = truth_index.get((host.address, svc.port))
                normalized = normalize_version(svc.version).version

                if expected is None:
                    verdict_truth = "artifact" if svc.port == ARTIFACT_PORT else "unlisted"
                    correct = None
                else:
                    correct = (
                        normalized == expected["expected_version"]
                        and (svc.product or "").lower() == expected["product"].lower()
                    )
                    verdict_truth = "correct" if correct else "incorrect"

                decision = evaluate(
                    config,
                    IsolationRequest(
                        target_address=host.address, port=svc.port, proto=svc.proto,
                        max_severity=max_sev, max_confidence=max_conf,
                    ),
                )

                detected.append({
                    "host": host.address,
                    "port": svc.port,
                    "proto": svc.proto,
                    "detected_product": svc.product,
                    "detected_version": svc.version,
                    "normalized_version": normalized,
                    "version_confidence": svc.version_confidence,
                    "identification_status": svc.identification_status,
                    "nmap_confidence": svc.nmap_confidence,
                    "expected_version": expected["expected_version"] if expected else None,
                    "identification": verdict_truth,
                    "is_lab_target": bool(expected and expected.get("is_lab_target")),
                    "signatures": [
                        {"cpe23": s.cpe23, "source": s.mapping_source, "confidence": s.confidence}
                        for s in sigs
                    ],
                    "cve_candidates": count,
                    "flagged_false_positives": flagged,
                    "max_severity": max_sev,
                    "max_confidence": max_conf,
                    "verdict": decision.verdict.value,
                    "verdict_reason": decision.blocking_reason,
                    "vulnerability_id": vuln_id,
                })

    scored = [d for d in detected if d["identification"] in ("correct", "incorrect")]
    correct_count = sum(1 for d in scored if d["identification"] == "correct")
    for d in detected:
        mark = {"correct": "OK ", "incorrect": "BAD", "artifact": "art", "unlisted": "?? "}[
            d["identification"]
        ]
        log(
            f"  [{mark}] {d['host']}:{d['port']:<5} {(d['detected_product'] or '-')[:20]:<21}"
            f"detected={str(d['detected_version'])[:22]:<23}"
            f"normalized={str(d['normalized_version']):<10} expected={d['expected_version']}"
        )

    report["detection"] = {
        "services_detected": len(detected),
        "services_scored": len(scored),
        "correct_identifications": correct_count,
        "incorrect_identifications": len(scored) - correct_count,
        "detection_accuracy": (
            round(correct_count / len(scored), 4) if scored else None
        ),
        "excluded_artifacts": [
            d for d in detected if d["identification"] == "artifact"
        ],
        "accuracy_definition": (
            "A detection counts as correct when the Nmap product string matches "
            "the ground-truth product AND the normalized version equals the "
            "ground-truth upstream version. tcp/22 is excluded: it is the Colima "
            "VM's own sshd answering on all four aliases, one service seen four "
            "times."
        ),
        "services": detected,
    }

    verdicts = {"ALLOW": 0, "DENY": 0, "REVIEW_REQUIRED": 0}
    for d in detected:
        verdicts[d["verdict"]] += 1
    report["eligibility"] = {
        "decisions": verdicts,
        "note": "One decision per open service, evaluated by the risk engine.",
        "detail": [
            {"host": d["host"], "port": d["port"], "verdict": d["verdict"],
             "reason": d["verdict_reason"]}
            for d in detected
        ],
    }
    log(f"\n=== PHASE D: eligibility decisions === {verdicts}")

    # -- Phase E: remediation cycles ---------------------------------------
    remediation_results: list[dict] = []
    eligible = [d for d in detected if d["verdict"] == "ALLOW"]

    if args.no_remediation:
        report["remediation"] = {"skipped": "disabled by --no-remediation"}
    elif not config.settings.live_remediation_enabled:
        log(
            "\n=== PHASE E: SKIPPED — backend is 'dryrun'. "
            "Set CYBERSHIELD_REMEDIATION_BACKEND=nftables to run it. ==="
        )
        report["remediation"] = {
            "skipped": "remediation backend is dryrun; no rule can be applied",
            "eligible_services": [f"{d['host']}:{d['port']}" for d in eligible],
        }
    else:
        log(f"\n=== PHASE E: isolate -> verify -> rollback for {len(eligible)} service(s) ===")
        for d in eligible:
            log(f"\n  --- {d['host']} tcp/{d['port']} ({d['detected_product']}) ---")
            entry = {"host": d["host"], "port": d["port"], "product": d["detected_product"]}
            try:
                plan = build_plan(
                    config,
                    IsolationRequest(
                        target_address=d["host"], port=d["port"], proto="tcp",
                        max_severity=d["max_severity"], max_confidence=d["max_confidence"],
                    ),
                    vulnerability_id=d["vulnerability_id"],
                )
                outcome = apply_plan(config, plan, confirmed=True, actor="experiment")
                v = outcome.verification
                entry.update({
                    "request_id": plan.request_id,
                    "apply_command": " ".join(plan.apply_argv),
                    "rollback_command": " ".join(plan.rollback_argv),
                    "before_state": v["before"]["state"],
                    "after_state": v["after"]["state"],
                    "exposure_reduced": v["exposure_reduced"],
                    "management_channel_intact": v.get("management_channel_intact"),
                })
                log(
                    f"      before={v['before']['state']} after={v['after']['state']} "
                    f"reduced={v['exposure_reduced']} mgmt_intact={v.get('management_channel_intact')}"
                )

                rb = rollback(config, plan.request_id, actor="experiment")
                entry.update({
                    "rollback_state": rb["restored_state"]["state"],
                    "rollback_verified": rb["rollback_verified"],
                })
                log(
                    f"      rollback -> {rb['restored_state']['state']} "
                    f"verified={rb['rollback_verified']}"
                )
            except ExecutionError as exc:
                entry["error"] = str(exc)
                log(f"      FAILED: {exc}")
            remediation_results.append(entry)

        applied = [r for r in remediation_results if "error" not in r]
        report["remediation"] = {
            "attempted": len(remediation_results),
            "applied_successfully": len(applied),
            "exposure_reduced": sum(1 for r in applied if r.get("exposure_reduced")),
            "management_channel_intact": sum(
                1 for r in applied if r.get("management_channel_intact")
            ),
            "rollback_verified": sum(1 for r in applied if r.get("rollback_verified")),
            "results": remediation_results,
        }

    # -- Phase F: metrics ---------------------------------------------------
    total_candidates = sum(d["cve_candidates"] for d in detected)
    total_flagged = sum(d["flagged_false_positives"] for d in detected)
    with_cpe = [d for d in detected if d["signatures"]]
    with_candidates = [d for d in detected if d["cve_candidates"] > 0]

    audit = AuditLog(DATA_DIR / "audit.jsonl")
    chain = audit.verify_chain()

    report["metrics"] = {
        "detection_count": len(detected),
        "correct_identification_count": correct_count,
        "detection_accuracy": report["detection"]["detection_accuracy"],
        "cve_candidate_count": total_candidates,
        "auto_flagged_probable_false_positives": total_flagged,
        "auto_flagged_rate": (
            round(total_flagged / total_candidates, 4) if total_candidates else None
        ),
        "manual_false_positive_review": None,
        "cpe_resolution_rate": (
            round(len(with_cpe) / len(detected), 4) if detected else None
        ),
        "nvd_correlation_success_rate": (
            round(len(with_candidates) / len(with_cpe), 4) if with_cpe else None
        ),
        "eligibility_decisions": verdicts,
        "scan_time_mean_seconds": report["scan_timing"]["mean_seconds"],
        "audit_chain_valid": chain.valid,
        "audit_entries": chain.entries_checked,
        "not_computed": {
            "manual_false_positive_review": (
                "Requires a human to adjudicate each candidate against the CVE "
                "text. The auto-flagged rate above is a machine check (no "
                "vulnerable cpeMatch names the queried vendor:product) and is "
                "a lower bound, not a reviewed false-positive rate."
            ),
            "exploitability": (
                "Never measured. No exploitation is attempted, by design."
            ),
        },
    }
    if not args.no_remediation and config.settings.live_remediation_enabled:
        rem = report["remediation"]
        report["metrics"].update({
            "exposure_reduction_success_rate": (
                round(rem["exposure_reduced"] / rem["attempted"], 4)
                if rem["attempted"] else None
            ),
            "rollback_success_rate": (
                round(rem["rollback_verified"] / rem["attempted"], 4)
                if rem["attempted"] else None
            ),
        })

    report["experiment"]["finished_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    report["sample_size_note"] = (
        f"Single laboratory of 4 hosts and {len(detected)} open services, "
        f"{args.repetitions} scan repetitions. Results characterise this "
        "environment only and are not generalisable without a larger and more "
        "varied target set."
    )

    out_dir = EXPERIMENTS_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"experiment_{stamp}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))

    log("\n=== PHASE F: metrics ===")
    for key, value in report["metrics"].items():
        if key != "not_computed":
            log(f"  {key}: {value}")
    log(f"\nReport written to {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
