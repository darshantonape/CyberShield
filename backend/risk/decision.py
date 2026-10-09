"""Risk-aware remediation decision engine (spec §12).

Every isolation request passes through `evaluate()` before anything touches a
target. The engine returns one of three verdicts:

    ALLOW            every safety condition passed
    REVIEW_REQUIRED  nothing unsafe, but a human must judge this one
    DENY             a hard safety rule blocked it

Two properties are deliberate:

  * **Fail closed.** The verdict starts as DENY and is only raised to ALLOW if
    every rule passes. An unexpected exception anywhere yields DENY, never ALLOW.
  * **No override.** There is no `force` parameter, no bypass flag, and no
    argument that turns a DENY into an ALLOW. That is required by spec §6B, and
    the absence is enforced by the function signature itself.

A high CVSS score alone never produces ALLOW — severity is one rule among eight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from backend.core.config import CONFIDENCE_ORDER, SEVERITY_ORDER, Config
from backend.core.authorization import AuthorizationDenied, assert_authorized_lab_target
from backend.core.validation import ValidationError, validate_port, validate_proto

__all__ = [
    "Verdict",
    "RuleResult",
    "Decision",
    "IsolationRequest",
    "evaluate",
]


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DENY = "DENY"


@dataclass(frozen=True)
class RuleResult:
    """Outcome of one rule in the chain. Every rule records its reasoning."""

    rule: str
    passed: bool
    verdict_if_failed: Verdict
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "passed": self.passed,
            "verdict_if_failed": self.verdict_if_failed.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class IsolationRequest:
    """An operator's request to isolate one service."""

    target_address: str
    port: int
    proto: str = "tcp"
    # Highest severity among the CVE candidates for this service, or None when
    # no scored candidate exists.
    max_severity: str | None = None
    # Best correlation confidence for this service: HIGH | MEDIUM | LOW | None.
    max_confidence: str | None = None
    vulnerability_id: int | None = None


@dataclass
class Decision:
    verdict: Verdict
    request: IsolationRequest
    rules: list[RuleResult] = field(default_factory=list)
    blocking_reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        """Serialised for the audit log and the remediation_actions row."""
        return {
            "verdict": self.verdict.value,
            "target": self.request.target_address,
            "port": self.request.port,
            "proto": self.request.proto,
            "max_severity": self.request.max_severity,
            "max_confidence": self.request.max_confidence,
            "blocking_reason": self.blocking_reason,
            "rules": [r.to_dict() for r in self.rules],
        }

    def summary(self) -> str:
        if self.verdict is Verdict.ALLOW:
            return (
                f"ALLOW: {self.request.proto}/{self.request.port} on "
                f"{self.request.target_address} passed all {len(self.rules)} safety checks."
            )
        return f"{self.verdict.value}: {self.blocking_reason}"


def evaluate(config: Config, request: IsolationRequest) -> Decision:
    """Run the full safety chain and return a verdict with its reasoning.

    Note the signature: config and request only. There is deliberately no
    parameter capable of bypassing any rule below.
    """
    decision = Decision(verdict=Verdict.DENY, request=request)

    def record(
        rule: str, passed: bool, detail: str, verdict_if_failed: Verdict = Verdict.DENY
    ) -> bool:
        decision.rules.append(RuleResult(rule, passed, verdict_if_failed, detail))
        if not passed and decision.blocking_reason is None:
            decision.verdict = verdict_if_failed
            decision.blocking_reason = detail
        return passed

    try:
        # --- Rule 0: well-formed input ------------------------------------
        try:
            port = validate_port(request.port)
            proto = validate_proto(request.proto)
        except ValidationError as exc:
            record("input_validation", False, f"Invalid isolation request: {exc}")
            return decision
        record("input_validation", True, f"Request targets {proto}/{port}.")

        # --- Rule 1: protocol is one the isolation backend can implement ---
        # Deliberately a capability gate, not a risk judgement, and therefore
        # ahead of the policy rules. A protocol the backend cannot express must
        # be DENY: no amount of human review makes a UDP rule implementable
        # here, so returning REVIEW_REQUIRED would imply a path that does not
        # exist. The SSH-reachability half of "technically supported" stays at
        # the end of the chain, where spec §12 places it.
        if not record(
            "protocol_supported",
            proto == "tcp",
            (
                f"Isolation is implemented for TCP only; this request is {proto}. "
                "No UDP isolation backend exists, so this cannot be approved by review."
                if proto != "tcp"
                else "TCP isolation is implemented."
            ),
        ):
            return decision

        # --- Rule 2: target authorized and remediable ---------------------
        # assert_authorized_lab_target covers three things at once: the
        # AUTHORIZATION.md signature, scope membership, and is_lab + ssh_user.
        try:
            entry = assert_authorized_lab_target(config, request.target_address)
        except AuthorizationDenied as exc:
            record("authorized_lab_target", False, str(exc))
            return decision
        record(
            "authorized_lab_target",
            True,
            f"{request.target_address} is inside authorized lab range "
            f"{entry.target} ({entry.name}).",
        )

        # --- Rule 2: protected port ---------------------------------------
        # Hard block. No configuration or parameter can lift this.
        protected = config.is_protected_port(port, proto)
        if not record(
            "protected_port",
            protected is None,
            (
                f"{proto}/{port} is a protected port and can never be isolated: "
                f"{protected.reason}"
                if protected
                else f"{proto}/{port} is not on the protected-port list."
            ),
        ):
            return decision

        # --- Rule 3: anti-lockout on the live management channel -----------
        # Independent of the protected list: catches a target administered over
        # a non-standard SSH port, where port 22 alone would not protect it.
        if config.protect_active_management_channel:
            is_mgmt = port == entry.ssh_port and proto == "tcp"
            if not record(
                "management_channel",
                not is_mgmt,
                (
                    f"{proto}/{port} is the active SSH management channel for "
                    f"{entry.name}. Isolating it would remove the ability to roll "
                    "back this very action."
                    if is_mgmt
                    else f"{proto}/{port} is not the management channel "
                    f"(tcp/{entry.ssh_port})."
                ),
            ):
                return decision
        else:
            record(
                "management_channel",
                True,
                "Management-channel protection is disabled in protected_ports.yaml.",
            )

        # --- Rule 4: approved-service policy -------------------------------
        policy = config.policy_for(port, proto)
        if policy.policy in {"approved", "protected"}:
            record(
                "service_policy",
                False,
                f"{proto}/{port} is classified '{policy.policy}' and is not "
                f"subject to isolation: {policy.reason}",
            )
            return decision
        if policy.policy == "review_required":
            record(
                "service_policy",
                False,
                f"{proto}/{port} is classified 'review_required': {policy.reason} "
                "An operator must classify this service before it can be isolated.",
                verdict_if_failed=Verdict.REVIEW_REQUIRED,
            )
            return decision
        record(
            "service_policy",
            True,
            f"{proto}/{port} is classified 'eligible_for_isolation': {policy.reason}",
        )

        # --- Rule 5: correlation confidence --------------------------------
        # Acting on a keyword-only match would mean isolating a service based on
        # a string resemblance. Below-threshold goes to review, not denial.
        required_conf = config.minimum_confidence_for_eligibility
        actual_conf = (request.max_confidence or "").upper()
        if actual_conf not in CONFIDENCE_ORDER:
            record(
                "correlation_confidence",
                False,
                "No correlation confidence is recorded for this service. "
                "Isolation requires a confidence rating of at least "
                f"{required_conf}.",
                verdict_if_failed=Verdict.REVIEW_REQUIRED,
            )
            return decision
        if CONFIDENCE_ORDER[actual_conf] < CONFIDENCE_ORDER[required_conf]:
            record(
                "correlation_confidence",
                False,
                f"Correlation confidence is {actual_conf}, below the required "
                f"{required_conf}. A weak product/version match is not a basis "
                "for automated action.",
                verdict_if_failed=Verdict.REVIEW_REQUIRED,
            )
            return decision
        record(
            "correlation_confidence",
            True,
            f"Correlation confidence {actual_conf} meets the {required_conf} threshold.",
        )

        # --- Rule 6: severity ----------------------------------------------
        # Deliberately AFTER policy and confidence: a high score never drives
        # the decision on its own.
        required_sev = config.minimum_severity_for_eligibility
        actual_sev = (request.max_severity or "").upper()
        if actual_sev not in SEVERITY_ORDER:
            record(
                "severity_threshold",
                False,
                "No usable CVSS severity is recorded for this service "
                "(NVD supplied no score, or no CVE candidate was correlated). "
                f"Isolation requires at least {required_sev}.",
                verdict_if_failed=Verdict.REVIEW_REQUIRED,
            )
            return decision
        if SEVERITY_ORDER[actual_sev] < SEVERITY_ORDER[required_sev]:
            record(
                "severity_threshold",
                False,
                f"Highest candidate severity is {actual_sev}, below the "
                f"configured {required_sev} threshold.",
                verdict_if_failed=Verdict.REVIEW_REQUIRED,
            )
            return decision
        record(
            "severity_threshold",
            True,
            f"Highest candidate severity {actual_sev} meets the {required_sev} threshold.",
        )

        # --- Rule 8: isolation technically deliverable ----------------------
        # Protocol support was settled in rule 1; what remains is whether this
        # specific target can actually be reached to apply and revert the rule.
        if not entry.ssh_host and not entry.ssh_user:
            record(
                "isolation_supported",
                False,
                f"No SSH management details configured for {entry.name}; the "
                "rule could not be applied or rolled back.",
            )
            return decision
        record(
            "isolation_supported",
            True,
            f"TCP isolation is supported via the "
            f"'{config.settings.remediation_backend}' backend over SSH.",
        )

        # Every rule passed.
        decision.verdict = Verdict.ALLOW
        decision.blocking_reason = None
        return decision

    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        decision.verdict = Verdict.DENY
        decision.blocking_reason = (
            f"Decision engine failed with an unexpected error; denying by default: {exc}"
        )
        decision.rules.append(
            RuleResult("engine_integrity", False, Verdict.DENY, decision.blocking_reason)
        )
        return decision
