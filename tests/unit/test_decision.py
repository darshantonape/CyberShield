"""Risk-aware decision engine: protected ports, policy, anti-lockout (spec §12, §14, §25)."""

from __future__ import annotations

import inspect

import pytest

from backend.core.config import load_config
from backend.risk.decision import IsolationRequest, Verdict, evaluate
from tests.conftest import write_config_dir

pytestmark = pytest.mark.usefixtures("signed_authorization")


def request_for(port: int, **kwargs) -> IsolationRequest:
    """An otherwise-passing request, so each test isolates one variable."""
    params = {
        "target_address": "192.168.56.10",
        "port": port,
        "proto": "tcp",
        "max_severity": "CRITICAL",
        "max_confidence": "HIGH",
    }
    params.update(kwargs)
    return IsolationRequest(**params)


def rule_named(decision, name: str):
    return next((r for r in decision.rules if r.rule == name), None)


class TestAllowPath:
    def test_fully_eligible_service_is_allowed(self, config) -> None:
        decision = evaluate(config, request_for(21))
        assert decision.verdict is Verdict.ALLOW, decision.blocking_reason
        assert decision.allowed
        assert decision.blocking_reason is None
        assert all(r.passed for r in decision.rules)

    def test_decision_records_every_rule(self, config) -> None:
        decision = evaluate(config, request_for(21))
        names = {r.rule for r in decision.rules}
        assert names == {
            "input_validation",
            "protocol_supported",
            "authorized_lab_target",
            "protected_port",
            "management_channel",
            "service_policy",
            "correlation_confidence",
            "severity_threshold",
            "isolation_supported",
        }


class TestProtectedPorts:
    @pytest.mark.parametrize("port", [22, 80, 443])
    def test_protected_ports_are_always_denied(self, config, port: int) -> None:
        decision = evaluate(config, request_for(port))
        assert decision.verdict is Verdict.DENY
        assert not decision.allowed

    def test_protected_port_denial_names_the_rule(self, config) -> None:
        decision = evaluate(config, request_for(80))
        rule = rule_named(decision, "protected_port")
        assert rule is not None and not rule.passed
        assert "protected port" in rule.detail.lower()

    def test_critical_severity_cannot_override_protection(self, config) -> None:
        # The central safety claim: severity never outranks a protected port.
        decision = evaluate(
            config, request_for(22, max_severity="CRITICAL", max_confidence="HIGH")
        )
        assert decision.verdict is Verdict.DENY

    def test_empty_protected_list_is_rejected_at_load(self, tmp_path) -> None:
        directory = write_config_dir(
            tmp_path / "config", **{"protected_ports.yaml": "protected_ports: []\n"}
        )
        with pytest.raises(Exception, match="protected"):
            load_config(directory)


class TestAntiLockout:
    def test_management_channel_is_protected(self, tmp_path) -> None:
        # Target administered over tcp/2222. Port 22 is on the protected list but
        # 2222 is not, so only the management-channel rule can catch this.
        targets = """
targets:
  - name: lab-net
    cidr: 192.168.56.0/24
    is_lab: true
    ssh_port: 2222
    ssh_user: labadmin
"""
        services = """
default_policy: review_required
services:
  - port: 2222
    proto: tcp
    policy: eligible_for_isolation
    reason: "Deliberately misclassified to test the anti-lockout guard."
minimum_severity_for_eligibility: HIGH
minimum_confidence_for_eligibility: MEDIUM
"""
        directory = write_config_dir(
            tmp_path / "config",
            **{"authorized_targets.yaml": targets, "approved_services.yaml": services},
        )
        config = load_config(directory)

        decision = evaluate(config, request_for(2222))
        assert decision.verdict is Verdict.DENY
        rule = rule_named(decision, "management_channel")
        assert rule is not None and not rule.passed
        assert "roll back" in rule.detail


class TestServicePolicy:
    def test_approved_service_is_denied(self, config) -> None:
        decision = evaluate(config, request_for(3306))
        assert decision.verdict is Verdict.DENY
        assert "approved" in decision.blocking_reason

    def test_unclassified_port_goes_to_review_not_denial(self, config) -> None:
        # An open port nobody classified must not be treated as hostile.
        decision = evaluate(config, request_for(9999))
        assert decision.verdict is Verdict.REVIEW_REQUIRED

    def test_review_required_is_not_allowed(self, config) -> None:
        assert not evaluate(config, request_for(9999)).allowed


class TestConfidenceAndSeverity:
    def test_low_confidence_goes_to_review(self, config) -> None:
        decision = evaluate(config, request_for(21, max_confidence="LOW"))
        assert decision.verdict is Verdict.REVIEW_REQUIRED
        assert "confidence" in decision.blocking_reason.lower()

    def test_missing_confidence_goes_to_review(self, config) -> None:
        assert evaluate(config, request_for(21, max_confidence=None)).verdict is (
            Verdict.REVIEW_REQUIRED
        )

    def test_low_severity_goes_to_review(self, config) -> None:
        decision = evaluate(config, request_for(21, max_severity="MEDIUM"))
        assert decision.verdict is Verdict.REVIEW_REQUIRED
        assert "severity" in decision.blocking_reason.lower()

    def test_missing_severity_goes_to_review(self, config) -> None:
        # No CVSS score from NVD must never be read as "safe to act".
        assert evaluate(config, request_for(21, max_severity=None)).verdict is (
            Verdict.REVIEW_REQUIRED
        )

    def test_high_severity_alone_does_not_allow(self, config) -> None:
        # Spec §12: a high CVSS score must not by itself trigger isolation.
        decision = evaluate(config, request_for(3306, max_severity="CRITICAL"))
        assert decision.verdict is not Verdict.ALLOW


class TestAuthorizationGate:
    def test_out_of_scope_target_is_denied(self, config) -> None:
        assert evaluate(config, request_for(21, target_address="8.8.8.8")).verdict is (
            Verdict.DENY
        )

    def test_assessment_only_target_is_denied(self, config) -> None:
        assert evaluate(
            config, request_for(21, target_address="10.10.0.5")
        ).verdict is Verdict.DENY

    def test_malformed_target_is_denied(self, config) -> None:
        assert evaluate(
            config, request_for(21, target_address="not-an-ip")
        ).verdict is Verdict.DENY

    def test_invalid_port_is_denied(self, config) -> None:
        assert evaluate(config, request_for(70000)).verdict is Verdict.DENY


class TestNoOverrideExists:
    def test_evaluate_accepts_no_bypass_parameter(self) -> None:
        # Spec §6B: there must be no force=true style bypass. Asserting on the
        # signature keeps that guarantee from being quietly reintroduced.
        params = set(inspect.signature(evaluate).parameters)
        assert params == {"config", "request"}

    def test_isolation_request_has_no_override_field(self) -> None:
        fields = set(IsolationRequest.__dataclass_fields__)
        forbidden = {"force", "override", "bypass", "skip_checks", "ignore_protected"}
        assert not (fields & forbidden)


class TestFailClosed:
    def test_unknown_protocol_denies(self, config) -> None:
        assert evaluate(config, request_for(21, proto="icmp")).verdict is Verdict.DENY

    def test_udp_is_denied_as_unsupported(self, config) -> None:
        # UDP passes protocol validation but no UDP isolation backend exists.
        # It must be a hard DENY, not REVIEW_REQUIRED: review implies a human
        # could approve it, and here no approval could make it work.
        decision = evaluate(config, request_for(21, proto="udp"))
        assert decision.verdict is Verdict.DENY
        rule = rule_named(decision, "protocol_supported")
        assert rule is not None and not rule.passed

    def test_udp_denial_precedes_policy_evaluation(self, config) -> None:
        # The capability gate must short-circuit before the policy rules, so an
        # unimplementable request can never be reported as merely needing review.
        decision = evaluate(config, request_for(21, proto="udp"))
        assert rule_named(decision, "service_policy") is None

    def test_decision_serialises_for_audit(self, config) -> None:
        payload = evaluate(config, request_for(22)).to_dict()
        assert payload["verdict"] == "DENY"
        assert payload["port"] == 22
        assert len(payload["rules"]) >= 3
