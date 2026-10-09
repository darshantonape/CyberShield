"""Remediation backends, plans and executor refusals (spec §13-§15, §25)."""

from __future__ import annotations

import inspect

import pytest

from backend.core.validation import ValidationError
from backend.remediation.backends.base import BackendError
from backend.remediation.backends.dryrun import DryRunBackend
from backend.remediation.backends.nftables import NftablesBackend, _parse_set_elements
from backend.remediation.executor import ExecutionError, apply_plan
from backend.remediation.plan import PlanError, RemediationPlan, build_plan, get_backend
from backend.risk.decision import IsolationRequest, Verdict

pytestmark = pytest.mark.usefixtures("signed_authorization")


def request_for(port: int = 21, **kwargs) -> IsolationRequest:
    params = {
        "target_address": "192.168.56.10",
        "port": port,
        "proto": "tcp",
        "max_severity": "CRITICAL",
        "max_confidence": "HIGH",
    }
    params.update(kwargs)
    return IsolationRequest(**params)


class TestNftablesCommands:
    @pytest.fixture
    def backend(self) -> NftablesBackend:
        return NftablesBackend()

    def test_apply_adds_a_set_element(self, backend) -> None:
        assert backend.apply_argv(21, "tcp") == [
            "nft", "add", "element", "inet", "cybershield", "blocked_tcp", "{ 21 }"
        ]

    def test_rollback_is_the_exact_inverse(self, backend) -> None:
        apply = backend.apply_argv(21, "tcp")
        revert = backend.rollback_argv(21, "tcp")
        # Identical but for the verb: this is what makes rollback derivable
        # before the forward command has ever run.
        assert apply[1] == "add" and revert[1] == "delete"
        assert apply[2:] == revert[2:]

    def test_rollback_is_derivable_without_applying(self, backend) -> None:
        # nftables can only delete a RULE by handle, and handles are assigned at
        # insertion. Set elements delete by value, so no prior state is needed.
        assert backend.rollback_argv(3306, "tcp")[-1] == "{ 3306 }"

    def test_commands_touch_only_the_cybershield_table(self, backend) -> None:
        for argv in (backend.apply_argv(21, "tcp"), backend.rollback_argv(21, "tcp")):
            assert "cybershield" in argv
            assert "filter" not in argv  # never the system's own table

    @pytest.mark.parametrize("port", [0, -1, 65536, "21; rm -rf /", None])
    def test_invalid_ports_are_rejected(self, backend, port) -> None:
        with pytest.raises(ValidationError):
            backend.apply_argv(port, "tcp")

    def test_non_tcp_is_refused(self, backend) -> None:
        with pytest.raises(BackendError, match="TCP"):
            backend.apply_argv(21, "udp")

    def test_every_argument_is_a_plain_string(self, backend) -> None:
        assert all(isinstance(a, str) for a in backend.apply_argv(21, "tcp"))


class TestSetParsing:
    def test_parses_elements(self) -> None:
        listing = (
            "table inet cybershield {\n\tset blocked_tcp {\n\t\ttype inet_service\n"
            "\t\telements = { 21, 3306 }\n\t}\n}"
        )
        assert _parse_set_elements(listing) == {21, 3306}

    def test_empty_set_has_no_elements(self) -> None:
        listing = "table inet cybershield {\n\tset blocked_tcp {\n\t\ttype inet_service\n\t}\n}"
        assert _parse_set_elements(listing) == set()

    def test_garbage_does_not_raise(self) -> None:
        assert _parse_set_elements("not nft output") == set()


class TestDryRunBackend:
    def test_renders_identical_commands_to_the_live_backend(self) -> None:
        # If they diverged, the preview would stop predicting the live run,
        # which is the only reason a preview is worth anything.
        assert DryRunBackend().apply_argv(21, "tcp") == NftablesBackend().apply_argv(21, "tcp")
        assert DryRunBackend().rollback_argv(21, "tcp") == NftablesBackend().rollback_argv(21, "tcp")

    def test_declares_that_it_does_not_execute(self) -> None:
        assert DryRunBackend().executes is False
        assert NftablesBackend().executes is True

    def test_reports_not_blocked_rather_than_echoing_intent(self) -> None:
        # A dry run must never look like evidence of isolation.
        state = DryRunBackend().read_state(None, 21, "tcp")  # type: ignore[arg-type]
        assert state.blocked is False
        assert "dry-run" in state.raw

    def test_is_the_default_backend(self, monkeypatch) -> None:
        # Tests the code default, not the operator's local .env: once live
        # enforcement is armed for real work, a test reading .env would silently
        # stop checking that dry-run is what a fresh install gets.
        from backend.core import config as config_module

        monkeypatch.setattr(config_module, "_load_dotenv", lambda *a, **k: None)
        monkeypatch.delenv("CYBERSHIELD_REMEDIATION_BACKEND", raising=False)

        settings = config_module._load_settings()
        assert settings.remediation_backend == "dryrun"
        assert settings.live_remediation_enabled is False

    def test_shipped_env_example_defaults_to_dry_run(self) -> None:
        from backend.core.config import PROJECT_ROOT

        example = (PROJECT_ROOT / ".env.example").read_text()
        assert "CYBERSHIELD_REMEDIATION_BACKEND=dryrun" in example

    def test_live_enforcement_must_be_opted_into(self, monkeypatch) -> None:
        from backend.core import config as config_module

        monkeypatch.setattr(config_module, "_load_dotenv", lambda *a, **k: None)
        monkeypatch.setenv("CYBERSHIELD_REMEDIATION_BACKEND", "nftables")
        assert config_module._load_settings().live_remediation_enabled is True


class TestBackendRegistry:
    def test_known_backends(self) -> None:
        assert isinstance(get_backend("nftables"), NftablesBackend)
        assert isinstance(get_backend("dryrun"), DryRunBackend)

    def test_ufw_is_not_registered(self) -> None:
        # No ufw backend has been written or tested; registering an untested one
        # would let the system claim a capability it does not have.
        with pytest.raises(PlanError, match="Unknown remediation backend"):
            get_backend("ufw")


class TestPlanConstruction:
    def test_allowed_plan_carries_both_commands(self, config) -> None:
        plan = build_plan(config, request_for(21))
        assert plan.decision.verdict is Verdict.ALLOW
        assert plan.apply_argv and plan.rollback_argv
        assert plan.apply_argv != plan.rollback_argv

    def test_rollback_exists_even_before_apply(self, config) -> None:
        # The property that makes a crash between apply and record survivable.
        plan = build_plan(config, request_for(21))
        assert "delete" in plan.rollback_argv

    def test_plan_has_an_expiry(self, config) -> None:
        assert build_plan(config, request_for(21)).expires_at is not None

    def test_refused_request_still_produces_an_explanatory_plan(self, config) -> None:
        # Operators need to see what WOULD have run and why it was refused.
        plan = build_plan(config, request_for(22))
        assert plan.decision.verdict is Verdict.DENY
        assert not plan.allowed
        assert plan.apply_argv

    def test_plan_states_it_does_not_patch(self, config) -> None:
        payload = build_plan(config, request_for(21)).to_dict()
        assert "does NOT patch" in payload["effect"]

    def test_out_of_scope_plan_has_no_management_channel(self, config) -> None:
        plan = build_plan(config, request_for(21, target_address="8.8.8.8"))
        assert plan.decision.verdict is Verdict.DENY
        assert plan.ssh_port == 0


class TestExecutorRefusals:
    """Every refusal must happen before anything is sent to a target."""

    def test_unconfirmed_action_is_refused(self, config) -> None:
        plan = build_plan(config, request_for(21))
        with pytest.raises(ExecutionError, match="confirmation is required"):
            apply_plan(config, plan, confirmed=False)

    def test_denied_verdict_cannot_be_applied(self, config) -> None:
        plan = build_plan(config, request_for(22))  # protected port
        with pytest.raises(ExecutionError, match="DENY"):
            apply_plan(config, plan, confirmed=True)

    def test_review_required_cannot_be_applied(self, config) -> None:
        plan = build_plan(config, request_for(9999))  # unclassified port
        with pytest.raises(ExecutionError, match="REVIEW_REQUIRED"):
            apply_plan(config, plan, confirmed=True)

    def test_confirmation_cannot_override_a_denial(self, config) -> None:
        # confirm is an acknowledgement, never an override.
        plan = build_plan(config, request_for(22))
        with pytest.raises(ExecutionError):
            apply_plan(config, plan, confirmed=True)


class TestNoOverridePath:
    def test_apply_plan_has_no_bypass_parameter(self) -> None:
        params = set(inspect.signature(apply_plan).parameters)
        forbidden = {"force", "override", "bypass", "skip_checks", "ignore_protected"}
        assert not (params & forbidden)

    def test_confirmed_is_required_not_defaulted(self) -> None:
        # An omitted confirmation must be a refusal, not an approval.
        assert inspect.signature(apply_plan).parameters["confirmed"].default is inspect.Parameter.empty

    def test_plan_dataclass_has_no_override_field(self) -> None:
        forbidden = {"force", "override", "bypass"}
        assert not (set(RemediationPlan.__dataclass_fields__) & forbidden)

    def test_api_apply_request_has_no_force_field(self) -> None:
        from backend.main import ApplyRequest

        fields = set(ApplyRequest.model_fields)
        assert not (fields & {"force", "override", "bypass", "skip_checks"})
        assert "confirm" in fields


class FakeSession:
    """Records argv sequences and replays scripted results.

    Stands in for a real SSH session so the EXECUTED nftables path can be
    tested without enabling live enforcement or touching a target. Only the
    surface NftablesBackend uses is implemented.
    """

    def __init__(self, responses=None):
        self.calls: list[list[str]] = []
        self._responses = responses or {}

    def run(self, argv, *, timeout: float = 30.0):
        from backend.remediation.ssh_adapter import SshResult

        args = list(argv)
        self.calls.append(args)
        key = " ".join(args)
        status, out, err = self._responses.get(key, (0, "", ""))
        for pattern, value in self._responses.items():
            if pattern != key and pattern in key:
                status, out, err = value
        return SshResult(
            argv=tuple(args), command=key, exit_status=status, stdout=out, stderr=err
        )


class TestExecutedNftablesPath:
    """The live backend's actual command sequence, against a fake session.

    Live enforcement is off by configuration, so this is the level at which the
    executed path can be verified honestly: what it sends, in what order, and
    what it concludes from the replies.
    """

    import pytest as _pytest

    @_pytest.fixture
    def backend(self):
        from backend.remediation.backends.nftables import NftablesBackend

        return NftablesBackend()

    def test_prepare_creates_table_set_and_chain_then_the_rule(self, backend) -> None:
        session = FakeSession()
        backend.ensure_prepared(session)
        sent = [" ".join(c) for c in session.calls]
        assert sent[0] == "nft add table inet cybershield"
        assert sent[1].startswith("nft add set inet cybershield blocked_tcp")
        assert sent[2].startswith("nft add chain inet cybershield input")
        assert "nft list chain inet cybershield input" in sent
        assert any("add rule inet cybershield input tcp dport @blocked_tcp drop" in s
                   for s in sent)

    def test_prepare_does_not_stack_a_duplicate_drop_rule(self, backend) -> None:
        # A chain that already references the set must not get a second rule.
        session = FakeSession({"nft list chain inet cybershield input":
                               (0, "tcp dport @blocked_tcp drop", "")})
        backend.ensure_prepared(session)
        added = [c for c in session.calls if c[1:3] == ["add", "rule"]]
        assert added == []

    def test_prepare_raises_rather_than_continuing_on_failure(self, backend) -> None:
        from backend.remediation.backends.base import BackendError

        session = FakeSession({"nft add table inet cybershield": (1, "", "Operation not permitted")})
        with self._pytest.raises(BackendError, match="Operation not permitted"):
            backend.ensure_prepared(session)

    def test_prepare_never_touches_a_table_it_does_not_own(self, backend) -> None:
        session = FakeSession()
        backend.ensure_prepared(session)
        for call in session.calls:
            assert "cybershield" in call, f"{call} escapes the cybershield table"
            assert "flush" not in call
            assert "ruleset" not in call

    def test_read_state_reports_blocked_when_the_port_is_in_the_set(self, backend) -> None:
        listing = ("table inet cybershield {\n  set blocked_tcp {\n"
                   "    type inet_service\n    elements = { 21, 3306 }\n  }\n}")
        session = FakeSession({"nft list set inet cybershield blocked_tcp": (0, listing, "")})
        assert backend.read_state(session, 21).blocked is True
        assert backend.read_state(session, 3306).blocked is True
        assert backend.read_state(session, 6379).blocked is False

    def test_read_state_reports_not_blocked_when_the_set_is_absent(self, backend) -> None:
        session = FakeSession({"nft list set inet cybershield blocked_tcp":
                               (1, "", "No such file or directory")})
        state = backend.read_state(session, 21)
        assert state.blocked is False

    def test_the_apply_then_read_round_trip_agrees(self, backend) -> None:
        # Apply 21, then a listing that contains it: the backend must agree the
        # port is blocked. This is the cross-check the executor relies on.
        session = FakeSession({"nft list set inet cybershield blocked_tcp":
                               (0, "elements = { 21 }", "")})
        apply_result = session.run(backend.apply_argv(21))
        assert apply_result.ok
        assert backend.read_state(session, 21).blocked is True

    def test_rollback_argv_is_the_exact_inverse_of_what_was_sent(self, backend) -> None:
        applied = backend.apply_argv(21)
        reverted = backend.rollback_argv(21)
        assert applied[1] == "add" and reverted[1] == "delete"
        assert applied[2:] == reverted[2:], "only the verb may differ"

    def test_no_caller_text_can_reach_the_target(self, backend) -> None:
        # Every element is a fixed literal or a validated integer.
        for argv in (backend.apply_argv(21), backend.rollback_argv(21),
                     backend.list_set_argv("tcp")):
            for token in argv:
                assert isinstance(token, str)
                assert ";" not in token and "&" not in token and "|" not in token
                assert "$" not in token and "`" not in token
