"""Authorized-target validation and unauthorized-target rejection (spec §6A, §25)."""

from __future__ import annotations

import pytest

from backend.core.authorization import (
    AuthorizationDenied,
    assert_authorized_lab_target,
    assert_in_scope,
    check_in_scope,
)
from backend.core.config import ConfigError, load_config
from tests.conftest import write_config_dir


class TestScopeChecking:
    def test_address_inside_authorized_range_is_allowed(self, config) -> None:
        decision = check_in_scope(config, "192.168.56.10")
        assert decision.allowed
        assert decision.authorizing_entry == "lab-net"

    @pytest.mark.parametrize(
        "address",
        [
            "192.168.57.10",  # adjacent subnet
            "8.8.8.8",  # public
            "127.0.0.1",  # loopback, still not in scope
            "172.16.0.1",  # private but unlisted
        ],
    )
    def test_address_outside_scope_is_refused(self, config, address: str) -> None:
        assert not check_in_scope(config, address).allowed

    def test_malformed_address_is_refused(self, config) -> None:
        decision = check_in_scope(config, "not-an-ip")
        assert not decision.allowed

    def test_range_partially_overlapping_scope_is_refused(self, config) -> None:
        # A /16 containing the authorized /24 must NOT be allowed — it would
        # pull 255 unauthorized subnets into the scan.
        assert not check_in_scope(config, "192.168.0.0/16").allowed

    def test_subrange_of_authorized_range_is_allowed(self, config) -> None:
        assert check_in_scope(config, "192.168.56.0/28").allowed


class TestAssertInScope:
    def test_raises_when_authorization_unsigned(self, config, monkeypatch) -> None:
        # An in-scope target must still be refused while the authorization is
        # unsigned. The unsigned record is injected rather than read from the
        # repository's AUTHORIZATION.md: once an operator signs that file for
        # real work, a test depending on its contents would silently stop
        # testing anything.
        from backend.core import authorization as auth_module
        from backend.core.config import AuthorizationRecord

        monkeypatch.setattr(
            auth_module,
            "load_authorization",
            lambda *a, **k: AuthorizationRecord(
                signed=False,
                operator_name="",
                institution="",
                date="",
                scope_description="",
                problems=("AUTHORIZATION.md is not signed (signed: false).",),
            ),
        )
        with pytest.raises(AuthorizationDenied, match="not signed"):
            assert_in_scope(config, "192.168.56.10")

    def test_allows_in_scope_when_signed(self, config, signed_authorization) -> None:
        assert assert_in_scope(config, "192.168.56.10").name == "lab-net"

    def test_refuses_out_of_scope_when_signed(self, config, signed_authorization) -> None:
        with pytest.raises(AuthorizationDenied, match="not inside any authorized range"):
            assert_in_scope(config, "8.8.8.8")


class TestLabTargetGate:
    def test_lab_target_permits_remediation(self, config, signed_authorization) -> None:
        assert assert_authorized_lab_target(config, "192.168.56.10").is_lab

    def test_assessment_only_target_refuses_remediation(
        self, config, signed_authorization
    ) -> None:
        # In scope for scanning, but is_lab is false. Scanning permission must
        # never imply permission to modify.
        assert check_in_scope(config, "10.10.0.5").allowed
        with pytest.raises(AuthorizationDenied, match="is_lab"):
            assert_authorized_lab_target(config, "10.10.0.5")

    def test_out_of_scope_target_refuses_remediation(
        self, config, signed_authorization
    ) -> None:
        with pytest.raises(AuthorizationDenied):
            assert_authorized_lab_target(config, "203.0.113.5")


class TestEmptyAndUnsafeScope:
    def test_empty_scope_refuses_everything(self, tmp_path, signed_authorization) -> None:
        directory = write_config_dir(
            tmp_path / "config", **{"authorized_targets.yaml": "targets: []\n"}
        )
        config = load_config(directory)
        decision = check_in_scope(config, "192.168.56.10")
        assert not decision.allowed
        assert "no targets" in decision.reason.lower()

    def test_public_range_is_rejected_at_load_time(self, tmp_path) -> None:
        # Guards against a typo putting a routable range into scope.
        unsafe = """
targets:
  - name: oops
    cidr: 8.8.8.0/24
    is_lab: false
"""
        directory = write_config_dir(
            tmp_path / "config", **{"authorized_targets.yaml": unsafe}
        )
        with pytest.raises(ConfigError, match="public range"):
            load_config(directory)

    def test_lab_target_without_ssh_user_is_rejected(self, tmp_path) -> None:
        # A rule that cannot be rolled back is not a reversible action.
        broken = """
targets:
  - name: no-ssh
    cidr: 192.168.56.0/24
    is_lab: true
"""
        directory = write_config_dir(
            tmp_path / "config", **{"authorized_targets.yaml": broken}
        )
        with pytest.raises(ConfigError, match="ssh_user"):
            load_config(directory)
