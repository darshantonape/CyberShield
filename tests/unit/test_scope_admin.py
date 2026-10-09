"""Scope management from the operator interface.

The property under test throughout: the UI can bring a private target into
scope, and can do nothing else. It cannot authorize a routable address, cannot
make a target remediable, cannot skip confirmation, and cannot leave the scope
file in a state that refuses the laboratory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.core.config import load_config
from backend.core.scope_admin import (
    ScopeError,
    add_authorized_target,
    describe_target_scope,
    remove_authorized_target,
    suggest_scope_entries,
)
from tests.conftest import write_config_dir


@pytest.fixture
def scope(tmp_path: Path) -> tuple[Path, Path]:
    """A throwaway config directory plus an audit path. Returns (file, audit)."""
    directory = write_config_dir(tmp_path / "config")
    return directory / "authorized_targets.yaml", tmp_path / "audit.jsonl"


def _add(scope, target: str, **kwargs):
    targets_file, audit = scope
    kwargs.setdefault("confirmed", True)
    return add_authorized_target(
        target, targets_file=targets_file, audit_path=audit, **kwargs
    )


class TestConfirmation:
    def test_unconfirmed_request_is_refused(self, scope) -> None:
        with pytest.raises(ScopeError, match="confirmed explicitly"):
            _add(scope, "192.168.1.25", confirmed=False)

    def test_nothing_is_written_when_refused(self, scope) -> None:
        targets_file, _ = scope
        before = targets_file.read_text()
        with pytest.raises(ScopeError):
            _add(scope, "192.168.1.25", confirmed=False)
        assert targets_file.read_text() == before


class TestPrivateOnly:
    @pytest.mark.parametrize(
        "target",
        [
            "8.8.8.8",
            "1.1.1.1/32",
            "0.0.0.0/0",
            # Reserved documentation range. `IPv4Network.is_private` returns
            # True for it, so relying on that property alone would have let a
            # public-looking address into scope.
            "203.0.113.0/24",
            "198.18.0.0/24",
            "100.64.0.0/24",
        ],
    )
    def test_public_and_reserved_ranges_are_refused(self, scope, target: str) -> None:
        with pytest.raises(ScopeError):
            _add(scope, target)

    @pytest.mark.parametrize(
        "target",
        ["192.168.1.25", "192.168.1.25/32", "10.20.30.0/24", "172.16.5.0/24"],
    )
    def test_private_ranges_are_accepted(self, scope, target: str) -> None:
        assert _add(scope, target).cidr

    def test_loopback_is_accepted(self, scope) -> None:
        # Useful for verifying the scanner against this machine.
        assert _add(scope, "127.0.0.1").cidr == "127.0.0.1/32"

    def test_ipv6_is_refused_clearly(self, scope) -> None:
        with pytest.raises(ScopeError, match="IPv6"):
            _add(scope, "fe80::1")

    def test_hostname_is_refused(self, scope) -> None:
        # DNS could resolve to a different address than the one authorized.
        with pytest.raises(ScopeError):
            _add(scope, "some-laptop.local")

    def test_garbage_is_refused(self, scope) -> None:
        with pytest.raises(ScopeError):
            _add(scope, "not-an-address")


class TestRangeSize:
    def test_oversized_private_range_is_refused(self, scope) -> None:
        with pytest.raises(ScopeError, match="largest range"):
            _add(scope, "10.0.0.0/8")

    def test_a_slash_24_is_accepted(self, scope) -> None:
        assert _add(scope, "192.168.7.0/24").address_count == 256


class TestAssessmentOnly:
    def test_ui_added_target_is_never_a_lab_target(self, scope) -> None:
        targets_file, _ = scope
        _add(scope, "192.168.1.25", name="friend-laptop")
        config = load_config(targets_file.parent)
        entry = config.find_authorized_target("192.168.1.25")
        assert entry is not None
        # The whole point: scannable, never firewall-modifiable.
        assert entry.is_lab is False

    def test_remediation_is_refused_on_a_ui_added_target(self, scope) -> None:
        from backend.core.authorization import AuthorizationDenied, assert_authorized_lab_target

        targets_file, _ = scope
        _add(scope, "192.168.1.25")
        config = load_config(targets_file.parent)
        with pytest.raises(AuthorizationDenied, match="is_lab"):
            assert_authorized_lab_target(config, "192.168.1.25")


class TestScopeEnforcement:
    def test_target_is_in_scope_only_after_being_added(self, scope) -> None:
        from backend.core.authorization import check_in_scope

        targets_file, _ = scope
        config = load_config(targets_file.parent)
        assert check_in_scope(config, "192.168.0.176").allowed is False

        _add(scope, "192.168.0.176")
        config = load_config(targets_file.parent)
        assert check_in_scope(config, "192.168.0.176").allowed is True

        # And only that address: a /32 does not authorize its neighbours.
        assert check_in_scope(config, "192.168.0.177").allowed is False

    def test_adding_a_target_does_not_disturb_the_existing_lab(self, scope) -> None:
        from backend.core.authorization import check_in_scope

        targets_file, _ = scope
        _add(scope, "192.168.0.176")
        config = load_config(targets_file.parent)

        lab = config.find_authorized_target("192.168.56.10")
        assert lab is not None
        assert lab.is_lab is True
        assert lab.ssh_user == "labadmin"
        assert check_in_scope(config, "192.168.56.10").allowed is True


class TestDuplicates:
    def test_already_covered_range_is_reported_not_duplicated(self, scope) -> None:
        _add(scope, "192.168.1.0/24")
        with pytest.raises(ScopeError, match="already inside"):
            _add(scope, "192.168.1.25")

    def test_duplicate_label_is_refused(self, scope) -> None:
        _add(scope, "192.168.1.25", name="laptop")
        with pytest.raises(ScopeError, match="already exists"):
            _add(scope, "192.168.2.25", name="laptop")

    def test_a_target_inside_the_lab_range_is_reported_as_covered(self, scope) -> None:
        with pytest.raises(ScopeError, match="already inside"):
            _add(scope, "192.168.56.10")


class TestRemoval:
    def test_ui_added_target_can_be_removed(self, scope) -> None:
        targets_file, audit = scope
        change = _add(scope, "192.168.1.25", name="laptop")
        remove_authorized_target("laptop", targets_file=targets_file, audit_path=audit)
        config = load_config(targets_file.parent)
        assert config.find_authorized_target(change.cidr) is None

    def test_lab_target_cannot_be_removed_from_the_ui(self, scope) -> None:
        targets_file, audit = scope
        with pytest.raises(ScopeError, match="laboratory target"):
            remove_authorized_target(
                "lab-net", targets_file=targets_file, audit_path=audit
            )

    def test_file_managed_target_cannot_be_removed_from_the_ui(self, scope) -> None:
        targets_file, audit = scope
        with pytest.raises(ScopeError, match="configured in"):
            remove_authorized_target(
                "assessment-only-net", targets_file=targets_file, audit_path=audit
            )

    def test_unknown_target_is_refused(self, scope) -> None:
        targets_file, audit = scope
        with pytest.raises(ScopeError, match="No authorized target"):
            remove_authorized_target(
                "nothing-like-this", targets_file=targets_file, audit_path=audit
            )


class TestAuditTrail:
    def test_authorization_is_audited(self, scope) -> None:
        _, audit = scope
        _add(scope, "192.168.1.25", name="laptop", operator="tester")
        text = audit.read_text()
        assert "scope.target_authorized" in text
        assert "192.168.1.25/32" in text
        assert "tester" in text

    def test_revocation_is_audited(self, scope) -> None:
        targets_file, audit = scope
        _add(scope, "192.168.1.25", name="laptop")
        remove_authorized_target("laptop", targets_file=targets_file, audit_path=audit)
        assert "scope.target_revoked" in audit.read_text()


class TestFileIntegrity:
    def test_the_file_still_loads_after_a_write(self, scope) -> None:
        targets_file, _ = scope
        _add(scope, "192.168.1.25")
        # Would raise ConfigError if the rewrite produced anything invalid.
        assert len(load_config(targets_file.parent).authorized_targets) == 3

    def test_a_write_that_would_break_the_file_is_rolled_back(
        self, scope, monkeypatch
    ) -> None:
        targets_file, audit = scope
        before = targets_file.read_text()

        # Simulate a rewrite that produces an unloadable file.
        from backend.core import scope_admin

        def broken_dump(*_args, **_kwargs):
            return "targets: [{name: bad, cidr: not-an-ip}]\n"

        monkeypatch.setattr(scope_admin.yaml, "safe_dump", broken_dump)
        with pytest.raises(ScopeError, match="restored"):
            _add(scope, "192.168.1.25")

        assert targets_file.read_text() == before
        assert len(load_config(targets_file.parent).authorized_targets) == 2

    def test_header_comment_is_preserved(self, scope) -> None:
        targets_file, _ = scope
        _add(scope, "192.168.1.25")
        text = targets_file.read_text()
        assert "FAIL-CLOSED" in text
        assert "allow_public" in text


class TestReporting:
    def test_describe_marks_provenance_and_removability(self, scope) -> None:
        targets_file, _ = scope
        _add(scope, "192.168.1.25", name="laptop")
        config = load_config(targets_file.parent)

        rows = {
            r["name"]: r
            for r in describe_target_scope(config, targets_file=targets_file)
        }
        assert rows["laptop"]["source"] == "operator_ui"
        assert rows["laptop"]["removable"] is True
        assert rows["laptop"]["is_lab"] is False
        assert rows["lab-net"]["removable"] is False
        assert rows["lab-net"]["is_lab"] is True

    def test_suggestions_authorize_nothing(self, scope) -> None:
        targets_file, _ = scope
        config = load_config(targets_file.parent)
        suggestions = suggest_scope_entries(config)
        from backend.core.authorization import check_in_scope

        for suggestion in suggestions:
            if not suggestion["already_authorized"]:
                # A detected subnet is a suggestion, not permission.
                assert check_in_scope(config, suggestion["cidr"]).allowed is False


class TestPerUserScopeUsesTheSameAllowlist:
    """backend.core.user_targets must refuse what this module refuses.

    The multi-tenant refactor moved the Targets page onto a per-user scope
    table, and that path checked `IPv4Network.is_private` instead of the
    explicit allowlist above. Python calls the RFC 5737 documentation ranges,
    the RFC 2544 benchmarking range, 240.0.0.0/4 and 0.0.0.0/8 "private", so
    203.0.113.5 — which looks exactly like a routable public address — could be
    authorized from the UI, contradicting both the README and
    docs/safety-controls.md.
    """

    import pytest as _pytest

    @_pytest.fixture
    def db(self, tmp_path):
        from backend.database.session import init_db

        path = tmp_path / "targets.db"
        init_db(path)
        return path

    @_pytest.fixture
    def user_id(self, db):
        from backend.auth.service import create_user

        return create_user(
            "scopeuser", "Correct-Horse-9", db_path=db, audit_path=db.parent / "a.jsonl"
        ).id

    @_pytest.mark.parametrize(
        "target",
        [
            "203.0.113.5/32",     # RFC 5737 TEST-NET-3
            "192.0.2.10/32",      # RFC 5737 TEST-NET-1
            "198.51.100.10/32",   # RFC 5737 TEST-NET-2
            "198.18.0.5/32",      # RFC 2544 benchmarking
            "240.0.0.5/32",       # reserved
            "8.8.8.8/32",         # plainly routable
        ],
    )
    def test_non_lan_ranges_are_refused(self, db, user_id, target) -> None:
        from backend.core.user_targets import UserTargetError, add_user_target

        with self._pytest.raises(UserTargetError):
            add_user_target(user_id, target, confirmed=True, db_path=db)

    @_pytest.mark.parametrize(
        "target",
        ["192.168.1.25/32", "10.0.0.25/32", "172.16.4.0/24", "127.0.0.1/32", "169.254.1.1/32"],
    )
    def test_real_lan_ranges_are_still_accepted(self, db, user_id, target) -> None:
        from backend.core.user_targets import add_user_target

        result = add_user_target(user_id, target, confirmed=True, db_path=db)
        assert result["cidr"] == target

    def test_both_paths_agree(self) -> None:
        # One allowlist, two callers. If this import breaks, they have drifted.
        import ipaddress

        from backend.core.scope_admin import AUTHORIZABLE_RANGES, is_authorizable

        assert is_authorizable(ipaddress.IPv4Network("192.168.1.0/24"))
        assert not is_authorizable(ipaddress.IPv4Network("203.0.113.0/24"))
        assert len(AUTHORIZABLE_RANGES) == 5
