"""The Scans page must offer the operator's OWN authorized targets.

The bug this locks down: the target box and the empty-scope banner both read
`safety.authorized_targets`, which is the install-wide config scope shared by
every account. A target the operator had just added on the Targets page
appeared nowhere on the Scans page, and the box stayed pre-filled with the
laboratory range — so the tool read as though the laboratory were the only
thing it would ever scan, even though the backend would have accepted the
operator's target perfectly well.
"""

from __future__ import annotations

import pytest
from fastapi.templating import Jinja2Templates

from backend.core.config import PROJECT_ROOT

TEMPLATES = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend" / "templates"))


def render(**overrides) -> str:
    """Render scans.html with a minimal but realistic context."""
    context = {
        "page": "scans",
        "user": None,
        "my_target_count": 0,
        "safety": {
            "authorization_signed": True,
            # The shared config scope: a laboratory range the operator did not
            # add and may not have any interest in.
            "authorized_targets": [
                {"name": "cybershield-lab", "range": "192.168.64.8/29", "is_lab": True}
            ],
            "protected_ports": [],
            "live_remediation_enabled": False,
            "remediation_backend": "dryrun",
            "remediation_ttl_minutes": 30,
        },
        "scans": [],
        "jobs": [],
        "running": False,
        "queued": None,
        "error": None,
        "profile_groups": {"discovery": [], "service_detect": []},
        "default_profile": "lan_service_detect",
        "preview": None,
        "typed_target": "",
        "last_summary": None,
        "selected_kind": "service_detect",
        "selected_profile": "",
        "unreachable_causes": (),
        "selectable_targets": [],
    }
    context.update(overrides)
    return TEMPLATES.get_template("scans.html").render(**context)


MY_TARGET = {
    "cidr": "192.168.1.25/32",
    "name": "my-laptop",
    "scope": "yours",
    "is_lab": False,
}
SHARED_LAB = {
    "cidr": "192.168.64.8/29",
    "name": "cybershield-lab",
    "scope": "shared",
    "is_lab": True,
}


class TestTheOperatorsOwnTargets:
    def test_an_added_target_appears_on_the_page(self) -> None:
        body = render(selectable_targets=[MY_TARGET, SHARED_LAB])
        assert "192.168.1.25/32" in body

    def test_the_form_prefills_the_operators_own_target_first(self) -> None:
        # Not the laboratory range, which is what it used to do regardless of
        # what the operator had authorized.
        body = render(selectable_targets=[MY_TARGET, SHARED_LAB])
        assert 'value="192.168.1.25/32"' in body

    def test_a_typed_target_still_wins_over_the_prefill(self) -> None:
        body = render(selectable_targets=[MY_TARGET, SHARED_LAB], typed_target="10.0.0.9/32")
        assert 'value="10.0.0.9/32"' in body

    def test_the_shared_scope_is_still_offered(self) -> None:
        # Fixing the per-user case must not hide the laboratory.
        body = render(selectable_targets=[MY_TARGET, SHARED_LAB])
        assert "192.168.64.8/29" in body


class TestEmptyScopeBanner:
    def test_no_selectable_targets_warns(self) -> None:
        body = render(selectable_targets=[])
        assert "No authorized targets" in body

    def test_an_operator_with_only_their_own_target_is_not_warned(self) -> None:
        # The banner used to key on the config scope alone, so an operator who
        # had authorized their own target was still told they had none.
        body = render(
            selectable_targets=[MY_TARGET],
            safety={
                "authorization_signed": True,
                "authorized_targets": [],
                "protected_ports": [],
                "live_remediation_enabled": False,
                "remediation_backend": "dryrun",
                "remediation_ttl_minutes": 30,
            },
        )
        assert "No authorized targets" not in body
