"""Shared test fixtures.

Tests build their own throwaway config directory rather than reading the real
`config/`, so the suite cannot be affected by (or affect) the operator's actual
authorized scope.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.config import load_config  # noqa: E402

AUTHORIZED_TARGETS_YAML = """
targets:
  - name: lab-net
    cidr: 192.168.56.0/24
    is_lab: true
    ssh_port: 22
    ssh_user: labadmin
    notes: "Test laboratory network."
  - name: assessment-only-net
    cidr: 10.10.0.0/24
    is_lab: false
    notes: "In scope for scanning, not for remediation."
"""

PROTECTED_PORTS_YAML = """
protected_ports:
  - port: 22
    proto: tcp
    reason: "SSH management channel."
  - port: 80
    proto: tcp
    reason: "HTTP."
  - port: 443
    proto: tcp
    reason: "HTTPS."
protect_active_management_channel: true
"""

APPROVED_SERVICES_YAML = """
default_policy: review_required
services:
  - port: 22
    proto: tcp
    policy: protected
    reason: "SSH."
  - port: 21
    proto: tcp
    policy: eligible_for_isolation
    reason: "Legacy cleartext FTP."
  - port: 8080
    proto: tcp
    policy: eligible_for_isolation
    reason: "Legacy HTTP test service."
  - port: 3306
    proto: tcp
    policy: approved
    reason: "Approved database service for this lab."
minimum_severity_for_eligibility: HIGH
minimum_confidence_for_eligibility: MEDIUM
"""

SCAN_PROFILES_YAML = """
profiles:
  discovery:
    description: "Host discovery."
    args: ["-sn", "-n"]
    timeout_seconds: 300
  service_detect:
    description: "Service and version detection."
    args: ["-sT", "-sV", "-n", "--top-ports", "1000"]
    timeout_seconds: 1800
default_profile: service_detect
global_max_timeout_seconds: 7200
"""


def write_config_dir(directory: Path, **overrides: str) -> Path:
    """Write a complete, valid config directory. Any file can be overridden."""
    files = {
        "authorized_targets.yaml": AUTHORIZED_TARGETS_YAML,
        "protected_ports.yaml": PROTECTED_PORTS_YAML,
        "approved_services.yaml": APPROVED_SERVICES_YAML,
        "scan_profiles.yaml": SCAN_PROFILES_YAML,
    }
    files.update(overrides)
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (directory / name).write_text(content)
    return directory


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    return write_config_dir(tmp_path / "config")


@pytest.fixture
def config(config_dir: Path):
    return load_config(config_dir)


@pytest.fixture
def signed_authorization(monkeypatch: pytest.MonkeyPatch):
    """Treat AUTHORIZATION.md as signed for tests that need to get past it."""
    from backend.core import authorization as auth_module
    from backend.core.config import AuthorizationRecord

    monkeypatch.setattr(
        auth_module,
        "load_authorization",
        lambda *a, **k: AuthorizationRecord(
            signed=True,
            operator_name="Test Operator",
            institution="Test University",
            date="2026-08-30",
            scope_description="Isolated test laboratory.",
            problems=(),
        ),
    )
