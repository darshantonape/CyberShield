#!/usr/bin/env python3
"""Environment and safety preflight.

Run before any experiment:

    python scripts/preflight.py

Reports what is present, what is missing, and whether CyberShield is currently
authorized to act. Exits non-zero if a REQUIRED check fails, so it can gate a
scripted experiment run.

This script performs no scans and changes nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running directly from a checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.core.config import (  # noqa: E402
    DATA_DIR,
    ConfigError,
    load_authorization,
    load_config,
)
from backend.core.exec import CommandError, run_command  # noqa: E402

OK = "\033[32mOK\033[0m"
MISSING = "\033[31mMISSING\033[0m"
WARN = "\033[33mWARN\033[0m"
INFO = "\033[36mINFO\033[0m"

_required_failures: list[str] = []
_warnings: list[str] = []


def line(status: str, label: str, detail: str = "") -> None:
    print(f"  [{status}] {label}" + (f" — {detail}" if detail else ""))


def require_fail(message: str) -> None:
    _required_failures.append(message)


def warn(message: str) -> None:
    _warnings.append(message)


def check_python() -> None:
    print("\nPython")
    v = sys.version_info
    detail = f"{v.major}.{v.minor}.{v.micro} at {sys.executable}"
    if (v.major, v.minor) >= (3, 11):
        line(OK, "interpreter", detail)
    else:
        line(MISSING, "interpreter", f"{detail} — 3.11+ required")
        require_fail(
            f"Python {v.major}.{v.minor} is too old. Use /opt/homebrew/bin/python3.14."
        )


def check_nmap() -> None:
    print("\nScanner")
    try:
        result = run_command(["nmap", "--version"], timeout_seconds=15)
    except CommandError as exc:
        line(MISSING, "nmap", str(exc))
        require_fail("nmap is not installed. Install it with: brew install nmap")
        return

    if not result.ok:
        line(MISSING, "nmap", f"exited {result.returncode}")
        require_fail("nmap is present but did not run correctly.")
        return

    first_line = result.stdout.splitlines()[0] if result.stdout else "unknown version"
    line(OK, "nmap", f"{first_line} ({result.argv[0]})")


def check_config() -> None:
    print("\nConfiguration")
    try:
        config = load_config()
    except ConfigError as exc:
        line(MISSING, "config", str(exc))
        require_fail(f"Configuration failed to load: {exc}")
        return

    line(OK, "policy files", f"config hash {config.config_hash}")

    if config.authorized_targets:
        for target in config.authorized_targets:
            flag = "lab (remediable)" if target.is_lab else "assessment only"
            line(OK, f"scope: {target.name}", f"{target.target} — {flag}")
    else:
        line(WARN, "scope", "no authorized targets configured")
        warn(
            "config/authorized_targets.yaml is empty. Nothing can be scanned until "
            "you add your laboratory range."
        )

    protected = ", ".join(f"{p.proto}/{p.port}" for p in config.protected_ports)
    line(OK, "protected ports", protected)
    line(
        OK,
        "management-channel guard",
        "enabled" if config.protect_active_management_channel else "DISABLED",
    )

    backend = config.settings.remediation_backend
    if backend == "dryrun":
        line(OK, "remediation backend", "dryrun — no rules will be applied")
    else:
        line(WARN, "remediation backend", f"{backend} — LIVE enforcement is armed")
        warn(
            f"Live remediation backend '{backend}' is active. Real firewall rules "
            "will be applied to authorized lab targets when you confirm an action."
        )

    line(
        OK,
        "eligibility thresholds",
        f"severity >= {config.minimum_severity_for_eligibility}, "
        f"confidence >= {config.minimum_confidence_for_eligibility}",
    )

    if config.settings.nvd_api_key:
        line(OK, "NVD API key", "configured (50 req/30s)")
    else:
        line(WARN, "NVD API key", "not set (rate limit 5 req/30s)")
        warn(
            "No NVD API key. Correlation will still work but is rate-limited to "
            "5 requests / 30s. Request a free key at "
            "https://nvd.nist.gov/developers/request-an-api-key"
        )

    key_path = config.settings.ssh_key_path
    if key_path is None:
        line(WARN, "SSH key", "CYBERSHIELD_SSH_KEY_PATH not set")
        warn("No SSH key configured. Required for remediation (not for scanning).")
    elif key_path.exists():
        line(OK, "SSH key", str(key_path))
    else:
        line(WARN, "SSH key", f"{key_path} does not exist")
        warn(f"SSH key {key_path} not found. Required for remediation.")


def check_authorization() -> None:
    print("\nAuthorization")
    record = load_authorization()
    if record.is_valid:
        line(OK, "AUTHORIZATION.md", f"signed by {record.operator_name} on {record.date}")
    else:
        for problem in record.problems:
            line(MISSING, "AUTHORIZATION.md", problem)
        require_fail(
            "AUTHORIZATION.md is not signed. CyberShield refuses to scan or "
            "remediate until it is."
        )


def check_database() -> None:
    print("\nDatabase")
    try:
        from backend.database.session import DB_PATH, init_db

        path = init_db()
        exists = Path(path).exists()
        line(OK if exists else WARN, "sqlite", f"{DB_PATH}")
    except Exception as exc:  # noqa: BLE001
        line(MISSING, "sqlite", str(exc))
        require_fail(f"Database initialisation failed: {exc}")


def check_audit_chain() -> None:
    print("\nAudit log")
    try:
        from backend.core.audit import AuditLog

        log = AuditLog(DATA_DIR / "audit.jsonl")
        result = log.verify_chain()
        line(OK if result.valid else MISSING, "hash chain", result.message)
        if not result.valid:
            require_fail(f"Audit chain verification failed: {result.message}")
    except Exception as exc:  # noqa: BLE001
        line(MISSING, "hash chain", str(exc))
        require_fail(f"Audit log could not be verified: {exc}")


def check_nvd() -> None:
    """Network reachability only. Sends one small, read-only public API request."""
    print("\nNVD API")
    try:
        import httpx

        response = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": "CVE-2011-2523"},
            timeout=20.0,
        )
        if response.status_code == 200:
            total = response.json().get("totalResults", 0)
            line(OK, "reachability", f"HTTP 200, {total} result(s) for the probe CVE")
        else:
            line(WARN, "reachability", f"HTTP {response.status_code}")
            warn(f"NVD returned HTTP {response.status_code}. Correlation may fail.")
    except Exception as exc:  # noqa: BLE001
        line(WARN, "reachability", str(exc))
        warn(f"Could not reach the NVD API: {exc}. Cached CVE data will still work.")


def check_lab() -> None:
    print("\nLaboratory environment")
    try:
        result = run_command(["colima", "status"], timeout_seconds=20)
        combined = (result.stdout + result.stderr).lower()
        if "not running" in combined:
            line(WARN, "colima", "installed but stopped")
            warn("Colima is stopped. Start it before running lab experiments.")
        elif result.ok:
            line(OK, "colima", "running")
        else:
            line(WARN, "colima", combined.strip().splitlines()[0] if combined else "unknown")
    except CommandError:
        line(WARN, "colima", "not installed")
        warn("Colima not found. Required only for the local laboratory target.")


def check_authentication() -> None:
    """Operator accounts: the dependency, the schema, and whether one exists."""
    print("\nAuthentication")

    try:
        import bcrypt  # noqa: F401
    except ImportError:
        line(MISSING, "bcrypt", "not installed")
        require_fail(
            "bcrypt is required for operator password hashing. Install it with: "
            "uv pip install --python .venv/bin/python -r requirements.txt"
        )
        return
    line(OK, "bcrypt", "available — passwords are hashed, never stored in plaintext")

    try:
        from backend.auth.service import user_count

        count = user_count()
    except Exception as exc:  # noqa: BLE001 - reported, never fatal here
        line(MISSING, "accounts", f"could not be read: {exc}")
        require_fail(f"The operator account table is unreadable: {exc}")
        return

    if count == 0:
        # Not a failure: the first run is expected to have no account, and the
        # signup page exists precisely for that.
        line(WARN, "accounts", "none yet — create one at /signup on first run")
        warn("No operator account exists yet. Create one at http://127.0.0.1:8000/signup")
    else:
        line(OK, "accounts", f"{count} operator account(s) registered")


def check_local_network() -> None:
    """Report the private subnets this machine is on, and what is authorized.

    Purely informational. Detecting a subnet authorizes nothing.
    """
    print("\nLocal network")
    try:
        from backend.core.netinfo import detect_local_interfaces

        interfaces = detect_local_interfaces()
    except Exception as exc:  # noqa: BLE001
        line(WARN, "interfaces", f"could not be detected: {exc}")
        return

    if not interfaces:
        line(WARN, "interfaces", "no private IPv4 interface detected")
        return

    try:
        config = load_config()
    except ConfigError:
        config = None

    for interface in interfaces:
        in_scope = (
            config is not None
            and config.find_authorized_target(interface.cidr) is not None
        )
        role = "default route" if interface.is_default_route else "secondary"
        line(
            OK,
            interface.name,
            f"{interface.address} on {interface.cidr} ({role})"
            + ("  [subnet authorized]" if in_scope else "  [not authorized]"),
        )
    line(
        OK,
        "note",
        "A subnet listed here is NOT authorized by being present. Add and "
        "confirm targets on the Targets page.",
    )


def main() -> int:
    print("=" * 68)
    print("CyberShield preflight — authorized laboratory use only")
    print("=" * 68)

    check_python()
    check_nmap()
    check_config()
    check_authorization()
    check_authentication()
    check_database()
    check_audit_chain()
    check_nvd()
    check_local_network()
    check_lab()

    print("\n" + "=" * 68)
    if _warnings:
        print(f"\n{len(_warnings)} warning(s):")
        for item in _warnings:
            print(f"  ! {item}")

    if _required_failures:
        print(f"\n{len(_required_failures)} blocking issue(s):")
        for item in _required_failures:
            print(f"  x {item}")
        print("\nPreflight FAILED. Resolve the blocking issues above.")
        return 1

    print("\nPreflight PASSED. All required checks succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
