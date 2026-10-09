"""Configuration loading and validation.

Two sources:
  * `config/*.yaml` — scope and policy. Validated strictly at load time; a
    malformed policy file is a hard error, never a silently-empty policy.
  * `.env` — secrets and runtime toggles, via environment variables.

Policy files are validated eagerly on load so that a typo surfaces at startup
rather than at the moment a firewall rule is about to be applied.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from backend.core.validation import (
    ParsedTarget,
    ValidationError,
    is_private_network,
    parse_target,
    validate_hostname,
    validate_port,
    validate_proto,
)

__all__ = [
    "ConfigError",
    "AuthorizedTarget",
    "ProtectedPort",
    "ServicePolicy",
    "ScanProfile",
    "Settings",
    "Config",
    "load_config",
    "PROJECT_ROOT",
]

# backend/core/config.py -> backend/core -> backend -> project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
EXPERIMENTS_DIR = PROJECT_ROOT / "experiments"

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Service classification states (spec §6C).
#   approved               Expected here. Never isolated.
#   review_required        Needs human judgement. Never AUTOMATICALLY isolated.
#   eligible_for_isolation May be isolated IF every other safety check passes.
#   protected              Never isolated under any circumstances. Overlaid from
#                          protected_ports.yaml, which always wins over the
#                          service policy file.
VALID_POLICIES = frozenset(
    {"approved", "review_required", "eligible_for_isolation", "protected"}
)
VALID_BACKENDS = frozenset({"dryrun", "nftables", "ufw"})

# Correlation confidence bands (spec §11).
CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or unsafe."""


# ---------------------------------------------------------------------------
# Policy records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizedTarget:
    name: str
    target: ParsedTarget
    is_lab: bool
    ssh_host: str | None
    ssh_port: int
    ssh_user: str | None
    notes: str

    def contains(self, address: str) -> bool:
        """True if `address` falls inside this authorized range."""
        try:
            probe = parse_target(address)
        except ValidationError:
            return False
        return probe.network.subnet_of(self.target.network)


@dataclass(frozen=True)
class ProtectedPort:
    port: int
    proto: str
    reason: str


@dataclass(frozen=True)
class ServicePolicy:
    port: int
    proto: str
    policy: str
    reason: str


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    args: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class Settings:
    """Runtime settings from the environment."""

    nvd_api_key: str | None
    ssh_key_path: Path | None
    remediation_backend: str
    remediation_ttl_minutes: int

    @property
    def live_remediation_enabled(self) -> bool:
        return self.remediation_backend != "dryrun"


@dataclass
class Config:
    """Fully-loaded, validated configuration."""

    authorized_targets: list[AuthorizedTarget]
    protected_ports: list[ProtectedPort]
    protect_active_management_channel: bool
    service_policies: dict[tuple[int, str], ServicePolicy]
    default_policy: str
    minimum_severity_for_eligibility: str
    minimum_confidence_for_eligibility: str
    scan_profiles: dict[str, ScanProfile]
    default_profile: str
    global_max_timeout_seconds: int
    settings: Settings
    config_hash: str = field(default="")

    def find_authorized_target(self, address: str) -> AuthorizedTarget | None:
        """Return the authorizing entry for `address`, or None if out of scope."""
        for entry in self.authorized_targets:
            if entry.contains(address):
                return entry
        return None

    def policy_for(self, port: int, proto: str = "tcp") -> ServicePolicy:
        """Effective classification for a port.

        The protected-port list is overlaid first and always wins. That way a
        port cannot be made isolatable by editing approved_services.yaml alone —
        both files would have to be changed, deliberately.
        """
        protected = self.is_protected_port(port, proto)
        if protected is not None:
            return ServicePolicy(
                port=port,
                proto=proto,
                policy="protected",
                reason=f"Protected by protected_ports.yaml: {protected.reason}",
            )

        found = self.service_policies.get((port, proto))
        if found is not None:
            return found

        return ServicePolicy(
            port=port,
            proto=proto,
            policy=self.default_policy,
            reason=(
                "Not listed in approved_services.yaml; default policy "
                f"({self.default_policy}) applied."
            ),
        )

    def is_protected_port(self, port: int, proto: str = "tcp") -> ProtectedPort | None:
        for entry in self.protected_ports:
            if entry.port == port and entry.proto == proto:
                return entry
        return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Required config file is missing: {path}")
    try:
        # safe_load: never construct arbitrary Python objects from config.
        loaded = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path.name} must contain a YAML mapping at the top level.")
    return loaded


def _load_authorized_targets(path: Path) -> list[AuthorizedTarget]:
    raw = _read_yaml(path)
    entries = raw.get("targets") or []
    if not isinstance(entries, list):
        raise ConfigError("authorized_targets.yaml: 'targets' must be a list.")

    targets: list[AuthorizedTarget] = []
    for index, item in enumerate(entries):
        where = f"authorized_targets.yaml entry #{index + 1}"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a mapping.")

        name = str(item.get("name") or "").strip()
        if not name:
            raise ConfigError(f"{where} is missing a 'name'.")

        cidr = item.get("cidr")
        if not cidr:
            raise ConfigError(f"{where} ({name}) is missing 'cidr'.")

        try:
            parsed = parse_target(str(cidr))
        except ValidationError as exc:
            raise ConfigError(f"{where} ({name}) has an invalid 'cidr': {exc}") from exc

        # Public ranges require an explicit, separate opt-in. Scanning a routable
        # address by accident is the failure this guards against.
        if not is_private_network(parsed.network) and not bool(item.get("allow_public")):
            raise ConfigError(
                f"{where} ({name}) targets the public range {parsed.network}. "
                "Refusing to load. If this is genuinely an authorized external "
                "range, set 'allow_public: true' and describe the authorization "
                "in AUTHORIZATION.md."
            )

        is_lab = bool(item.get("is_lab", False))

        ssh_host_raw = item.get("ssh_host")
        ssh_host: str | None = None
        if ssh_host_raw:
            try:
                ssh_host = validate_hostname(str(ssh_host_raw))
            except ValidationError as exc:
                raise ConfigError(f"{where} ({name}) has an invalid 'ssh_host': {exc}") from exc

        try:
            ssh_port = validate_port(item.get("ssh_port", 22))
        except ValidationError as exc:
            raise ConfigError(f"{where} ({name}) has an invalid 'ssh_port': {exc}") from exc

        ssh_user = str(item["ssh_user"]).strip() if item.get("ssh_user") else None

        # A lab target must be reachable for rollback. Without a user there is no
        # way to revert a rule, so refuse to treat it as remediable.
        if is_lab and not ssh_user:
            raise ConfigError(
                f"{where} ({name}) sets 'is_lab: true' but has no 'ssh_user'. "
                "Remediation requires SSH access so rules can be rolled back."
            )

        targets.append(
            AuthorizedTarget(
                name=name,
                target=parsed,
                is_lab=is_lab,
                ssh_host=ssh_host,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                notes=str(item.get("notes") or ""),
            )
        )

    return targets


def _load_protected_ports(path: Path) -> tuple[list[ProtectedPort], bool]:
    raw = _read_yaml(path)
    entries = raw.get("protected_ports")
    if not entries:
        raise ConfigError(
            "protected_ports.yaml defines no protected ports. Refusing to start: "
            "an empty protected-port list would allow isolation of management "
            "and web services. Restore at least ports 22, 80 and 443."
        )
    if not isinstance(entries, list):
        raise ConfigError("protected_ports.yaml: 'protected_ports' must be a list.")

    ports: list[ProtectedPort] = []
    for index, item in enumerate(entries):
        where = f"protected_ports.yaml entry #{index + 1}"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a mapping.")
        try:
            port = validate_port(item.get("port"))
            proto = validate_proto(str(item.get("proto", "tcp")))
        except ValidationError as exc:
            raise ConfigError(f"{where} is invalid: {exc}") from exc
        ports.append(
            ProtectedPort(port=port, proto=proto, reason=str(item.get("reason") or ""))
        )

    protect_channel = bool(raw.get("protect_active_management_channel", True))
    return ports, protect_channel


def _load_service_policies(
    path: Path,
) -> tuple[dict[tuple[int, str], ServicePolicy], str, str, str]:
    raw = _read_yaml(path)

    # Default is review_required, not eligible_for_isolation: an open port that
    # nobody has classified must never become automatically isolatable.
    default_policy = str(raw.get("default_policy", "review_required")).strip().lower()
    if default_policy not in VALID_POLICIES:
        raise ConfigError(
            f"approved_services.yaml: default_policy {default_policy!r} is invalid. "
            f"Expected one of {sorted(VALID_POLICIES)}."
        )

    minimum_severity = str(raw.get("minimum_severity_for_eligibility", "HIGH")).strip().upper()
    if minimum_severity not in SEVERITY_ORDER:
        raise ConfigError(
            f"approved_services.yaml: minimum_severity_for_eligibility "
            f"{minimum_severity!r} is invalid. Expected one of {sorted(SEVERITY_ORDER)}."
        )

    minimum_confidence = (
        str(raw.get("minimum_confidence_for_eligibility", "MEDIUM")).strip().upper()
    )
    if minimum_confidence not in CONFIDENCE_ORDER:
        raise ConfigError(
            f"approved_services.yaml: minimum_confidence_for_eligibility "
            f"{minimum_confidence!r} is invalid. Expected one of {sorted(CONFIDENCE_ORDER)}."
        )

    entries = raw.get("services") or []
    if not isinstance(entries, list):
        raise ConfigError("approved_services.yaml: 'services' must be a list.")

    policies: dict[tuple[int, str], ServicePolicy] = {}
    for index, item in enumerate(entries):
        where = f"approved_services.yaml entry #{index + 1}"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a mapping.")
        try:
            port = validate_port(item.get("port"))
            proto = validate_proto(str(item.get("proto", "tcp")))
        except ValidationError as exc:
            raise ConfigError(f"{where} is invalid: {exc}") from exc

        policy = str(item.get("policy", "")).strip().lower()
        if policy not in VALID_POLICIES:
            raise ConfigError(
                f"{where} has policy {policy!r}; expected one of {sorted(VALID_POLICIES)}."
            )

        key = (port, proto)
        if key in policies:
            raise ConfigError(
                f"{where} duplicates the policy for {proto}/{port}. "
                "Remove the duplicate so the effective policy is unambiguous."
            )

        policies[key] = ServicePolicy(
            port=port, proto=proto, policy=policy, reason=str(item.get("reason") or "")
        )

    return policies, default_policy, minimum_severity, minimum_confidence


# Nmap flags that must never appear in a profile, enforced at load time.
_FORBIDDEN_NMAP_ARGS = {
    "-T5": "aggressive timing is disruptive and degrades accuracy",
    "--script-args": "NSE script arguments are not permitted",
    "-oN": "output paths are controlled by the runner, not the profile",
    "-oX": "output paths are controlled by the runner, not the profile",
    "-oG": "output paths are controlled by the runner, not the profile",
    "-oA": "output paths are controlled by the runner, not the profile",
    "--resume": "not supported",
    "--interactive": "not supported",
}

_FORBIDDEN_NSE_CATEGORIES = ("vuln", "exploit", "brute", "dos", "malware", "intrusive")


def _load_scan_profiles(path: Path) -> tuple[dict[str, ScanProfile], str, int]:
    raw = _read_yaml(path)
    entries = raw.get("profiles") or {}
    if not isinstance(entries, dict) or not entries:
        raise ConfigError("scan_profiles.yaml: 'profiles' must be a non-empty mapping.")

    global_max = int(raw.get("global_max_timeout_seconds", 7200))
    if global_max <= 0:
        raise ConfigError("scan_profiles.yaml: global_max_timeout_seconds must be positive.")

    profiles: dict[str, ScanProfile] = {}
    for name, item in entries.items():
        where = f"scan_profiles.yaml profile {name!r}"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a mapping.")

        args = item.get("args")
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ConfigError(f"{where}: 'args' must be a list of strings.")

        for arg in args:
            if arg in _FORBIDDEN_NMAP_ARGS:
                raise ConfigError(
                    f"{where} uses forbidden Nmap argument {arg!r}: "
                    f"{_FORBIDDEN_NMAP_ARGS[arg]}."
                )
            lowered = arg.lower()
            if lowered.startswith("--script"):
                for category in _FORBIDDEN_NSE_CATEGORIES:
                    if category in lowered:
                        raise ConfigError(
                            f"{where} references the {category!r} NSE category. "
                            "CyberShield does not run intrusive or exploit scripts."
                        )

        timeout = int(item.get("timeout_seconds", 600))
        if timeout <= 0:
            raise ConfigError(f"{where}: timeout_seconds must be positive.")
        if timeout > global_max:
            raise ConfigError(
                f"{where}: timeout_seconds ({timeout}) exceeds "
                f"global_max_timeout_seconds ({global_max})."
            )

        profiles[name] = ScanProfile(
            name=name,
            description=str(item.get("description") or ""),
            args=tuple(args),
            timeout_seconds=timeout,
        )

    default_profile = str(raw.get("default_profile") or "").strip()
    if default_profile not in profiles:
        raise ConfigError(
            f"scan_profiles.yaml: default_profile {default_profile!r} is not a defined profile."
        )

    return profiles, default_profile, global_max


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader. Existing environment variables always win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _load_settings() -> Settings:
    _load_dotenv(PROJECT_ROOT / ".env")

    backend = os.environ.get("CYBERSHIELD_REMEDIATION_BACKEND", "dryrun").strip().lower()
    if backend not in VALID_BACKENDS:
        raise ConfigError(
            f"CYBERSHIELD_REMEDIATION_BACKEND={backend!r} is invalid. "
            f"Expected one of {sorted(VALID_BACKENDS)}."
        )

    raw_ttl = os.environ.get("CYBERSHIELD_REMEDIATION_TTL_MINUTES", "30").strip()
    try:
        ttl = int(raw_ttl)
    except ValueError as exc:
        raise ConfigError(
            f"CYBERSHIELD_REMEDIATION_TTL_MINUTES={raw_ttl!r} is not an integer."
        ) from exc
    if ttl <= 0:
        raise ConfigError(
            "CYBERSHIELD_REMEDIATION_TTL_MINUTES must be positive: the TTL watchdog "
            "is what guarantees a rule cannot be left applied indefinitely."
        )

    key = os.environ.get("CYBERSHIELD_NVD_API_KEY", "").strip() or None

    ssh_key_raw = os.environ.get("CYBERSHIELD_SSH_KEY_PATH", "").strip()
    ssh_key_path = Path(ssh_key_raw).expanduser() if ssh_key_raw else None

    return Settings(
        nvd_api_key=key,
        ssh_key_path=ssh_key_path,
        remediation_backend=backend,
        remediation_ttl_minutes=ttl,
    )


def _hash_config_dir(config_dir: Path) -> str:
    """Stable hash of all policy files, recorded in every run manifest.

    Lets a reader of the research output confirm which policy produced a result.
    """
    digest = hashlib.sha256()
    for path in sorted(config_dir.glob("*.yaml")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def load_config(config_dir: Path | None = None) -> Config:
    """Load and validate all configuration. Raises ConfigError on any problem."""
    directory = config_dir or CONFIG_DIR
    if not directory.is_dir():
        raise ConfigError(f"Config directory not found: {directory}")

    targets = _load_authorized_targets(directory / "authorized_targets.yaml")
    protected, protect_channel = _load_protected_ports(directory / "protected_ports.yaml")
    policies, default_policy, min_sev, min_conf = _load_service_policies(
        directory / "approved_services.yaml"
    )
    profiles, default_profile, global_max = _load_scan_profiles(directory / "scan_profiles.yaml")

    return Config(
        authorized_targets=targets,
        protected_ports=protected,
        protect_active_management_channel=protect_channel,
        service_policies=policies,
        default_policy=default_policy,
        minimum_severity_for_eligibility=min_sev,
        minimum_confidence_for_eligibility=min_conf,
        scan_profiles=profiles,
        default_profile=default_profile,
        global_max_timeout_seconds=global_max,
        settings=_load_settings(),
        config_hash=_hash_config_dir(directory),
    )


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Process-wide cached config. Call `get_config.cache_clear()` after edits."""
    return load_config()


# ---------------------------------------------------------------------------
# Authorization signature
# ---------------------------------------------------------------------------

_SIGNATURE_BLOCK_RE = re.compile(r"```yaml\s*(.*?)```", re.DOTALL)


@dataclass(frozen=True)
class AuthorizationRecord:
    signed: bool
    operator_name: str
    institution: str
    date: str
    scope_description: str
    problems: tuple[str, ...]

    @property
    def is_valid(self) -> bool:
        return self.signed and not self.problems


def load_authorization(path: Path | None = None) -> AuthorizationRecord:
    """Parse the signature block from AUTHORIZATION.md."""
    target = path or (PROJECT_ROOT / "AUTHORIZATION.md")
    if not target.exists():
        return AuthorizationRecord(
            False, "", "", "", "", (f"AUTHORIZATION.md not found at {target}.",)
        )

    match = _SIGNATURE_BLOCK_RE.search(target.read_text())
    if not match:
        return AuthorizationRecord(
            False, "", "", "", "", ("No ```yaml signature block found in AUTHORIZATION.md.",)
        )

    try:
        block = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError as exc:
        return AuthorizationRecord(
            False, "", "", "", "", (f"Signature block is not valid YAML: {exc}",)
        )

    signed = bool(block.get("signed", False))
    operator = str(block.get("operator_name") or "").strip()
    institution = str(block.get("institution") or "").strip()
    date = str(block.get("date") or "").strip()
    scope = str(block.get("scope_description") or "").strip()

    problems: list[str] = []
    if not signed:
        problems.append("AUTHORIZATION.md is not signed (signed: false).")
    else:
        for label, value in (
            ("operator_name", operator),
            ("institution", institution),
            ("date", date),
            ("scope_description", scope),
        ):
            if not value:
                problems.append(f"AUTHORIZATION.md field {label!r} is empty.")
        if date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            problems.append(f"AUTHORIZATION.md date {date!r} is not in YYYY-MM-DD form.")

    return AuthorizationRecord(
        signed=signed,
        operator_name=operator,
        institution=institution,
        date=date,
        scope_description=scope,
        problems=tuple(problems),
    )
