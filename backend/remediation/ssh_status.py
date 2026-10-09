"""Management-channel status, for the operator interface.

Why this exists. Remediation is only reversible if the rule can be *removed*,
and removal happens over SSH. So an SSH channel that is misconfigured or
unreachable is not a cosmetic problem — it is the difference between a
reversible action and a rule stuck on a target until its TTL expires. The
operator should be able to see that before approving anything, not discover it
half way through an apply.

What this module deliberately does NOT do:

  * It never reads, returns, or logs key material. Only whether the configured
    key file exists, its path, and its permission bits.
  * It never accepts a host, port or user from the caller. Every value comes
    from `config/authorized_targets.yaml`, so this cannot be used to probe an
    arbitrary host over SSH.
  * It only ever runs one fixed, side-effect-free command (`true`). There is no
    parameter through which a command could be supplied.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.core.audit import AuditLog
from backend.core.config import DATA_DIR, AuthorizedTarget, Config
from backend.remediation.ssh_adapter import SshError, SshTarget, connect

__all__ = ["SshChannelStatus", "describe_channels", "probe_channel"]

# The probe command. A fixed literal: no caller-supplied text reaches the
# target. `true` changes nothing and exits 0 on any POSIX host.
PROBE_ARGV = ["true"]


@dataclass
class SshChannelStatus:
    """Configuration and health of one laboratory target's management channel."""

    name: str
    cidr: str
    is_lab: bool
    host: str | None
    port: int
    user: str | None
    key_path: str | None
    key_present: bool
    key_permissions: str | None
    key_too_open: bool
    problems: list[str] = field(default_factory=list)

    # Populated only by probe_channel(); None means "not probed in this request".
    reachable: bool | None = None
    detail: str | None = None
    latency_ms: float | None = None
    # Why the probe failed, classified by exception type rather than message:
    # "auth" | "timeout" | "connect" | "config" | "command". None on success
    # and when not probed.
    failure_kind: str | None = None

    @property
    def configured(self) -> bool:
        """True when everything needed to open a channel is present."""
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "cidr": self.cidr,
            "is_lab": self.is_lab,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            # The PATH only. Never the key, never a fingerprint of it.
            "key_path": self.key_path,
            "key_present": self.key_present,
            "key_permissions": self.key_permissions,
            "key_too_open": self.key_too_open,
            "configured": self.configured,
            "problems": list(self.problems),
            "reachable": self.reachable,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "failure_kind": self.failure_kind,
        }


def _describe_key(config: Config) -> tuple[str | None, bool, str | None, bool]:
    """Return (path, present, mode string, too_open) for the configured key."""
    key = config.settings.ssh_key_path
    if key is None:
        return None, False, None, False

    path = Path(key).expanduser()
    if not path.exists():
        return str(path), False, None, False

    mode = stat.S_IMODE(path.stat().st_mode)
    # A private key readable by group or others is a real finding: OpenSSH
    # itself refuses such a key, so this would fail at connect time anyway.
    too_open = bool(mode & (stat.S_IRWXG | stat.S_IRWXO))
    return str(path), True, oct(mode)[-3:], too_open


def _status_for(config: Config, entry: AuthorizedTarget) -> SshChannelStatus:
    key_path, key_present, key_mode, key_too_open = _describe_key(config)

    problems: list[str] = []
    if not entry.is_lab:
        problems.append(
            "This target is assessment-only (is_lab: false). No management "
            "channel is needed or used, and remediation is refused on it."
        )
    else:
        if not entry.ssh_user:
            problems.append(
                "No 'ssh_user' configured. Without it a rule could not be "
                "rolled back, so the config loader refuses this combination."
            )
        if key_path is None:
            problems.append(
                "No SSH key configured. Set CYBERSHIELD_SSH_KEY_PATH in .env — "
                "password authentication is not supported by design."
            )
        elif not key_present:
            problems.append(f"The configured SSH key does not exist at {key_path}.")
        elif key_too_open:
            problems.append(
                f"The SSH key at {key_path} has permissions {key_mode}. OpenSSH "
                "refuses group- or world-readable keys; run chmod 600 on it."
            )

    return SshChannelStatus(
        name=entry.name,
        cidr=str(entry.target),
        is_lab=entry.is_lab,
        # For the lab, each container answers on its own address; ssh_host is
        # only set when a single fixed jump address is configured.
        host=entry.ssh_host,
        port=entry.ssh_port,
        user=entry.ssh_user,
        key_path=key_path,
        key_present=key_present,
        key_permissions=key_mode,
        key_too_open=key_too_open,
        problems=problems,
    )


def describe_channels(config: Config) -> list[SshChannelStatus]:
    """Configuration status for every authorized target. Opens no connection."""
    return [_status_for(config, entry) for entry in config.authorized_targets]


def probe_channel(
    config: Config,
    address: str,
    *,
    actor: str = "operator",
    audit_path: Path | None = None,
) -> SshChannelStatus:
    """Open a real SSH session to an authorized lab target and run `true`.

    Args:
        address: An IPv4 address that must resolve to an `is_lab` entry in the
            authorized scope. Anything else is refused before a socket is
            opened — this is the same gate remediation uses, reused rather than
            reimplemented.

    Raises:
        AuthorizationDenied: if `address` is not an authorized lab target.
    """
    import time

    from backend.core.authorization import assert_authorized_lab_target

    # Fail closed, and reuse the existing gate: scope, signature, is_lab and
    # ssh_user are all checked here.
    entry = assert_authorized_lab_target(config, address)
    status = _status_for(config, entry)
    status.host = address

    audit = AuditLog(audit_path or (DATA_DIR / "audit.jsonl"))

    if not status.configured:
        status.reachable = False
        status.detail = "; ".join(status.problems)
        status.failure_kind = "config"
        audit.record(
            "ssh.test",
            outcome="refused",
            actor=actor,
            detail={"target": address, "port": entry.ssh_port, "reason": status.detail},
        )
        return status

    target = SshTarget(
        host=address,
        port=entry.ssh_port,
        username=entry.ssh_user or "",
        key_path=config.settings.ssh_key_path,
    )

    started = time.monotonic()
    try:
        with connect(target) as session:
            result = session.run(PROBE_ARGV, timeout=15.0)
        status.latency_ms = round((time.monotonic() - started) * 1000, 1)
        status.reachable = result.ok
        status.detail = (
            f"Connected as {entry.ssh_user}@{address}:{entry.ssh_port} and ran "
            f"`{' '.join(PROBE_ARGV)}` successfully."
            if result.ok
            else f"Connected, but the probe command exited {result.exit_status}."
        )
    except SshError as exc:
        status.latency_ms = round((time.monotonic() - started) * 1000, 1)
        status.reachable = False
        # The SshError message names host, port and user — never the key.
        status.detail = str(exc)
        status.failure_kind = exc.kind

    audit.record(
        "ssh.test",
        outcome="success" if status.reachable else "failure",
        actor=actor,
        detail={
            "target": address,
            "port": entry.ssh_port,
            "user": entry.ssh_user,
            "reachable": status.reachable,
            "latency_ms": status.latency_ms,
            "failure_kind": status.failure_kind,
            # The detail text, which contains no secret material.
            "result": status.detail,
        },
    )
    return status
