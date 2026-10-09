# Assessing an authorized device on a real network

The laboratory in `lab/docker-compose.yml` is a controlled environment: every
container publishes known ports and answers every probe. A real device on a real
Wi-Fi network does none of that, and the difference is large enough to produce
false negatives if it is ignored.

This document records what changed to support it, what the failure modes are,
and where the honest limits sit.

## The problem this started from

An operator authorized to assess another laptop on the same Wi-Fi network tried
to scan it and got:

```
192.168.0.176/32 is not inside any authorized range.
```

Two separate problems in one message:

1. **The scope could not be extended without editing YAML.** The only authorized
   range was the laboratory's `192.168.64.8/29`, and adding another meant
   hand-editing a config file.
2. **The message did not say what to do about it.** It was accurate and
   actionable-by-nobody.

## What scope management now does

`backend/core/scope_admin.py` is the only writer of
`config/authorized_targets.yaml`. The file stays the single source of truth, so
`config_hash` still identifies the policy that produced any result, and
`preflight.py` still validates it.

Rules applied to anything added from the UI or `POST /api/targets`:

| Rule | Behaviour |
|---|---|
| Private IPv4 only | An explicit allowlist: `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`. |
| Reserved ranges refused | `203.0.113.0/24` and friends are refused even though Python's `is_private` returns `True` for them. |
| Size cap | `/22` (1024 addresses) maximum. |
| Confirmation | `confirmed=True` required; there is no way to skip it. |
| Assessment only | Always written `is_lab: false`. |
| Validated before commit | The file is rewritten, then re-loaded. If it would not load, the original is restored and the call fails. |
| No silent widening | A range already covered is reported, not duplicated. |
| Audited | `scope.target_authorized` / `scope.target_revoked`, with the operator's name. |

`allow_public: true` exists in the file format and is **unreachable from the
web interface**. Authorizing a routable range requires editing the file by hand
and describing that authorization in `AUTHORIZATION.md`.

Laboratory entries cannot be deleted from the UI, and neither can entries that
were configured in the file rather than added through it.

### Why UI-added targets are never remediable

A firewall rule is only reversible if the rule can be *removed*, which needs an
SSH management channel that is known to work. A checkbox on a web form is not
evidence of that. So the UI can bring a target into scope for assessment, and
promoting one to `is_lab: true` remains a deliberate file edit with `ssh_user`
supplied — which the config loader enforces independently.

## Why local subnets are detected

`backend/core/netinfo.py` reports the private IPv4 subnets this machine is on.
The reason is narrow: different Wi-Fi networks use different subnets, so
`192.168.1.0/24` cannot be assumed, hardcoded, or defaulted to. The operator
needs to see `192.168.10.0/24` if that is where they actually are.

Detection **authorizes nothing**. The Targets page labels every detected range
`not authorized` until it is added and confirmed. The suggestion list exists to
save looking up an address, not to grant anything.

## Why the LAN profiles use `-Pn`

This is the single most important change for real-network assessment.

Nmap's default behaviour is to establish that a host is up before scanning its
ports. On a real LAN that check fails routinely:

- Windows blocks inbound connections by default, including the ports the
  laboratory profile probes.
- macOS's firewall does the same when enabled.
- ICMP echo is frequently filtered, and unprivileged Nmap cannot send it anyway.

When the check fails, Nmap declares the host **down** and skips it. The scan
finishes in a couple of seconds and reports *zero open services* — for a machine
that is powered on and sitting on the same network. That result is
indistinguishable from a genuinely clean host, which is exactly the class of
false negative this project must not produce.

`lan_service_detect` therefore passes `-Pn`: skip host discovery, probe the
ports regardless. Reachability is then decided from the **port results** by
`backend/scanner/reachability.py`, not from Nmap's up/down guess.

The cost is honest and stated: every address in the range is probed whether or
not anything is there, so these profiles are meant for a single host or a small
range. `--host-timeout` bounds the worst case.

`lan_discovery` uses a wider TCP probe set than the laboratory profile — 445,
139 and 135 for Windows, 5000, 7000 and 62078 for Apple devices, 8008/8009 for
smart TVs, plus the general 22/80/443/3389.

## The three states the UI distinguishes

| State | Meaning |
|---|---|
| **NOT AUTHORIZED** | Out of scope. Never probed, whatever its actual state. |
| **AUTHORIZED + UNREACHABLE** | In scope; nothing answered. **Nothing was learned.** |
| **AUTHORIZED + REACHABLE** | In scope; something answered. |

An unreachable scan is stored with status `completed_unreachable` and a
`reachability_note`, and every page that shows it says so. The alternative —
storing it as `completed` with zero hosts — is what makes a dashboard report
"0 vulnerabilities" for a machine it never reached.

A **closed** port is treated as reachable, and that distinction is deliberate: a
closed port means a RST came back, so packets reached the host. `filtered` means
no answer at all. "Reachable with nothing exposed" and "no answer" are different
findings and are reported differently.

When an authorized target does not answer, the UI lists the ordinary causes for
the operator to rule out: device asleep or off, host firewall, Wi-Fi client
isolation, ICMP filtered, wrong subnet, DHCP address change, or nothing
listening on any probed port. These are presented as possibilities to check,
never as a diagnosis — from the outside, CyberShield cannot tell a firewalled
host from an absent one.

## Limits, stated plainly

- **Client isolation is invisible to the scanner.** If the access point drops
  station-to-station traffic, every authorized target on that network is
  unreachable and CyberShield cannot distinguish that from the devices being
  off. It says "unreachable", which is all it knows.
- **`-Pn` over a range is slow**, because absent addresses cost a full timeout
  per port. Prefer a `/32`.
- **`--max-retries 1` risks false negatives on a lossy link.** Acceptable on a
  wired local link; Wi-Fi is lossier than the laboratory bridge, and this is
  recorded as a threat to validity.
- **Nmap's port list is explicit, not exhaustive.** A service on a port outside
  the profile's list will not be found. `service_detect_full` covers all 65535
  ports and is very slow.
- **No ARP scanning.** ARP would identify hosts on the local segment that answer
  nothing else, but it needs raw sockets and therefore root. The assessment path
  is deliberately unprivileged, so this capability is given up rather than
  requiring `sudo`.
- **DHCP moves addresses.** A `/32` authorization can silently start pointing at
  a different device. Re-check the target's current address before scanning; the
  authorization is for an address, and CyberShield has no way to bind it to a
  particular machine.
