# Threats to Validity

Consolidated limitations of the CyberShield results. Everything here was
measured or observed during development, not anticipated in the abstract.
Results are in [`experiments/README.md`](../experiments/README.md).

---

## 1. What the system fundamentally cannot establish

| Claim | Status |
|---|---|
| A detected version is the software actually running | **Inferred** from a banner, which can be absent, wrong or spoofed |
| A CVE candidate applies to this deployment | **Not established.** Candidate only |
| A candidate is exploitable here | **Never measured.** No exploitation is attempted, by design |
| An isolated port is unreachable | **Only from this scanner's vantage point** |
| An isolated service is fixed | **No.** The service keeps running; the software is unchanged |

The last row is the central boundary of the project. Isolating tcp/8080 on the
laboratory's Apache 2.4.49 changed nothing about CVE-2021-41773: it was equally
present before, during and after.

---

## 2. Measured limitations of NVD correlation

All figures below were measured against the live NVD REST API 2.0 on
2026-08-30 and drove design decisions.

### 2.1 Keyword search under-reports severely

| Query for Apache httpd 2.4.49 | CVEs |
|---|---|
| `keywordSearch=Apache httpd 2.4.49` | **0** |
| `cpeName=cpe:2.3:a:apache:http_server:2.4.49:*:...` | **81** |

Keyword search is therefore a labelled fallback only, and everything it returns
is LOW confidence by construction.

### 2.2 CPE queries over-report

Of those 81 Apache candidates, **12 (14.8%)** were auto-flagged because no
`cpeMatch` with `vulnerable: true` named `apache:http_server`. Examples:
CVE-2007-4723 names `ragnarok_online_control_panel`, CVE-2011-2688 names
`mod_authnz_external`, CVE-2013-4365 names `apache:mod_fcgid`.

### 2.3 The CPE dictionary's ranking does not identify the vendor that carries CVEs

Searching the dictionary for "redis" ranks `redislabs:redis` and
`pivotal_software:redis` highest. For Redis 5.0.14 **both return 0 CVEs**, while
`redis:redis` returns **21**. Every vendor pair in the curated map was therefore
verified by CVE count, not by dictionary rank. Plausible guesses were often
wrong: nginx is `igor_sysoev:nginx`, not `f5:nginx`.

### 2.4 Some products have several legitimate vendor prefixes

MySQL 5.7.44 returns 12 CVEs under `oracle:mysql` and 2 under `mysql:mysql`;
neither is a superset. Such products yield one signature per vendor and
confidence is capped at MEDIUM.

### 2.5 Version strings must be normalized, or counts are meaningless

MariaDB advertises `5.5.5-10.5.29` (a MySQL-client compatibility prefix).

| CPE version used | Candidates |
|---|---|
| `10.5.29` (normalized) | **3** |
| `5.5.5-10.5.29` (raw banner) | **250** |
| `oracle:mysql:10.5.29` (wrong vendor) | **0** |

An ~83× over-report from the raw banner, and a total false negative from the
wrong vendor.

### 2.6 A version-less CPE query returns nothing

`cpeName` with `version=*` returns zero results, so a service whose version Nmap
could not determine cannot be correlated by CPE at all and falls to the keyword
path at LOW confidence.

### 2.7 CVSS metrics are heterogeneous

Responses mix `cvssMetricV2`, `V30`, `V31` and `V40`. v2 entries carry
`baseSeverity: null`, so the band is derived from the score — and **CVSS v2 has
no CRITICAL band**, so a 9.8 v2 score is HIGH. In the recorded run, 28 of 278
candidates were v2-only.

### 2.8 NVD data changes over time

Candidate counts depend on NVD's contents on the run date. Raw responses are
cached under `data/nvd_cache/` so the analysis can be reproduced against the
same data.

---

## 3. Measured limitations of scanning

### 3.1 `--top-ports` silently excludes services

`6379/tcp` (Redis) is scanned by **neither** `--top-ports 1000` **nor**
`--top-ports 2000`. A demonstrably listening Redis target was absent from two
consecutive full scans. The profile now uses an explicit 46-port list — which
means **the scan finds only what it is told to look for**. No independent
full-port sweep was run to quantify what that misses.

### 3.2 A truncated scan can look like a clean one

With `--host-timeout 180s`, all four hosts expired and the run reported "4 hosts
up, 0 open services" while exiting successfully. Nmap's `timedout="true"` is now
parsed and such runs are recorded as `completed_with_timeouts`, but the
underlying hazard is general: a scan that fails partway can resemble a scan that
found nothing.

### 3.3 Missing host-discovery probes produce silent false negatives

Without explicit `-PS` probes, Nmap's default unprivileged discovery (TCP
connect to 80 and 443) declared every target down and returned "0 open services"
in four seconds.

### 3.4 Reduced retries

`--max-retries 1` is safe on this loss-free local link and would risk false
negatives on a lossy network. Wi-Fi is measurably lossier than the laboratory
bridge, so this threat is larger for real-LAN assessment than for the lab.

### 3.5 Nmap output can be truncated mid-write

Nmap streams `-oX` as it scans, so a killed process leaves a file with valid
host results and no closing tags. This previously produced
`NmapParseError: Nmap XML is not well-formed` and the whole run was lost. The
parser now drops the incomplete tail, closes the open containers, and marks the
scan `recovered_from_truncation` — which forces `is_complete` to `False`. A
recovered scan under-reports by construction and is never presented as
exhaustive. Output that cannot be recovered at all fails loudly and writes no
findings.

### 3.6 On a real network, "no answer" is ambiguous and unresolvable

This is the largest threat introduced by supporting LAN assessment. From the
outside, and without privileged access, these are indistinguishable:

- the device is powered off or has left the network
- the device is online but its host firewall drops inbound connections
  (the Windows default)
- the Wi-Fi access point enforces client isolation
- the address moved to another device via DHCP
- nothing is listening on any port the profile probes

CyberShield reports `unreachable` and lists these as possibilities to check. It
does **not** diagnose which one holds, and no result in this project should be
read as evidence about an unreachable target's security posture. This is why the
`completed_unreachable` status exists as a distinct value rather than being
folded into `completed`.

### 3.7 An authorization binds an address, not a device

Scope entries are IPv4 addresses. On a DHCP network an address can be
reassigned, so a `/32` authorized for one machine can later point at another.
CyberShield has no mechanism to bind an authorization to a device identity, and
MAC-based identification would require privileged ARP access that the
deliberately-unprivileged assessment path does not have. The operator is
responsible for re-checking the target's current address.

### 3.8 No ARP discovery

ARP would find hosts on the local segment that answer nothing else, and is the
standard technique for local-network host discovery. It requires raw sockets and
therefore root. Keeping the assessment path unprivileged was judged the more
important property, so this detection capability is given up. Host discovery on a
LAN is consequently weaker than a privileged scanner's.

---

## 4. Limitations of the experimental setup

1. **Sample size.** One laboratory, 4 hosts, 12 open services, 3 scan
   repetitions, 3 remediation cycles. The perfect scores (detection 8/8,
   exposure reduction 3/3, rollback 3/3) characterise this environment only.
2. **Software selection bias.** Apache, vsftpd, Redis, OpenSSH and MariaDB are
   common, actively fingerprinted software. Obscure or custom services would
   very likely reduce detection accuracy.
3. **Containers are not bare metal.** Isolation was applied inside a container
   network namespace. A host firewall on physical hardware behaves differently,
   and a container restart clears rules that would persist on a real host.
4. **A shared-interface artifact inflates raw service counts.** tcp/22 appears
   open on all four addresses but is the Colima VM's own sshd answering on every
   alias — one service observed four times. It is excluded from per-target
   metrics, and the exclusion is stated rather than applied silently.
5. **Ground truth covers versions only.** It establishes which software is
   running, not which CVEs genuinely affect it, so it cannot validate the
   correlation stage — only the detection stage.
6. **No reviewed false-positive rate.** The 5.04% auto-flagged figure is a
   machine check for one failure mode and a **lower bound**. Human adjudication
   of all 278 candidates has not been performed and no such figure is claimed.
7. **Timing is indicative.** n=3, one machine, one lab. Correlation completed in
   0.13 s only because the NVD cache was warm; a cold run is bounded by NVD's
   5 requests / 30 s unkeyed rate limit.
8. **The real-LAN path has n=1.** Real-network assessment was exercised against
   a single authorized host (this machine's own Wi-Fi address, 1 open service,
   161 s) plus one deliberately unreachable address. That is enough to
   demonstrate the workflow and the reachability classification; it is not a
   measurement of LAN detection accuracy, and no such figure is claimed. In
   particular, the `-Pn` behaviour against a genuinely firewalled third-party
   device has not been measured, only reasoned about from Nmap's documented
   behaviour.

---

## 5. Accumulated-state hazard

The database retains every scan session, including verification rescans. Three
separate defects during development came from queries that did not filter by
`scan_kind`: inflated host counts (12 vs 4), inflated service counts (18 vs 12),
and doubled CVE candidates (556 vs 278). Each produced a plausible but wrong
figure that would have reached the paper unexamined.

Any analysis must scope to a single assessment session.

---

## 6. What would strengthen the results

Honest next steps, none of which have been done:

- A larger and more varied target set, including uncommon and custom services
- Independent full-port sweeps to quantify false negatives from the explicit
  port list
- Human adjudication of a random sample of candidates to convert the auto-flagged
  lower bound into a measured false-positive rate
- Repetition on bare-metal Linux hosts rather than containers
- Verification from a second vantage point to test the single-vantage-point
  limitation directly
- More scan repetitions, and on varied hardware, before any timing claim
