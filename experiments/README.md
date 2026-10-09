# CyberShield — Experimental Results

Real measurements from the authorized laboratory. Every figure here was
produced by running the system; nothing is estimated, and metrics that cannot
be computed are recorded as not computed rather than filled in.

**Run:** `experiments/reports/experiment_20260830T183653Z.json`
**Date:** 2026-08-30 · **Darshan Tonape:** See the original experiment record
**Config hash:** `54eb1f109d7298c3` · **Nmap:** 7.991 · **NVD REST API 2.0**

Reproduce with:

```bash
sh scripts/lab_network.sh up
CYBERSHIELD_REMEDIATION_BACKEND=nftables \
  ./.venv/bin/python scripts/run_experiment.py --repetitions 3
```

---

## 1. Environment

Four containers on an isolated Docker bridge inside a local Colima Linux VM,
published on per-target IP aliases (192.168.64.11–.14). Authorized scope is
`192.168.64.8/29`, which excludes the Mac (.1) and the VM (.2).

| Host | Service under study | Port | Management |
|---|---|---|---|
| 192.168.64.11 | Apache httpd 2.4.49 | 8080 | sshd 2222 |
| 192.168.64.12 | vsftpd 3.0.3 | 21 | sshd 2222 |
| 192.168.64.13 | Redis 5.0.14 | 6379 | sshd 2222 |
| 192.168.64.14 | MariaDB 10.5.29 | 3306 | sshd 2222 |

### Ground truth

Versions in `ground_truth.yaml` were read **from the software itself** inside
each container (`httpd -v`, `redis-server --version`, `mariadbd --version`,
`dpkg-query` for vsftpd and OpenSSH), not copied from CyberShield's output.
Deriving the reference from the system under test would make the accuracy
figure meaningless.

### Known measurement artifact

`tcp/22` appears open on all four addresses, but it is **not a target service**.
The Colima VM's own sshd binds `0.0.0.0:22`, and the targets are published on
aliases of that same interface, so one sshd answers on all four — the same
service observed four times. It is excluded from per-target metrics, and the
exclusion is stated rather than applied silently.

---

## 2. Detection and identification

12 open services detected; 8 scored against ground truth; 4 excluded as the
artifact above.

| Host | Port | Product | Advertised version | Normalized | Expected | Correct |
|---|---|---|---|---|---|---|
| .11 | 8080 | Apache httpd | `2.4.49` | 2.4.49 | 2.4.49 | ✅ |
| .12 | 21 | vsftpd | `3.0.3` | 3.0.3 | 3.0.3 | ✅ |
| .13 | 6379 | Redis | `5.0.14` | 5.0.14 | 5.0.14 | ✅ |
| .14 | 3306 | MariaDB | `5.5.5-10.5.29` | **10.5.29** | 10.5.29 | ✅ |
| .11 | 2222 | OpenSSH | `7.9p1 Debian 10+deb10u4` | 7.9p1 | 7.9p1 | ✅ |
| .12 | 2222 | OpenSSH | `8.4p1 Debian 5+deb11u7` | 8.4p1 | 8.4p1 | ✅ |
| .13 | 2222 | OpenSSH | `8.4p1 Debian 5+deb11u7` | 8.4p1 | 8.4p1 | ✅ |
| .14 | 2222 | OpenSSH | `8.2p1 Ubuntu 4ubuntu0.13` | 8.2p1 | 8.2p1 | ✅ |

**Detection accuracy: 8/8 = 1.00.** A detection counts as correct only when the
product string matches ground truth *and* the normalized version equals the
upstream version.

The MariaDB row is the one that matters: the service advertises
`5.5.5-10.5.29`, and normalization is what turns it into `10.5.29`.

**Do not over-read this figure.** n = 8, all four products are common, actively
fingerprinted software that Nmap identifies well, and all were reachable over a
loss-free local link. It says the pipeline works on this set; it is not a
general accuracy claim.

---

## 3. CVE correlation

278 candidates across 12 services. Every match came from the **exact-CPE** path;
the keyword fallback was never needed.

| Host | Port | Product | Candidates | Auto-flagged | Max severity | Max confidence |
|---|---|---|---|---|---|---|
| .11 | 8080 | Apache httpd | 81 | **12** | CRITICAL | HIGH |
| .11 | 2222 | OpenSSH 7.9p1 | 25 | 0 | CRITICAL | HIGH |
| .14 | 2222 | OpenSSH 8.2p1 | 26 | 0 | CRITICAL | HIGH |
| .12 | 2222 | OpenSSH 8.4p1 | 24 | 0 | CRITICAL | HIGH |
| .13 | 2222 | OpenSSH 8.4p1 | 24 | 0 | CRITICAL | HIGH |
| .13 | 6379 | Redis 5.0.14 | 21 | 1 | CRITICAL | MEDIUM |
| .14 | 3306 | MariaDB 10.5.29 | 3 | 1 | MEDIUM | HIGH |
| .12 | 21 | vsftpd 3.0.3 | 2 | 0 | HIGH | HIGH |

- **CPE resolution rate: 12/12 = 1.00** — every detected service produced at
  least one CPE signature.
- **NVD correlation success: 12/12 = 1.00** — every signature returned at least
  one candidate.
- **Severity distribution:** 31 CRITICAL, 114 HIGH, 109 MEDIUM, 24 LOW.
- **CVSS coverage:** 249 v3.1, 1 v3.0, 28 v2.0. Scores are never compared
  across generations without their version label, and CVSS v2 has no CRITICAL
  band.

### Auto-flagged probable false positives: 14/278 = 5.04%

A candidate is flagged when NVD returned it for the queried CPE but **no
`cpeMatch` marked `vulnerable: true` names the queried vendor:product**. Twelve
of the fourteen are on Apache 2.4.49, for example:

| CVE | Configuration actually names |
|---|---|
| CVE-2007-4723 | `ragnarok_online_control_panel_project:ragnarok_online_control_panel` |
| CVE-2011-2688 | `mod_authnz_external_project:mod_authnz_external` |
| CVE-2013-4365 | `apache:mod_fcgid` |

**This is a lower bound, not a reviewed false-positive rate.** It is a machine
check for one specific failure mode. A candidate can still be wrong for reasons
this check cannot see — for instance a CVE affecting only a build option or
platform not in use here. A human adjudication of all 278 against the CVE text
has not been performed, and no such figure is reported.

---

## 4. Remediation eligibility

One decision per open service, from the risk engine:

| Verdict | Count | Services |
|---|---|---|
| **ALLOW** | 3 | Apache 8080, vsftpd 21, Redis 6379 |
| **DENY** | 8 | 4 × tcp/22 and 4 × tcp/2222 — protected ports |
| **REVIEW_REQUIRED** | 1 | MariaDB 3306 |

MariaDB is instructive: it is a classified, eligible service with a HIGH
confidence match, but its highest candidate severity is **MEDIUM**, below the
configured HIGH threshold. The engine returns REVIEW_REQUIRED rather than
acting — severity gating works, and a high CVE count alone does not authorise
an action.

The eight DENY results include four SSH management channels carrying CRITICAL
candidates at HIGH confidence. They are refused anyway, which is the intended
behaviour: severity never outranks a protected port.

---

## 5. Controlled exposure reduction

All three eligible services were isolated, verified, rolled back and verified
again.

| Host | Port | Service | Before | After | Exposure reduced | Mgmt intact | Rollback | Restored |
|---|---|---|---|---|---|---|---|---|
| .11 | 8080 | Apache httpd | open | **filtered** | ✅ | ✅ | verified | open |
| .12 | 21 | vsftpd | open | **filtered** | ✅ | ✅ | verified | open |
| .13 | 6379 | Redis | open | **filtered** | ✅ | ✅ | verified | open |

- **Exposure-reduction success: 3/3 = 1.00**
- **Rollback success: 3/3 = 1.00**
- **Management channel intact: 3/3** — SSH remained reachable throughout
- Applied: `nft add element inet cybershield blocked_tcp { <port> }`
- Rolled back: `nft delete element inet cybershield blocked_tcp { <port> }`

After the run, each target's `blocked_tcp` set was confirmed **empty** and each
port confirmed `open` again.

**What this shows, precisely.** Port reachability changed as observed by this
scanner, and reverted. It does **not** show that any vulnerability was patched,
fixed or removed. Every service kept running throughout, and CVE-2021-41773 on
Apache 2.4.49 was equally present before, during and after.

---

## 6. Timing

Three repetitions of the same service-detection scan (46-port explicit set,
4 hosts, `-T4 --max-retries 1`):

| Run | Duration |
|---|---|
| 1 | 16.586 s |
| 2 | 16.498 s |
| 3 | 15.666 s |

Mean **16.25 s**, min 15.67 s, max 16.59 s, sd 0.51 s.

n = 3 on one machine and one lab. Reported as observed values, not as a
performance claim, and no confidence interval is given for a sample this size.

Correlation completed in 0.13 s because all 14 NVD queries were served from the
local cache. A cold run is bounded by NVD's rate limit of 5 requests / 30 s
without an API key.

---

## 7. Audit

The hash chain verified intact across **106 entries** covering every scan,
correlation, plan, application, verification and rollback in this run.

The chain makes tampering *detectable* and locates it. It does not *prevent*
it: anyone who can write the file can rewrite the whole chain.

---

## 8. Metrics summary

| Metric | Value |
|---|---|
| Services detected | 12 |
| Services scored against ground truth | 8 |
| Correct identifications | 8 |
| **Detection accuracy** | **1.00** (n=8) |
| CVE candidates | 278 |
| Auto-flagged probable false positives | 14 (**5.04%**, lower bound) |
| CPE resolution rate | 1.00 |
| NVD correlation success rate | 1.00 |
| Eligibility: ALLOW / DENY / REVIEW | 3 / 8 / 1 |
| **Exposure-reduction success** | **3/3 = 1.00** |
| **Rollback success** | **3/3 = 1.00** |
| Management channel preserved | 3/3 |
| Mean scan time | 16.25 s (n=3) |
| Audit chain | valid, 106 entries |

### Not computed

- **Reviewed false-positive rate** — requires a human to adjudicate each
  candidate against the CVE text. The 5.04% above is a machine check for one
  failure mode and is a lower bound.
- **Exploitability** — never measured. No exploitation is attempted, by design.
- **False negatives** — the scan uses an explicit 46-port list, so a service on
  an unlisted port would not be found. No independent full-port sweep was run
  to quantify what was missed.

---

## 9. Threats to validity

1. **Sample size.** One lab, 4 hosts, 12 services, 3 scan repetitions. The
   perfect scores in §2 and §5 characterise this environment, not the method in
   general.
2. **Software selection bias.** All four products are common and well
   fingerprinted. Obscure or custom services would very likely lower detection
   accuracy.
3. **Container networking is not bare metal.** Isolation was applied inside a
   container network namespace. A host firewall on physical hardware behaves
   differently.
4. **Single vantage point.** Verification measures reachability from this
   scanner only. It is not evidence that a port is unreachable from elsewhere.
5. **Loss-free local link.** `--max-retries 1` is safe here and would risk false
   negatives on a lossy network.
6. **Explicit port list.** The scan finds only what it is told to look for.
   This is a deliberate trade for reproducibility after `--top-ports` was found
   to silently exclude 6379/tcp.
7. **NVD data changes.** Candidate counts depend on NVD's contents on the run
   date. Raw responses are cached under `data/nvd_cache/` so the analysis can be
   reproduced against the same data.
8. **`AutoAddPolicy` for SSH host keys.** Acceptable for ephemeral lab
   containers whose keys change on every rebuild; wrong for durable hosts.

---

## 10. Evidence layout

```
experiments/
  ground_truth.yaml                     independently-read reference versions
  raw/*.xml                             raw Nmap output for every scan
  scans/<session>.json                  normalized results + run manifest
  reports/<session>_correlation.json    per-service correlation detail
  reports/experiment_<ts>.json          full experiment record and metrics
  reports/screenshots/*.png             dashboard screenshots of this data
  remediation/<request_id>.json         plan, apply, verification, rollback
reports/audit_log.jsonl               hash-chained audit log, verifiable snapshot
```
