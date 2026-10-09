# Data Flow

Diagrams: **[Figure 2](figures.md#figure-2--vulnerability-detection-workflow)**
(detection), **[Figure 3](figures.md#figure-3--nvdcve-correlation-workflow)**
(correlation), **[Figure 5](figures.md#figure-5--controlled-isolation-and-verification-workflow)**
(isolation), **[Figure 6](figures.md#figure-6--database-and-data-flow-architecture)**
(schema).

## Assessment pipeline (Objective 1)

```
auth.middleware                                FAIL-CLOSED, no session -> no request
 └─> config/authorized_targets.yaml            written only by core.scope_admin
      └─> core.authorization.assert_in_scope() FAIL-CLOSED, before any packet
      └─> scanner.nmap_runner                  argv array, shell=False, timeout
           └─> data/raw/<session>.xml          raw evidence written before parsing
                └─> scanner.nmap_parser        defusedxml; banners are untrusted input
                     │                         truncated output repaired and FLAGGED,
                     │                         unreadable output -> scan status=failed
                     └─> scanner.reachability  reachable / unreachable / unknown
                     └─> discovered_hosts, discovered_services
                          └─> normalization    version cleaning, product map, CPE 2.3
                               └─> software_signatures
                                    └─> nvd.correlate
                                         ├─ PRIMARY  ?cpeName=      match_method=cpe_exact
                                         └─ FALLBACK ?keywordSearch= match_method=keyword (LOW)
                                              └─> applicability check
                                                   └─> nvd.severity  v3.1 > v4.0 > v3.0 > v2
                                                        └─> vulnerabilities (status=candidate)
                                                             └─> experiments/
```

### What each stage may and may not conclude

| Stage | May conclude | May **not** conclude |
|---|---|---|
| Port scan | This port answered / did not answer, from here | That nothing listens on unscanned ports |
| Version detection | The service advertised this string | That the string is truthful |
| Normalization | This is the upstream version of the advertised string | A version, where none was advertised |
| CPE construction | This vendor:product is a plausible identity | That it is the only one |
| NVD query | NVD returns these CVEs for this CPE | That they apply to this deployment |
| Applicability check | No vulnerable `cpeMatch` names this product | That the candidate is definitely wrong |
| Severity | NVD publishes this base score | That this is the risk here |
| Reachability | This target answered, or answered nothing, from here | That an unanswering target is secure, absent, or free of vulnerabilities |
| A failed scan | That the scan could not be read | Anything at all about the target |

### Three outcomes, never collapsed

A completed scan, an unreachable target and a failed scan are stored as
different statuses, because they support different conclusions:

| Status | Hosts / services rows | What it means |
|---|---|---|
| `completed` | written | The target answered and the results are exhaustive for the profile's port list |
| `completed_with_timeouts` | written, **truncated** | A host hit `--host-timeout`, or the XML was repaired. An absent port proves nothing |
| `completed_unreachable` | none, or hosts with no answering port | In scope, nothing answered. **Nothing was learned** |
| `failed` | **none** | Nmap could not run or its output could not be read. No findings are fabricated |

Collapsing the last two into `completed` is what makes a dashboard report zero
vulnerabilities for a machine it never reached.

## Remediation pipeline (Objective 2)

```
Operator selects a finding
 1. authorization.assert_authorized_lab_target()   in scope, is_lab, has ssh_user
 2. risk.decision.evaluate()                       nine rules, fail-closed
 3. plan.build_plan()                              apply + INVERSE rollback + TTL
 4. persist remediation_actions row                BEFORE anything is sent
 5. verification.observe_port()                    BEFORE state (real rescan)
 6. ssh_adapter.connect()                          key-based SSH
 7. backend.ensure_prepared()                      idempotent, cybershield table only
 8. backend.apply_argv                             add port to blocked_tcp set
 9. audit.record()                                 hash-chained
10. verification.observe_port()                    AFTER state (real rescan)
11. verification.observe_port(ssh_port)            anti-lockout check
12. compare_observations()                         exposure_reduced true/false
13. TtlWatchdog.arm()                              auto-revert on expiry
14. rollback() -> observe_port()                   restoration verified
```

Step 4 precedes step 8 deliberately: a crash between them still leaves the exact
rollback command in the database.

## Evidence written per run

| Path | Contents |
|---|---|
| `data/raw/<session>.xml` | Raw Nmap output, unmodified |
| `experiments/raw/<session>.xml` | Version-controlled copy of the same |
| `experiments/scans/<session>.json` | Normalized results + run manifest |
| `experiments/reports/<session>_correlation.json` | Per-service correlation detail |
| `experiments/remediation/<request_id>.json` | Plan, apply, verification, rollback |
| `experiments/reports/experiment_<ts>.json` | Full experiment record and metrics |
| `data/audit.jsonl` | Hash-chained audit log (live, gitignored) |
| `experiments/reports/audit_log.jsonl` | Committed snapshot of the same, chain-verifiable |

Each run manifest carries the Nmap version, the exact argv, the config hash and
the duration, so a result can be re-derived and attributed to the policy that
produced it.

## A trap for analysis queries

`scan_sessions` records **every** scan, including the single-port verification
rescans from remediation. An analysis query that does not filter by
`scan_kind='assessment'` will over-count. This caused three separate defects
during development — inflated host counts, inflated service counts, and doubled
CVE candidate counts — each of which produced plausible but wrong figures.
Filter by `scan_kind`, and scope vulnerability counts through the service IDs of
one assessment session.
