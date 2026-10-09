# Safety Controls

Every control, how it is enforced, and the test that holds it in place.
Decision logic is diagrammed in
**[Figure 4](figures.md#figure-4--risk-aware-remediation-decision-flow)**.

## Design principle: fail closed

The decision engine initialises its verdict to `DENY` and raises it to `ALLOW`
only after all nine rules pass. Any unexpected exception anywhere in the chain
yields `DENY`, never `ALLOW`. Refusal functions raise rather than returning
`False`, so a caller who forgets to check a return value still cannot proceed.

## Controls

Controls 1-21 were the original set; 22-32 were added with operator
authentication, UI scope management and real-LAN assessment.

| # | Control | Enforced in | Test |
|---|---|---|---|
| 1 | Authorization signature | `core/authorization.py` — unsigned `AUTHORIZATION.md` refuses every scan and remediation | `test_authorization.py` |
| 2 | Scope enforcement | `authorized_targets.yaml` ships **empty**; a target outside it is refused before Nmap runs | `test_authorization.py` |
| 3 | Public-range guard | Routable ranges rejected at config load unless `allow_public: true` | `test_authorization.py` |
| 4 | Hostname rejection | Scan targets must be numeric — a DNS name could resolve differently between check and use | `test_validation.py` |
| 5 | Protected ports | tcp/22, 80, 443, 2222 can never be isolated | `test_decision.py` |
| 6 | Anti-lockout | The live SSH port is protected even on a non-standard port and even if removed from the list | `test_decision.py` |
| 7 | Approved-service policy | An open port is not presumed unauthorized; unclassified defaults to `review_required` | `test_decision.py` |
| 8 | Confidence threshold | Below MEDIUM goes to review — a keyword-only match cannot drive action | `test_decision.py` |
| 9 | Severity threshold | Evaluated **last**, so it never overrides an earlier refusal | `test_decision.py` |
| 10 | No override exists | `evaluate()` and `apply_plan()` accept no force/bypass parameter | `test_decision.py`, `test_remediation.py` |
| 11 | Mandatory confirmation | `confirmed` has no default; omission is refusal | `test_remediation.py` |
| 12 | Reversibility | Rollback command computed and persisted before apply | `test_remediation.py` |
| 13 | TTL auto-revert | Watchdog plus a startup sweep for rules that outlived the process | `test_remediation.py` |
| 14 | Dry-run default | Live enforcement is opt-in via env var | `test_remediation.py` |
| 15 | Isolated firewall table | Only the `cybershield` table is touched | `test_remediation.py` |
| 16 | Safe command execution | Single entry point, argv arrays, `shell=False`, mandatory timeout | `test_exec.py` |
| 17 | No intrusive Nmap | `-T5` and `vuln`/`exploit`/`brute`/`dos` NSE rejected at config load | `test_nmap_runner.py` |
| 18 | Runner-owned arguments | A profile cannot set `-oX`, `-iL`, or other output flags | `test_nmap_runner.py` |
| 19 | XXE resistance | Nmap XML parsed with `defusedxml`; banners are attacker-influenced | `test_nmap_parser.py` |
| 20 | Tamper-evident audit | Hash-chained JSONL; modification, deletion and forgery all detected | `test_audit.py` |
| 21 | macOS never a target | No local firewall execution path exists | structural |
| 22 | Authenticated access | Every page and `/api/*` route requires a session; the gate is middleware, so a new route is protected by default | `test_web.py::TestAuthenticationGate` |
| 23 | Password storage | bcrypt cost 12; no plaintext column, and no password or hash in any log line | `test_auth.py` |
| 24 | Session revocation | Sessions are database rows; logout revokes, expiry and disabled accounts refuse | `test_auth.py::TestSessions` |
| 25 | No account enumeration | "No such user" and "wrong password" are byte-identical, and both cost a real bcrypt verification | `test_auth.py` |
| 26 | UI scope additions are private-only | An explicit allowlist of RFC1918/loopback/link-local; reserved and documentation ranges refused, `/22` size cap | `test_scope_admin.py` |
| 27 | UI scope additions are assessment-only | Written `is_lab: false`; remediation on them is refused by the decision engine | `test_scope_admin.py::TestAssessmentOnly` |
| 28 | Scope changes are confirmed and audited | `confirmed=True` mandatory; `scope.target_authorized` records operator and range | `test_scope_admin.py` |
| 29 | Scope file cannot be left broken | The rewrite is re-loaded and rolled back if it would not parse, so a bad edit cannot refuse the laboratory | `test_scope_admin.py::TestFileIntegrity` |
| 30 | Unreachable is never clean | A target answering nothing is `completed_unreachable` with a note, never a host with no findings | `test_reachability.py` |
| 31 | Failed scan writes no findings | Unparseable Nmap output yields a `failed` scan row with its error and zero host/service/CVE rows | `test_nmap_parser.py`, structural |
| 32 | Recovered XML is never called complete | A repaired truncated file sets `is_complete = False` and drops partial elements rather than guessing | `test_nmap_parser.py` |

## The no-override guarantee

Spec §6B requires that no `force=true`-style parameter exists. Three tests
assert this on the *signatures* rather than the behaviour, so the guarantee
cannot be removed by accident:

```python
assert set(inspect.signature(evaluate).parameters) == {"config", "request"}
assert not (set(inspect.signature(apply_plan).parameters) & {"force", "override", ...})
assert not (set(ApplyRequest.model_fields) & {"force", "override", "bypass", ...})
```

The API's `confirm` field is **not** an override. It is the mandatory human
acknowledgement; the executor refuses any verdict other than `ALLOW` regardless
of its value.

## Protected-port override: future work, deliberately unimplemented

`protected_ports.yaml` documents an administrative override workflow as future
work. It is **not implemented**. There is no runtime path, API parameter or UI
control that lifts protection. Changing it requires editing the file and
restarting — a deliberate, auditable act rather than a request parameter.

Note that ports 22, 80 and 443 being permanently protected means a vulnerable
service on those ports **cannot be isolated by this system at all**. That is a
real functional limitation accepted in exchange for the guarantee, and it is why
the laboratory's Apache listens on 8080.

## Refusals observed in the recorded experiment

From the run in `experiments/README.md`, all evaluated before any command was
constructed:

| Attempt | Verdict | Rule |
|---|---|---|
| Isolate tcp/2222 (live SSH channel) | DENY | protected_port |
| Isolate tcp/22 at CRITICAL severity | DENY | protected_port |
| Isolate tcp/21 on 8.8.8.8 | DENY | authorized_lab_target |
| Isolate tcp/3306, MEDIUM severity | REVIEW_REQUIRED | severity_threshold |
| Isolate tcp/21 on lab-ftp | ALLOW | all nine passed |

Four SSH channels carrying CRITICAL candidates at HIGH confidence were refused
anyway. Severity does not outrank a protected port.

## Known weaknesses

- **The audit chain is tamper-evident, not tamper-proof.** Anyone who can write
  the file can rewrite the whole chain. Detection locates the first altered
  entry; it does not prevent alteration.
- **`AutoAddPolicy` for SSH host keys.** Acceptable for ephemeral lab containers
  whose host keys change on every rebuild; wrong for durable hosts, where a
  changed key should abort the connection.
- **Single operator model.** There is no authentication on the dashboard or API.
  It binds to localhost and assumes a single trusted operator. Not suitable for
  a shared host without adding authentication.
- **TTL timers are in-process.** A crash loses the timers; `sweep_expired()` at
  startup is what covers that gap, and it only runs when the process is
  restarted.
