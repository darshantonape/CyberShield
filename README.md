# CyberShield

**Lightweight Vulnerability Scanner with Controlled Network Exposure Reduction**

A final-year cybersecurity research project. **Authorized laboratory environments only.**

---

## What this system does — and does not do

**Objective 1 (primary).** Discover network hosts, identify exposed services and
software versions, normalize detected software into signatures, and correlate
those against CVE/NVD records. This works against both the Docker laboratory and
an explicitly authorized device on the operator's own private LAN.

**Objective 2 (limited).** Apply controlled, **reversible** firewall-based
isolation of an eligible exposed service on an authorized Linux laboratory
target, then verify the change by rescanning.

### Boundaries, stated plainly

CyberShield reduces **network exposure**. It does not patch software.

- Blocking a port does **not** fix, patch, or remove the underlying vulnerability.
- Detecting a software version does **not** prove the service is exploitable.
- A CVE correlation is a **candidate** requiring human review, not a confirmed finding.
- Verification confirms port reachability changed **from the scanner's vantage
  point** — not that the service is unreachable from everywhere.

The system implements no exploitation, no penetration testing, no credential
attacks, and no automatic OS or package patching.

---

## Safety controls

| Control | Behaviour |
|---|---|
| Operator authentication | Every page and every `/api/*` route requires a session; unauthenticated HTML redirects to `/login`, API returns 401 |
| Password storage | bcrypt (cost 12); no plaintext column, no password or hash in any log |
| Authorization signature | `AUTHORIZATION.md` must be signed; unsigned ⇒ every scan and remediation refused |
| Scope enforcement | Only ranges in `config/authorized_targets.yaml` may be scanned; ships **empty** |
| Scope additions | UI-added targets must be private IPv4, ≤ /22, explicitly confirmed, and are always `is_lab: false` |
| Assessment vs remediation | A target added from the UI can be scanned and **never** firewall-modified |
| Unreachable ≠ clean | A target that answers nothing is recorded `completed_unreachable`, never as a host with no findings |
| Failed scan ≠ clean | Unparseable Nmap output is recorded `failed` with its error; zero host, service or CVE rows are written |
| Public-range guard | Routable ranges rejected at config load unless explicitly opted in |
| Protected ports | tcp/22, 80, 443 can **never** be isolated — no override exists |
| Anti-lockout | The live SSH management port is protected even on a non-standard port |
| Approved-service policy | An open port is not presumed unauthorized; unclassified ⇒ `review_required` |
| Reversibility | The rollback command is computed and stored **before** any rule is applied |
| TTL watchdog | Applied rules auto-revert after `CYBERSHIELD_REMEDIATION_TTL_MINUTES` |
| Dry-run default | Live enforcement is opt-in via `CYBERSHIELD_REMEDIATION_BACKEND` |
| Audit log | Hash-chained append-only JSONL; tampering is detectable and located |
| Command execution | Single entry point, argv arrays, `shell=False`, mandatory timeouts |
| macOS host | Never a remediation target — there is no local-execution code path |

There is deliberately **no `force=true`** parameter anywhere. A unit test asserts
on the decision engine's signature so the guarantee cannot be quietly removed.

---

## Requirements

- macOS (developed on 26.1, Apple Silicon)
- Nmap 7.9x — `brew install nmap`
- Python 3.13 via `uv` (see the environment note below)
- Colima + Docker, for the laboratory target

### Environment note: Homebrew Python is broken on this machine

Homebrew's `python@3.13` and `python@3.14` bottles both link `pyexpat` against
`/usr/lib/libexpat.1.dylib` and require a symbol
(`_XML_SetAllocTrackerActivationThreshold`) that macOS 26.1's system expat does
not export. This breaks `xml.etree.ElementTree`, `defusedxml`, and even `pip`
bootstrapping — i.e. exactly what is needed to parse Nmap XML.

The project therefore uses a **standalone CPython** managed by `uv`, which ships
its own libexpat:

```bash
brew install uv
uv python install 3.13
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r requirements.txt
```

---

## Setup

```bash
cd ~/Desktop/CyberShield

# 1. Environment (see note above)
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r requirements.txt

# 2. Configure secrets
cp .env.example .env      # add NVD API key and SSH key path

# 3. Declare your authorized scope
$EDITOR config/authorized_targets.yaml

# 4. Sign the authorization
$EDITOR AUTHORIZATION.md  # set signed: true and complete every field

# 5. Verify
./.venv/bin/python scripts/preflight.py

# 6. Start the app, then create the first operator account at /signup
```

Preflight reports whether an operator account exists, which private subnets this
machine is on, and which of them are authorized. A subnet appearing in that list
is **not** authorized by being there.

Preflight exits non-zero while any required check fails, so it can gate a
scripted experiment run.

## Running

```bash
./.venv/bin/python -m uvicorn backend.main:app --reload --port 8000
```

- Console: <http://127.0.0.1:8000/> (redirects to `/login`)
- API docs: <http://127.0.0.1:8000/docs>

**First run.** There is no default account and no default password. Open
<http://127.0.0.1:8000/signup> and create one; it becomes the operator recorded
against every scan and remediation. Passwords are stored as bcrypt hashes.

**Forgot password.** `/login` → *Forgot Password?* → enter an email or username.
The response is identical whether or not the account exists. A single-use link
valid for 30 minutes is delivered by SMTP (`CYBERSHIELD_SMTP_*` in `.env`), or,
with `CYBERSHIELD_ENV=development`, printed to the server console for local
testing. Redeeming it sets the new password and signs out every session.

Pages: dashboard (counts, severity distribution, CVSS coverage, scan outcomes,
remediation status, recent audit events), targets (scope management), scans,
vulnerabilities, remediation (review / approve / result), SSH channel, audit. Server-rendered Jinja2 — no CDN, no
vendored JS framework, works offline. Screenshots of a real run are in
`experiments/reports/screenshots/`.

Everything except `/login`, `/signup` and `/api/health` requires a session. The
gate is middleware, not a per-route dependency, so a route added later is
protected by default rather than accidentally public.

---

## Two kinds of target

CyberShield distinguishes what it may **scan** from what it may **modify**.

| | Laboratory target | Authorized LAN target |
|---|---|---|
| Declared in | `config/authorized_targets.yaml`, by hand | the Targets page, or `POST /api/targets` |
| `is_lab` | `true` | always `false` |
| Scanning | permitted | permitted |
| Firewall isolation | permitted, approval-gated | **refused** |
| Requires | `ssh_user`, a reachable management port | private IPv4, ≤ /22, explicit confirmation |
| Profiles | `discovery`, `service_detect` | `lan_discovery`, `lan_service_detect` |

### Assessing a device on your own Wi-Fi

1. Open **Targets**. The page lists the private subnets this machine is actually
   on — nothing is hardcoded, because every network uses a different subnet.
2. Enter the address you have permission to assess, e.g. `192.168.1.25` (a bare
   address becomes a `/32`), or a subnet such as `192.168.1.0/24`.
3. Tick the confirmation box. Without it the request is refused.
4. Open **Scans**, pick the target, and choose the `lan_service_detect` profile.

The LAN profiles pass `-Pn`, which is the difference that matters. Windows
blocks inbound connections by default, so with normal host discovery Nmap
declares the machine down and reports *zero services* for a laptop that is
sitting right there. With `-Pn` the ports are probed anyway and reachability is
decided from the port results instead.

If nothing answers, the scan is recorded as `completed_unreachable` and the UI
says **AUTHORIZED + UNREACHABLE**, listing the ordinary causes — host firewall,
Wi-Fi client isolation, wrong subnet, device asleep, DHCP address change. It is
never reported as a host with no vulnerabilities.

A target is never scanned because it is reachable. Only because it was
authorized.

Ranges accepted from the Targets page: any subnet inside `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` or `169.254.0.0/16`, from a
single `/32` up to a `/22` (1024 addresses). Wider than `/22` is refused so
that one form submission cannot authorize a sweep of a large network; a broader
range must be a deliberate edit to `config/authorized_targets.yaml`. Public,
documentation and benchmark ranges are refused outright.

Full detail, including why `-Pn` matters and what "unreachable" can and cannot
tell you: **[docs/lan-assessment.md](docs/lan-assessment.md)**.

---

## Authorization — read this before scanning anything

Scanning or modifying a system you do not own, without written permission to
test it, is unlawful in most jurisdictions. CyberShield is built so that using
it lawfully is the path of least resistance, but it cannot make that judgement
for you:

- `AUTHORIZATION.md` must be signed, and its `scope_description` should describe
  every range you have authorized — including any LAN target you add later.
- Every target must be added and confirmed explicitly. The confirmation box is a
  statement that you own the target or hold written permission to assess it.
- Public ranges cannot be authorized from the interface at all.
- Only laboratory targets you configured by hand, with SSH details, can have
  their firewall modified — and only after an approval you give per action.

"Another device on my Wi-Fi" is not the same as "a device I am authorized to
assess". Ask the owner first.

## A complete run, in order

1. **Sign in** at `/login`, or create the first account at `/signup`.
2. **Targets** — add the private IPv4 address or subnet you are authorized to
   assess, and confirm it. The page shows the subnets this machine is actually
   on; those are suggestions, not authorizations.
3. **Scans** — pick the target. Pre-scan status shows `AUTHORIZED` or
   `NOT AUTHORIZED` before you run anything, and reachability as `UNKNOWN`
   because nothing has been probed yet. Choose a profile:
   `discovery` / `service_detect` for the lab, `lan_discovery` /
   `lan_service_detect` for a real network. Leave *Correlate against NVD* ticked.
4. **Scan result** — hosts, open ports, service, product, version, and Nmap's
   own confidence. Reachability is stated explicitly; an unreachable target says
   so rather than showing zeros.
5. **Vulnerabilities** — CVE candidates with severity, CVSS (with its version),
   correlation confidence, matching method, and probable-false-positive flags.
   Filter by severity, confidence, CVE, host, port, service, review status or
   scan scope. Open one to see what was queried and why, and to record your own
   review verdict.
6. **Remediation** — candidates with their verdict. `Review & approve` opens the
   full nine-rule decision, the exact `nft` commands, the rollback command, and
   the TTL. Nothing is sent until you tick the acknowledgement and approve.
7. **Result** — before/after port state, whether exposure was reduced, whether
   the management channel survived, the verification rescans, and this action's
   audit entries. Roll back from here, or let the TTL do it.
8. **SSH channel** — why remediation needs SSH, whether the channel is usable,
   and a one-command connection test. Key paths only; never key material.
9. **Audit log** — every event above, hash-chained, with chain verification.

## Where things live

| Thing | Path |
|---|---|
| SQLite database | `data/cybershield.db` (WAL: `-shm` / `-wal` alongside) |
| Audit log (authoritative) | `data/audit.jsonl` — hash-chained, append-only |
| Raw Nmap XML | `data/raw/<session>_<profile>_<timestamp>.xml` |
| Authorized scope | `config/authorized_targets.yaml` |
| Scan profiles | `config/scan_profiles.yaml` |
| Protected ports | `config/protected_ports.yaml` |
| Service policy | `config/approved_services.yaml` |
| Secrets / toggles | `.env` (gitignored) |
| Research evidence | `experiments/` |

There is exactly one database. `init_db()` runs on startup: it creates missing
tables with `create_all`, then applies any missing **columns** via
`backend/database/migrate.py`, which is `ADD COLUMN` only — it never drops,
renames or rewrites a column, and never deletes a row. Starting the app on an
existing database therefore preserves every user, scan and finding. Starting it
on a clean checkout creates the schema from scratch.

## Tests

```bash
./.venv/bin/python -m pytest tests/ -q
```

591 tests, plus 14 integration tests that need the live lab or the network;
those are marked `integration` and excluded from the default run.

The suite asserts safety properties, not just behaviour: that an unauthenticated
request cannot reach a page or start a scan, that no password or session token
reaches the database or the audit log in a usable form, that the login form
cannot be used to enumerate accounts, that a target added from the UI cannot be
firewall-modified, that a public or reserved range cannot be authorized, that a
truncated Nmap file never invents a port, and that the decision engine has no
`force` parameter.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/figures.md](docs/figures.md) | Figures 1-6 with captions; rendered SVG/PNG in `docs/figures/` |
| [docs/architecture.md](docs/architecture.md) | Components, technology choices, what runs where |
| [docs/data-flow.md](docs/data-flow.md) | Pipelines; what each stage may and may not conclude |
| [docs/safety-controls.md](docs/safety-controls.md) | All controls and the tests holding them |
| [docs/authentication.md](docs/authentication.md) | Operator accounts, sessions, and the request gate |
| [docs/lan-assessment.md](docs/lan-assessment.md) | Assessing an authorized device on a real Wi-Fi network |
| [docs/threats-to-validity.md](docs/threats-to-validity.md) | Consolidated measured limitations |
| [docs/lab-setup.md](docs/lab-setup.md) | Laboratory topology and reachability |
| [experiments/README.md](experiments/README.md) | Experimental results and metrics |

## Layout

```
backend/
  auth/           operator accounts, DB-backed sessions, the request gate
  core/           authorization, validation, safe exec, hash-chained audit, config,
                  scope administration, local-interface detection, error explanations
  scanner/        Nmap execution, XML parsing and truncation recovery, reachability
  normalization/  Nmap product strings -> vendor/product/version -> CPE
  nvd/            NVD client, cache, correlation, CVSS severity resolution
  risk/           ALLOW / REVIEW_REQUIRED / DENY decision engine
  remediation/    eligibility, SSH adapter, nftables/ufw/dryrun backends, rollback
  verification/   before/after rescanning
  database/       SQLAlchemy models, session management, additive migrations
  main.py         FastAPI entry point
frontend/         Jinja2 templates and static assets
config/           authorized_targets, protected_ports, approved_services, scan_profiles
lab/              deliberately vulnerable laboratory target definitions
experiments/      research evidence: raw/, scans/, remediation/, reports/
docs/             architecture, data flow, safety controls, threats to validity
tests/            unit and integration tests
```

---

## Status

| Milestone | Scope | State |
|---|---|---|
| M1 | Foundation: config, safety core, DB schema, decision engine, API skeleton | **Complete** |
| M2 | Nmap runner, XML parser, host and service discovery | **Complete** |
| M3 | Normalization and NVD/CVE correlation | **Complete** |
| M4 | Web dashboard | **Complete** |
| M5 | Laboratory target environment | **Complete** |
| M6 | SSH isolation, rollback, verification | **Complete** |
| M7 | Experiments | **Complete** |
| M8 | Documentation and diagrams | **Complete** |
| M9 | Operator authentication, scope management from the UI, real-LAN assessment, reachability reporting, console redesign | **Complete** |

### First laboratory run — 2026-08-30

Session `4fc9c1f6bae14ab7`, config `54eb1f109d7298c3`, Nmap 7.991. Evidence in
`experiments/`. These are real measurements, not estimates.

| Host | Port | Product | Detected | Normalized | CVEs | Flagged FP |
|---|---|---|---|---|---|---|
| .11 | 8080 | Apache httpd | 2.4.49 | 2.4.49 | 81 | **12** |
| .12 | 21 | vsftpd | 3.0.3 | 3.0.3 | 2 | 0 |
| .13 | 6379 | Redis | 5.0.14 | 5.0.14 | 21 | 1 |
| .14 | 3306 | MariaDB | 5.5.5-10.5.29 | **10.5.29** | 3 | 1 |
| all | 22 / 2222 | OpenSSH | various | various | 171 | 0 |

4 hosts, 12 open services, scan 15.7s, **278 CVE candidates**, 14 auto-flagged
as probable false positives (**5.0%**). Severity: 31 CRITICAL / 114 HIGH /
109 MEDIUM / 24 LOW. CVSS coverage: 249 v3.1, 1 v3.0, 28 v2.0. All matches via
`cpe_exact`; the keyword fallback was never needed.

Full experimental results, methodology and threats to validity:
**[`experiments/README.md`](experiments/README.md)**

### Controlled exposure reduction — 2026-08-30

Request `fb5234dc32d74cef`, target `lab-ftp` (192.168.64.12), tcp/21 (vsftpd
3.0.3, 2 CVE candidates, max severity HIGH). Evidence in
`experiments/remediation/`, raw Nmap XML for every observation in
`experiments/raw/`.

| Stage | Command | Observed port state |
|---|---|---|
| Before | — | **open** |
| Apply | `nft add element inet cybershield blocked_tcp { 21 }` | **filtered** |
| Rollback | `nft delete element inet cybershield blocked_tcp { 21 }` | **open** |

`exposure_reduced: true` · `management_channel_intact: true` ·
`rollback_verified: true` · audit chain intact across 16 entries.

Safety refusals verified in the same run, all before any command was sent:

| Attempt | Verdict |
|---|---|
| Isolate tcp/2222 (live SSH management channel) | **DENY** — protected port |
| Isolate tcp/22 with CRITICAL severity | **DENY** — protected port |
| Isolate tcp/21 on 8.8.8.8 | **DENY** — outside authorized scope |
| Isolate tcp/21 on lab-ftp | **ALLOW** — all 9 rules passed |

SSH into the target was exercised *after* isolation to prove the anti-lockout
guard held. Live enforcement was then returned to `dryrun`, and the target's
`blocked_tcp` set was confirmed empty.

**What this does and does not show.** The port's reachability changed from
this scanner's vantage point, and reverted. vsftpd never stopped running, no
software was patched, and CVE-2021-30047 and CVE-2021-3618 remain equally
present on the target throughout.

---

## Measured NVD behaviour

Verified against the live NVD REST API 2.0 on 2026-08-30. These measurements
drove the correlation design and belong in the paper's methodology and
threats-to-validity sections.

**1. Keyword search under-reports severely.** CPE matching is therefore the
primary path and keyword search a labelled fallback.

| Query for Apache httpd 2.4.49 | CVEs |
|---|---|
| `keywordSearch=Apache httpd 2.4.49` | **0** |
| `cpeName=cpe:2.3:a:apache:http_server:2.4.49:*:...` | **81** |

**2. CPE queries over-report.** Of those 81 Apache candidates, the
applicability check automatically flagged **12 (14.8%)** as probable false
positives — no vulnerable `cpeMatch` named `apache:http_server`. Examples:
CVE-2007-4723 (references `ragnarok_online_control_panel`), CVE-2011-2688
(`mod_authnz_external`), CVE-2013-4365 (`mod_fcgid`).

**3. The CPE dictionary's keyword ranking does not identify the vendor that
carries the CVEs.** Searching the dictionary for "redis" ranks
`redislabs:redis` and `pivotal_software:redis` highest; for Redis 5.0.14 both
return **0** CVEs, while `redis:redis` returns **21**. Every vendor pair in
`backend/normalization/product_map.py` was therefore verified by CVE count, not
by dictionary rank. Plausible guesses were often wrong — nginx is
`igor_sysoev:nginx`, not `f5:nginx`.

**4. Some products have several legitimate vendor prefixes.** MySQL 5.7.44
returns 12 CVEs under `oracle:mysql` and 2 under `mysql:mysql`; neither is a
superset. Such products yield one signature per vendor, and confidence is
capped at MEDIUM to record the ambiguity.

**5. A `cpeName` query with `version=*` returns zero results**, so a service
whose version Nmap could not determine cannot be correlated by CPE at all. It
falls through to the keyword path at LOW confidence.

**6. CVSS metrics are heterogeneous.** Responses mix `cvssMetricV2`,
`cvssMetricV30`, `cvssMetricV31` and `cvssMetricV40`. v2 entries carry
`baseSeverity: null`, so the band is derived from the score — and CVSS v2 has
no CRITICAL band, so a 9.8 v2 score is HIGH.
