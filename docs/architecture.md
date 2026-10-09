# Architecture

See **[Figure 1](figures.md#figure-1--overall-cybershield-architecture)** for the
system diagram.

## Separation of concerns

CyberShield splits into two halves that never merge:

| macOS control machine | Authorized Linux laboratory target |
|---|---|
| Dashboard, API, job runner | Deliberately exposed services |
| Nmap execution (as scan *source*) | `sshd` — management channel |
| Normalization, NVD correlation, severity | `nftables` — **the only place rules are applied** |
| Risk decision engine | |
| SQLite storage, reports, audit log | |
| Paramiko SSH **client** | |

The macOS host cannot be a remediation target. This is not a policy but a
structural property: the only code that changes firewall state is
`backend/remediation/ssh_adapter.py`, which has no local-execution branch, and
`pfctl` appears nowhere in the codebase.

## Component map

```
backend/
  auth/           operator accounts, DB-backed sessions, the request gate
  core/           authorization, validation, safe exec, hash-chained audit, config,
                  scope administration, local-interface detection, error explanation
  scanner/        Nmap runner, XML parser + truncation recovery, reachability,
                  scan pipeline
  normalization/  CPE 2.2 to 2.3, version cleaning, curated product map
  nvd/            client, disk cache, correlation, CVSS resolution
  risk/           ALLOW / REVIEW_REQUIRED / DENY decision engine
  remediation/    plan, SSH adapter, nftables + dryrun backends, executor, TTL
  verification/   before/after rescanning and comparison
  database/       SQLAlchemy models, session management, additive migrations
  jobs/           DB-backed background runner
  web/            server-rendered console views
  main.py         FastAPI entry point
```

## Technology choices and why

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.13 via `uv` | See *Environment constraint* below |
| API | FastAPI + Uvicorn | Typed, auto OpenAPI docs usable as paper evidence |
| Dashboard | Jinja2, server-rendered | No build step, no CDN, works offline |
| Database | SQLite + SQLAlchemy 2.x, WAL | Single-user research tool; the DB file *is* a portable artifact |
| Scanner | Nmap subprocess to `-oX`, parsed with `defusedxml` | Argv arrays, no shell. Deliberately **not** `python-nmap`, which is unmaintained and builds shell strings |
| CVE source | NVD REST API 2.0, self-throttled, disk-cached | Cache makes experiments reproducible offline |
| SSH | Paramiko | Key-only auth, no password path |
| Firewall | nftables named set | Only design where the rollback command is derivable before applying — see below |
| Jobs | `concurrent.futures` + DB-backed job table | Scans outlive a request; no Celery/Redis complexity |
| Audit | Hash-chained JSONL | Tamper-evident, verifiable, cheap |
| Auth | bcrypt + DB-backed session rows | Logout must be a real revocation; no signing key to manage, and `itsdangerous` is unavailable here. See `authentication.md` |
| Schema change | `create_all` + ADD COLUMN migrations | Alembic is a declared dependency but was never initialised, so stamping the live DB with a baseline it never had risks data loss. Columns are added, never dropped or rewritten |

### Why an nftables named set

nftables can only delete a **rule** by handle, and handles are assigned at
insertion time. A rule-per-port design therefore cannot state its own rollback
command before it has run — which would make "store the rollback before
applying" impossible to honour.

Set elements delete by *value*:

```
apply     nft add element    inet cybershield blocked_tcp { 21 }
rollback  nft delete element inet cybershield blocked_tcp { 21 }
```

Both are known up front, they are exact inverses, and reverting one port never
disturbs another. Everything lives in a table named `cybershield` that the tool
alone owns, so no pre-existing rule on the target is read or modified.

### Environment constraint: Homebrew Python is unusable here

Homebrew's `python@3.13` and `python@3.14` bottles both link `pyexpat` against
`/usr/lib/libexpat.1.dylib` and require a symbol
(`_XML_SetAllocTrackerActivationThreshold`) that macOS 26.1's system expat does
not export. That breaks `xml.etree.ElementTree`, `defusedxml`, and `pip`
bootstrapping — precisely what is needed to parse Nmap XML. The project uses a
standalone CPython managed by `uv`, which ships its own libexpat.

## Deliberate non-goals

Not implemented, and not to be added:

- Exploitation, payload delivery, penetration testing
- Automatic patching or package installation
- Modification of arbitrary configuration files
- Credential attacks, lateral movement, detection evasion
- A `ufw` backend. The interface exists and is documented, but no ufw backend
  has been written or tested; `get_backend("ufw")` raises, and a test asserts
  it. Registering an untested backend would let the system claim a capability it
  does not have.
