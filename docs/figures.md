# CyberShield — Figures

Six figures for the research paper (spec §24). Each is authored in Mermaid so
it stays version-controlled and editable alongside the code it describes.

**Rendered exports** are committed in [`figures/`](figures/) as both SVG
(vector, preferred for print) and PNG. They were produced with:

```bash
npx -y @mermaid-js/mermaid-cli -i docs/figures.md -o docs/figures/figure.svg
```

Captions are written to stand alone, as a reader encountering the figure out of
context will need them to.

### Placement guidance

Rendered proportions differ, which affects how each fits on a page:

| Figure | Rendered | Shape | Suggested placement |
|---|---|---|---|
| 1 | 1677 x 1284 | balanced | Inline, single column or full width |
| 2 | 1784 x 271 | wide strip | Full page width, landscape |
| 3 | 1784 x 394 | wide | Full page width, landscape |
| 4 | 1784 x 616 | landscape | Full page width |
| 5 | 1784 x 173 | wide strip | Full page width, landscape |
| 6 | 1351 x 2445 | portrait | Full page, portrait |

Figures 2, 3 and 5 are process chains and render as wide strips; they read best
spanning the full text width. Use the SVGs so they stay sharp at any scale.

---

## Figure 1 — Overall CyberShield Architecture

**Caption.** Figure 1: Overall CyberShield architecture. The macOS control
machine performs all assessment and decision logic; firewall enforcement occurs
only on the authorized Linux laboratory target, reached over an SSH management
channel. The macOS host is never a remediation target — no local firewall
execution path exists in the codebase. The scanner and the enforcement point are
deliberately separated so that assessment cannot alter the system it measures.

```mermaid
flowchart TB
    subgraph MAC["macOS control machine (assessment and decision only)"]
        UI["Web dashboard<br/>Jinja2 server-rendered"]
        API["Backend API<br/>FastAPI"]
        SCAN["Scanner<br/>Nmap runner + XML parser"]
        NORM["Normalizer<br/>product string to CPE 2.3"]
        NVD["NVD client<br/>rate-limited + disk cache"]
        RISK["Risk decision engine<br/>ALLOW / REVIEW / DENY"]
        DB[("SQLite<br/>scans, services, signatures,<br/>vulnerabilities, actions, audit")]
        SSHC["SSH client<br/>key-based, Paramiko"]
    end

    subgraph EXT["External read-only source"]
        NVDAPI["NVD REST API 2.0<br/>services.nvd.nist.gov"]
    end

    subgraph LAB["Authorized Linux laboratory target"]
        SVC["Deliberately exposed services<br/>Apache 2.4.49, vsftpd, Redis, MariaDB"]
        SSHD["sshd<br/>management channel, protected port"]
        NFT["nftables<br/>table 'cybershield' only"]
    end

    UI --> API
    API --> SCAN
    API --> RISK
    SCAN -->|"TCP connect scan"| SVC
    SCAN --> NORM
    NORM --> NVD
    NVD <-->|"cpeName query"| NVDAPI
    NVD --> DB
    SCAN --> DB
    RISK --> DB
    RISK -->|"only on ALLOW<br/>+ human confirmation"| SSHC
    SSHC -->|"SSH"| SSHD
    SSHD --> NFT
    NFT -.->|"drops traffic to<br/>isolated port"| SVC
    SCAN -->|"post-action rescan"| SVC

    style MAC fill:#eef4fb,stroke:#1f5f9e
    style LAB fill:#fdecea,stroke:#b91c1c
    style EXT fill:#f5f5f5,stroke:#888
```

---

## Figure 2 — Vulnerability Detection Workflow

**Caption.** Figure 2: Vulnerability detection workflow, from authorization
check to stored evidence. Authorization is evaluated before any packet is sent,
and a refused target produces an audit record without invoking Nmap. Absence of
a detected version yields an `undetermined` classification rather than a clean
result, and a scan truncated by the per-host timeout is recorded as
`completed_with_timeouts` so a partial result cannot be read as an exhaustive
one.

```mermaid
flowchart LR
    START(["Scan request<br/>for target T"]) --> AUTHZ

    subgraph AUTH["Authorization — before any packet"]
        direction TB
        AUTHZ{"AUTHORIZATION.md<br/>signed?"} -->|yes| SCOPE{"T inside an<br/>authorized range?"}
    end

    subgraph EXEC["Execution"]
        direction TB
        PROFILE["Load named profile<br/>raw Nmap flags never accepted"] --> RUN["Run Nmap<br/>argv array, shell=False,<br/>mandatory timeout"]
        RUN --> RAW[("Raw XML written<br/>before parsing")]
    end

    subgraph PARSE["Parsing and classification"]
        direction TB
        PARSED["Parse with defusedxml<br/>banners are untrusted"] --> TIMEOUT{"Any host<br/>timedout=true?"}
        TIMEOUT -->|yes| PARTIAL["completed_with_timeouts<br/>audit outcome = partial"]
        TIMEOUT -->|no| OK["completed"]
        PARTIAL --> CLASSIFY{"Version reported?"}
        OK --> CLASSIFY
        CLASSIFY -->|"product + version"| IDENT["identified<br/>version_confidence = known"]
        CLASSIFY -->|"product only"| PONLY["product_only"]
        CLASSIFY -->|neither| UNDET["undetermined<br/>NOT 'clean'"]
    end

    SCOPE -->|yes| PROFILE
    RAW --> PARSED
    IDENT --> STORE
    PONLY --> STORE
    UNDET --> STORE[("Persist hosts, services<br/>and evidence manifest")]
    STORE --> DONE(["Ready for correlation"])

    AUTHZ -->|no| REFUSE
    SCOPE -->|no| REFUSE["Record scan.refused<br/>Nmap never invoked"]

    style REFUSE fill:#fbe9eb,stroke:#a01b2b
    style UNDET fill:#fdf4dc,stroke:#a16207
    style PARTIAL fill:#fdf4dc,stroke:#a16207
```

---

## Figure 3 — NVD/CVE Correlation Workflow

**Caption.** Figure 3: CVE correlation workflow, showing the primary
CPE-matching path and the labelled keyword fallback. Nmap emits CPE 2.2 URIs
while the NVD API requires 2.3 formatted strings, so conversion is mandatory.
Every returned CVE is re-examined by an applicability check: unless some
`cpeMatch` marked `vulnerable: true` names the queried vendor and product, the
candidate is demoted and flagged as a probable false positive. Measured against
Apache httpd 2.4.49, keyword search returned 0 results where CPE matching
returned 81, of which 12 (14.8%) were flagged by this check.

```mermaid
flowchart LR
    SVC(["Detected service<br/>product + version"]) --> VER

    subgraph NORM["Normalization"]
        direction TB
        VER["Clean version string<br/>strip packaging and<br/>compatibility prefixes"] --> NOTE["MariaDB 5.5.5-10.5.29 to 10.5.29<br/>250 candidates to 3"]
        NOTE --> MAP{"Product in the<br/>curated map?"}
        MAP -->|yes| AMB{"Several real<br/>vendor prefixes?"}
        AMB -->|yes| MULTI["One candidate per vendor<br/>confidence capped MEDIUM"]
        AMB -->|no| SINGLE["Single CPE 2.3 candidate"]
    end

    subgraph QUERY["NVD query"]
        direction TB
        CPEQ["?cpeName=<br/>PRIMARY PATH"] --> HITS{"Any results?"}
        HITS -->|no| KEYWORD["?keywordSearch=<br/>FALLBACK, always LOW"]
    end

    subgraph VALID["Validation and scoring"]
        direction TB
        APPLIC{"cpeMatch with vulnerable:true<br/>naming our vendor:product?"}
        APPLIC -->|yes| CONF["Keep signature confidence"]
        APPLIC -->|no| FLAG["Demote to LOW<br/>flag probable false positive"]
        CONF --> SEV["Resolve CVSS<br/>v3.1 > v4.0 > v3.0 > v2<br/>v2 has no CRITICAL band"]
        FLAG --> SEV
    end

    MULTI --> CPEQ
    SINGLE --> CPEQ
    MAP -->|no| KEYWORD
    HITS -->|yes| APPLIC
    KEYWORD --> SEV
    SEV --> CAND[("Store as CANDIDATE<br/>method, confidence,<br/>evidence, caveats")]
    CAND --> NEVER(["No state means<br/>'confirmed vulnerable'"])

    style KEYWORD fill:#fdf4dc,stroke:#a16207
    style FLAG fill:#fdf4dc,stroke:#a16207
    style NEVER fill:#eef4fb,stroke:#1f5f9e
```

---

## Figure 4 — Risk-Aware Remediation Decision Flow

**Caption.** Figure 4: Risk-aware remediation decision engine. Nine rules are
evaluated in order and the verdict begins at DENY, so any unexpected error
yields a refusal rather than an approval. Capability and authorization checks
precede policy checks; severity is evaluated last and never overrides an earlier
refusal, so a CRITICAL CVSS score on a protected port is still DENIED. The
function signature accepts no override parameter, and a unit test asserts on
that signature so the guarantee cannot be quietly removed.

```mermaid
flowchart LR
    REQ(["Isolation request"]) --> INIT["verdict = DENY<br/>fail closed"]

    subgraph GATE1["Capability and authorization"]
        direction TB
        R0{"1. Input valid?"} -->|yes| R1{"2. TCP?"}
        R1 -->|yes| R2{"3. Authorized lab target<br/>with ssh_user?"}
    end

    subgraph GATE2["Hard safety refusals"]
        direction TB
        R3{"4. Protected port?"} -->|no| R4{"5. Live SSH<br/>management channel?"}
    end

    subgraph GATE3["Policy and risk gates"]
        direction TB
        R5{"6. Service policy?"} -->|eligible| R6{"7. Confidence<br/>>= MEDIUM?"}
        R6 -->|yes| R7{"8. Severity >=<br/>threshold?"}
        R7 -->|yes| R8{"9. Reachable for<br/>apply and rollback?"}
    end

    INIT --> R0
    R2 -->|yes| R3
    R4 -->|no| R5
    R8 -->|yes| ALLOW["ALLOW"]
    ALLOW --> CONFIRM{"Human<br/>confirmation?"}
    CONFIRM -->|yes| ACT(["Figure 5"])

    R0 -->|no| DENY["DENY"]
    R1 -->|no| DENY
    R2 -->|no| DENY
    R3 -->|yes| DENY
    R4 -->|yes| DENY
    R5 -->|approved/protected| DENY
    R8 -->|no| DENY
    CONFIRM -->|no| DENY
    R5 -->|review_required| REVIEW["REVIEW_REQUIRED"]
    R6 -->|no| REVIEW
    R7 -->|no| REVIEW

    style DENY fill:#fbe9eb,stroke:#a01b2b
    style REVIEW fill:#fdf4dc,stroke:#a16207
    style ALLOW fill:#e3f0e8,stroke:#15803d
```

---

## Figure 5 — Controlled Isolation and Verification Workflow

**Caption.** Figure 5: Controlled isolation and verification workflow. The
rollback command is computed and persisted before the forward command is sent,
so an interruption between application and recording still leaves a documented
way back. Verification is a real Nmap rescan rather than an inference from the
command's exit status, and the management channel is rescanned separately
because an isolation that locks the operator out is a failure. An applied rule
auto-reverts when its TTL expires.

```mermaid
flowchart LR
    ALLOW(["Verdict ALLOW<br/>+ confirmation"]) --> PLAN

    subgraph PREPARE["Plan and record — before acting"]
        direction TB
        PLAN["Build plan:<br/>apply = nft add element<br/>rollback = nft delete element"] --> PERSIST[("Persist action record<br/>INCLUDING rollback command")]
        PERSIST --> BEFORE["Rescan port:<br/>BEFORE state"]
    end

    subgraph APPLYP["Apply"]
        direction TB
        PREP["SSH to target<br/>ensure cybershield table exists"] --> APPLY["Add port to blocked_tcp set"]
        APPLY --> OKQ{"Succeeded?"}
        OKQ -->|yes| READ["Read firewall state<br/>back from the target"]
    end

    subgraph VERIFY["Verification — real rescans"]
        direction TB
        AFTER["Rescan port:<br/>AFTER state"] --> MGMT["Rescan SSH port:<br/>anti-lockout check"]
        MGMT --> CMP{"Reachable BEFORE<br/>and not AFTER?"}
        CMP -->|yes| REDUCED["exposure_reduced = true"]
        CMP -->|"already closed"| INCONC["Inconclusive"]
        CMP -->|"still reachable"| NOEFFECT["No effect"]
    end

    subgraph BACK["Rollback"]
        direction TB
        TTL["Arm TTL watchdog"] --> RB{"Operator or<br/>TTL expiry"}
        RB --> REVERT["Send stored<br/>rollback command"]
        REVERT --> VER2["Rescan: reachable again?"]
    end

    BEFORE --> PREP
    READ --> AFTER
    OKQ -->|no| FAIL["state = failed<br/>audit failure"]
    REDUCED --> CLAIM["NOT claimed: patched, fixed,<br/>service stopped, or unreachable<br/>from other vantage points"]
    CLAIM --> TTL
    VER2 --> DONE(["rollback_verified recorded<br/>every step in the audit chain"])

    style REDUCED fill:#e3f0e8,stroke:#15803d
    style CLAIM fill:#eef4fb,stroke:#1f5f9e
    style FAIL fill:#fbe9eb,stroke:#a01b2b
    style NOEFFECT fill:#fdf4dc,stroke:#a16207
    style INCONC fill:#fdf4dc,stroke:#a16207
```

---

## Figure 6 — Database and Data Flow Architecture

**Caption.** Figure 6: Database schema and data flow. Each stage writes its own
table, so a finding can be traced back through normalization to the raw Nmap
banner that produced it. `scan_sessions` records every scan including
verification rescans, which is why analysis queries must filter by `scan_kind` —
counting all sessions inflates host, service and candidate totals. The audit log
is written to an append-only hash-chained file, and mirrored into `audit_logs`
only so the dashboard can paginate without re-verifying the chain.

```mermaid
erDiagram
    scan_sessions ||--o{ discovered_hosts : "produces"
    discovered_hosts ||--o{ discovered_services : "exposes"
    discovered_services ||--o{ software_signatures : "normalizes to"
    discovered_services ||--o{ vulnerabilities : "correlates to"
    cve_records ||--o{ vulnerabilities : "referenced by"
    software_signatures ||--o{ vulnerabilities : "matched via"
    vulnerabilities ||--o{ remediation_actions : "may justify"

    scan_sessions {
        string session_id PK
        string target_spec
        string scan_kind "assessment | verification_*"
        string status "completed | completed_with_timeouts"
        json nmap_argv "exact command"
        string config_hash "policy in force"
        string raw_xml_path "primary evidence"
        float duration_seconds
    }
    discovered_hosts {
        string address
        string state
    }
    discovered_services {
        int port
        string state "open | filtered | closed"
        string product "raw Nmap output"
        string version "raw, may carry quirks"
        string version_confidence "known | unknown"
        string identification_status "never 'clean'"
        int nmap_confidence "1-10"
    }
    software_signatures {
        string vendor
        string product
        string version "normalized"
        string cpe23 "null if unresolvable"
        string mapping_source "nmap_cpe | curated_map"
        string confidence "HIGH | MEDIUM | LOW"
    }
    cve_records {
        string cve_id PK
        float base_score
        string base_severity
        string cvss_version "always stored with score"
        json all_metrics "every version NVD gave"
    }
    vulnerabilities {
        string matching_method "cpe_exact | keyword"
        string confidence "HIGH | MEDIUM | LOW"
        string status "candidate (only)"
        json evidence "applicability check result"
        json caveats "shown with every finding"
    }
    remediation_actions {
        string request_id PK
        json apply_argv
        json rollback_argv "stored BEFORE apply"
        string state "planned to applied to rolled_back"
        json decision "all nine rules"
        json before_state
        json after_state
        bool exposure_reduced
        bool management_channel_intact
        bool rollback_verified
        datetime expires_at "TTL"
    }
    audit_logs {
        int sequence
        string action
        string outcome "success|failure|refused|partial"
        string prev_hash "SHA-256 chain"
        string entry_hash
    }
```

---

## Figure index

| Figure | Title | Primary use in the paper |
|---|---|---|
| 1 | Overall CyberShield Architecture | System design chapter |
| 2 | Vulnerability Detection Workflow | Objective 1 methodology |
| 3 | NVD/CVE Correlation Workflow | Objective 1 methodology; correlation limitations |
| 4 | Risk-Aware Remediation Decision Flow | Safety design; Objective 2 methodology |
| 5 | Controlled Isolation and Verification Workflow | Objective 2 methodology and results |
| 6 | Database and Data Flow Architecture | Implementation chapter; reproducibility |
