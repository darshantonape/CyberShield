# CyberShield Documentation

| Document | Contents |
|---|---|
| [figures.md](figures.md) | **Figures 1–6** with captions, for the paper |
| [architecture.md](architecture.md) | Components, technology choices and rationale, what runs where |
| [data-flow.md](data-flow.md) | Assessment and remediation pipelines; what each stage may and may not conclude |
| [safety-controls.md](safety-controls.md) | All 32 controls, how each is enforced, and the test holding it |
| [authentication.md](authentication.md) | Operator accounts, sessions, the request gate, and what is deliberately absent |
| [lan-assessment.md](lan-assessment.md) | Assessing an authorized device on a real Wi-Fi network, and why `-Pn` matters |
| [threats-to-validity.md](threats-to-validity.md) | Consolidated measured limitations |
| [lab-setup.md](lab-setup.md) | Laboratory topology and the reachability problem |
| [../experiments/README.md](../experiments/README.md) | **Experimental results and metrics** |
| [../lab/README.md](../lab/README.md) | Target definitions and build notes |

## Suggested mapping to a dissertation

| Chapter | Sources |
|---|---|
| Introduction, objectives | Root `README.md` — objectives and boundaries |
| Literature / background | `threats-to-validity.md` §2 — measured NVD behaviour |
| System design | `architecture.md`, Figures 1 and 6 |
| Methodology — Objective 1 | `data-flow.md`, Figures 2 and 3 |
| Methodology — Objective 2 | `safety-controls.md`, Figures 4 and 5 |
| Methodology — real-network assessment | `lan-assessment.md` |
| Implementation — access control | `authentication.md` |
| Implementation | `architecture.md`, `lab-setup.md`, `../lab/README.md` |
| Results | `../experiments/README.md`, dashboard screenshots |
| Discussion, limitations | `threats-to-validity.md` |
| Conclusion, future work | `threats-to-validity.md` §6 |

## Three things to state clearly in the write-up

**The scope of the remediation claim.** CyberShield performs *network-level
exposure reduction*. Isolating a port changes reachability from the scanner's
vantage point. It does not patch, fix or remove a vulnerability, and the service
continues running throughout. Every report the system produces words it this
way; the paper should too.

**The status of a finding.** A CVE match is a *candidate*: a detected version
string resembles software named in a CVE's applicability data. No exploitation
is attempted, so exploitability is never established. The database has no state
meaning "confirmed vulnerable", by design.

**The difference between "found nothing" and "learned nothing".** A target that
answers no probe is recorded `completed_unreachable`, and a scan whose output
could not be read is recorded `failed` with zero findings attached. Neither is a
clean result, and neither may be reported as one. On a real network — where host
firewalls and Wi-Fi client isolation are ordinary — this distinction carries
most of the difference between an honest result table and a misleading one. See
`lan-assessment.md`.
