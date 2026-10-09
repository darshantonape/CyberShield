"""CVE correlation (spec §9, §11).

The pipeline, kept explicit so each step's uncertainty stays visible:

    Nmap detection -> normalization -> CPE candidate -> NVD lookup
      -> applicability check -> severity resolution -> finding + confidence

Nothing here concludes that a service is vulnerable. A `CveCandidate` states
that a detected version string resembles software named in a CVE's
applicability data. Confirming it requires a human.

**The applicability check matters.** An NVD `?cpeName=` query returns every CVE
whose configuration tree matches, and those trees are frequently over-broad.
Measured during planning: `apache:http_server:2.4.49` returns 81 CVEs including
entries from 2007-2013 that predate that release, and CVE-2007-4723's first
configuration node references `ragnarok_online_control_panel` — an unrelated
product. So every returned CVE is re-examined here: unless some `cpeMatch` with
`vulnerable: true` actually names our vendor:product, the candidate is flagged
and downgraded rather than reported at face value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.normalization.normalizer import (
    NormalizationResult,
    SignatureCandidate,
    normalize_service,
)
from backend.nvd.client import NvdClient, NvdError
from backend.nvd.severity import ResolvedSeverity, resolve_severity
from backend.scanner.nmap_parser import ParsedService

__all__ = ["CveCandidate", "CorrelationResult", "correlate_service", "NVD_CVE_URL"]

NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/"

_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _cap(confidence: str, ceiling: str) -> str:
    return confidence if _RANK[confidence] <= _RANK[ceiling] else ceiling


@dataclass
class CveCandidate:
    cve_id: str
    description: str | None = None
    published: str | None = None
    last_modified: str | None = None
    severity: ResolvedSeverity = field(default_factory=ResolvedSeverity)
    cwe_ids: list[str] = field(default_factory=list)

    # cpe_exact | keyword
    matching_method: str = "cpe_exact"
    # HIGH | MEDIUM | LOW
    confidence: str = "LOW"

    matched_cpe: str | None = None
    detected_product: str | None = None
    detected_version: str | None = None

    evidence: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def nvd_reference(self) -> str:
        return f"{NVD_CVE_URL}{self.cve_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published": self.published,
            "matching_method": self.matching_method,
            "confidence": self.confidence,
            "matched_cpe": self.matched_cpe,
            "detected_product": self.detected_product,
            "detected_version": self.detected_version,
            "nvd_reference": self.nvd_reference,
            "evidence": self.evidence,
            "caveats": list(self.caveats),
            **self.severity.to_dict(),
        }


@dataclass
class CorrelationResult:
    service_port: int
    normalization: NormalizationResult
    candidates: list[CveCandidate] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    queries_made: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        """Highest severity among candidates, or None if nothing is scored.

        Feeds the risk decision engine. None means "no usable score", which the
        engine treats as REVIEW_REQUIRED, never as safe.
        """
        order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        scored = [
            c.severity.base_severity
            for c in self.candidates
            if c.severity.base_severity in order
        ]
        return max(scored, key=lambda s: order[s]) if scored else None

    @property
    def max_confidence(self) -> str | None:
        if not self.candidates:
            return None
        return max((c.confidence for c in self.candidates), key=lambda c: _RANK[c])

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.service_port,
            "normalization": self.normalization.to_dict(),
            "candidate_count": len(self.candidates),
            "max_severity": self.max_severity,
            "max_confidence": self.max_confidence,
            "queries_made": self.queries_made,
            "caveats": list(self.caveats),
            "errors": list(self.errors),
            "candidates": [c.to_dict() for c in self.candidates],
        }


def _iter_cpe_matches(cve: dict[str, Any]):
    """Yield every cpeMatch in a CVE's applicability configurations."""
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                yield match


def check_applicability(
    cve: dict[str, Any], signature: SignatureCandidate
) -> tuple[bool, dict[str, Any]]:
    """Does this CVE actually name our vendor:product as vulnerable?

    Returns (applies, evidence). `applies` is False when NVD returned the CVE
    for our CPE query but no vulnerable `cpeMatch` names our vendor and product
    — a strong indicator of an over-broad configuration or a mis-attribution.
    """
    target = f"{signature.vendor}:{signature.product}".lower()
    matching: list[dict[str, Any]] = []
    other_products: set[str] = set()

    for match in _iter_cpe_matches(cve):
        criteria = str(match.get("criteria") or "")
        fields = criteria.split(":")
        if len(fields) < 5:
            continue
        pair = f"{fields[3]}:{fields[4]}".lower()

        if pair == target:
            if match.get("vulnerable") is True:
                matching.append(
                    {
                        "criteria": criteria,
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                )
        else:
            other_products.add(pair)

    evidence: dict[str, Any] = {
        "target_vendor_product": target,
        "vulnerable_matches": matching[:5],
        "vulnerable_match_count": len(matching),
    }
    if other_products:
        evidence["other_products_in_configuration"] = sorted(other_products)[:10]

    # A CVE with no configuration data at all cannot be checked either way.
    if not any(True for _ in _iter_cpe_matches(cve)):
        evidence["no_configuration_data"] = True
        return False, evidence

    return bool(matching), evidence


def _build_candidate(
    cve: dict[str, Any],
    signature: SignatureCandidate,
    service: ParsedService,
    *,
    method: str,
) -> CveCandidate:
    cve_id = str(cve.get("id") or "").strip()

    description = None
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value")
            break

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value")
            if value and value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)

    severity = resolve_severity(cve)
    caveats: list[str] = []

    # Start from the signature's own confidence, then adjust downward only.
    confidence = signature.confidence
    if method == "keyword":
        confidence = "LOW"
        caveats.append(
            "Matched by NVD keyword search, not by CPE. Keyword search is known "
            "to under-report severely (Apache httpd 2.4.49 returns 0 results by "
            "keyword and 81 by CPE), and a text match does not establish that "
            "this CVE applies to the detected software."
        )
        applies, evidence = True, {"method": "keyword", "query_product": service.product}
    else:
        applies, evidence = check_applicability(cve, signature)
        if not applies:
            confidence = "LOW"
            if evidence.get("no_configuration_data"):
                caveats.append(
                    "This CVE carries no CPE applicability configuration, so it "
                    "could not be confirmed as applying to the detected software."
                )
            else:
                others = evidence.get("other_products_in_configuration") or []
                caveats.append(
                    "NVD returned this CVE for the queried CPE, but no vulnerable "
                    f"cpeMatch names {signature.vendor}:{signature.product}"
                    + (f" (configuration references {', '.join(others[:3])})" if others else "")
                    + ". Likely an over-broad configuration or mis-attribution; "
                    "treat as a probable false positive pending review."
                )

    if not severity.has_score:
        caveats.append(
            "NVD supplied no usable CVSS score for this CVE. Severity is null; "
            "no score has been estimated."
        )
    elif severity.severity_derived:
        caveats.append(
            f"NVD provided a CVSS v{severity.version} score with no baseSeverity "
            "field; the band was derived from the numeric score."
        )
    if severity.version and severity.version.startswith("2"):
        caveats.append(
            "Only a CVSS v2 score is available. v2 scores are not directly "
            "comparable with v3.x and v2 has no CRITICAL band."
        )

    if not signature.has_version:
        confidence = _cap(confidence, "LOW")
        caveats.append(
            "The CPE used for this lookup has no version component, so results "
            "cover all versions of the product, not the deployed one."
        )

    # Universal caveat: this is the core honesty requirement of spec §9.
    caveats.append(
        "Candidate only: a version string resembling this CVE's affected "
        "software is not proof that the service is vulnerable or exploitable. "
        "No exploitation was attempted."
    )

    return CveCandidate(
        cve_id=cve_id,
        description=description,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        severity=severity,
        cwe_ids=cwe_ids,
        matching_method=method,
        confidence=confidence,
        matched_cpe=signature.cpe23,
        detected_product=service.product,
        detected_version=signature.version,
        evidence=evidence,
        caveats=caveats,
        raw=cve,
    )


def correlate_service(
    client: NvdClient,
    service: ParsedService,
    *,
    max_candidates_per_signature: int = 200,
) -> CorrelationResult:
    """Correlate one detected service against NVD."""
    normalization = normalize_service(service)
    result = CorrelationResult(service_port=service.port, normalization=normalization)
    result.caveats.extend(normalization.caveats)

    if not normalization.candidates:
        result.caveats.append(
            "No CPE candidate could be built, so no CVE correlation was "
            "attempted. This service is UNDETERMINED, not clean."
        )
        return result

    seen: dict[str, CveCandidate] = {}

    # --- primary path: exact CPE ----------------------------------------
    # Only signatures carrying a CONCRETE version are queried. NVD's cveHistory
    # endpoint answers a `cpeName` whose version component is `*` with HTTP 404
    # — measured on 2026-09-20 against both an unknown product
    # (encode:uvicorn) and a well-known one (apache:http_server), while the
    # same product WITH a version returns 200 and 81 results. A wildcard CPE is
    # therefore a guaranteed-failing round trip, and recording its 404 as an
    # error made `correlation.finish` audit as outcome="failure" for a run that
    # completed perfectly normally.
    #
    # This changes nothing about what is reported: a version-less service still
    # gets no CPE candidates, still falls through to the keyword path below at
    # LOW confidence, and is still UNDETERMINED rather than clean — which is
    # exactly the behaviour README "Measured NVD behaviour" item 5 describes.
    cpe_signatures = [s for s in normalization.candidates if s.cpe23 and s.has_version]
    skipped = [s for s in normalization.candidates if s.cpe23 and not s.has_version]
    for signature in skipped:
        result.caveats.append(
            f"No version was detected for {signature.vendor}:{signature.product}, "
            "so no CPE lookup was attempted — NVD rejects a cpeName with a "
            "wildcard version. This service is UNDETERMINED, not clean."
        )
    for signature in cpe_signatures:
        try:
            response = client.search_by_cpe(signature.cpe23)  # type: ignore[arg-type]
            result.queries_made += 1
        except NvdError as exc:
            result.errors.append(f"CPE lookup failed for {signature.cpe23}: {exc}")
            continue

        if response.total_results > len(response.cves):
            result.caveats.append(
                f"NVD reported {response.total_results} results for "
                f"{signature.cpe23} but returned {len(response.cves)}; the "
                "result set was truncated by the page size."
            )

        for cve in response.cves[:max_candidates_per_signature]:
            candidate = _build_candidate(cve, signature, service, method="cpe_exact")
            if not candidate.cve_id:
                continue
            existing = seen.get(candidate.cve_id)
            # Keep the strongest evidence when several signatures match one CVE.
            if existing is None or _RANK[candidate.confidence] > _RANK[existing.confidence]:
                seen[candidate.cve_id] = candidate

    # --- fallback path: keyword, only if CPE produced nothing ------------
    if not seen and service.product:
        keyword = service.product
        if normalization.candidates and normalization.candidates[0].version:
            keyword = f"{service.product} {normalization.candidates[0].version}"

        try:
            response = client.search_by_keyword(keyword)
            result.queries_made += 1
            result.caveats.append(
                f"No CVE matched by CPE, so a keyword search for {keyword!r} was "
                "used as a fallback. Results are LOW confidence by construction."
            )
            fallback_signature = normalization.candidates[0]
            for cve in response.cves:
                candidate = _build_candidate(
                    cve, fallback_signature, service, method="keyword"
                )
                if candidate.cve_id and candidate.cve_id not in seen:
                    seen[candidate.cve_id] = candidate
        except NvdError as exc:
            result.errors.append(f"Keyword fallback failed for {keyword!r}: {exc}")

    order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    result.candidates = sorted(
        seen.values(),
        key=lambda c: (
            -_RANK[c.confidence],
            -(order.get(c.severity.base_severity or "", -1)),
            -(c.severity.base_score or 0.0),
            c.cve_id,
        ),
    )

    if not result.candidates and not result.errors:
        result.caveats.append(
            "NVD returned no CVE candidates for the constructed CPEs. This means "
            "no match was found in NVD, which is not the same as the service "
            "being free of vulnerabilities."
        )

    return result
