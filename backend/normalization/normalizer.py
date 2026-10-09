"""Software normalization (spec §8).

Turns one detected service into zero or more `SignatureCandidate`s:

    Nmap: product="Apache httpd" version="2.4.49 ((Ubuntu))"
      ->  vendor="apache" product="http_server" version="2.4.49"
          cpe23="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

Rules held throughout:

  * **Never invent.** No product, no signature. No version, the CPE keeps `*`
    in the version component and confidence drops — the gap is never filled in.
  * **Ambiguity is preserved.** A product with several real vendor prefixes
    produces one candidate per vendor. Correlation reports which one matched
    rather than the normalizer silently picking a favourite.
  * **Every candidate carries its provenance** (`mapping_source`) and a note
    explaining how it was derived, so it can be audited against the raw XML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.normalization.cpe import ANY, CpeError, CpeParts, parse_cpe
from backend.normalization.product_map import ProductMapping, lookup_product
from backend.normalization.version import normalize_version
from backend.scanner.nmap_parser import ParsedService

__all__ = ["SignatureCandidate", "NormalizationResult", "normalize_service"]

# Below this, Nmap's own service match is weak enough to cap confidence.
_LOW_NMAP_CONFIDENCE = 7


@dataclass(frozen=True)
class SignatureCandidate:
    vendor: str
    product: str
    version: str | None
    part: str = "a"
    cpe23: str | None = None
    # nmap_cpe | curated_map | unmapped
    mapping_source: str = "curated_map"
    # HIGH | MEDIUM | LOW  (spec §11)
    confidence: str = "LOW"
    notes: str = ""

    @property
    def has_version(self) -> bool:
        return self.version is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "cpe23": self.cpe23,
            "mapping_source": self.mapping_source,
            "confidence": self.confidence,
            "notes": self.notes,
        }


@dataclass
class NormalizationResult:
    """Everything derived from one service, including why."""

    candidates: list[SignatureCandidate] = field(default_factory=list)
    version_confidence: str = "unknown"
    identification_status: str = "undetermined"
    caveats: list[str] = field(default_factory=list)

    @property
    def best_confidence(self) -> str | None:
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        if not self.candidates:
            return None
        return max((c.confidence for c in self.candidates), key=lambda c: order[c])

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [c.to_dict() for c in self.candidates],
            "version_confidence": self.version_confidence,
            "identification_status": self.identification_status,
            "caveats": list(self.caveats),
        }


def _rank(confidence: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[confidence]


def _cap(confidence: str, ceiling: str) -> str:
    return confidence if _rank(confidence) <= _rank(ceiling) else ceiling


def _confidence_for(
    service: ParsedService,
    *,
    has_version: bool,
    source: str,
    mapping: ProductMapping | None,
) -> tuple[str, list[str]]:
    """Grade one candidate and explain any downgrade (spec §11)."""
    caveats: list[str] = []

    # method="table" means Nmap guessed from the port number and never saw a
    # banner. That is not evidence about what is running.
    if service.method == "table":
        return "LOW", [
            "Nmap inferred this service from the port number alone "
            "(method=table); no banner evidence was obtained."
        ]

    if not has_version:
        return "LOW", [
            "No version was detected, so the CPE version component is ANY. "
            "Correlation on a version-less CPE over-reports heavily."
        ]

    if source == "nmap_cpe":
        confidence = "HIGH"
    elif mapping is not None and mapping.alternates:
        confidence = "MEDIUM"
        caveats.append(
            f"{mapping.vendor}:{mapping.product} is one of "
            f"{len(mapping.candidates())} real vendor prefixes for this product; "
            "each is correlated separately."
        )
    elif mapping is not None:
        confidence = "HIGH"
    else:
        confidence = "LOW"
        caveats.append("Product is not in the curated map; vendor is unverified.")

    if service.confidence is not None and service.confidence < _LOW_NMAP_CONFIDENCE:
        capped = _cap(confidence, "MEDIUM")
        if capped != confidence:
            caveats.append(
                f"Nmap reported only {service.confidence}/10 confidence in this "
                "service match; capped to MEDIUM."
            )
        confidence = capped

    return confidence, caveats


def _from_nmap_cpes(
    service: ParsedService, version: str | None
) -> tuple[list[SignatureCandidate], list[str]]:
    """Candidates built from CPEs Nmap emitted itself."""
    candidates: list[SignatureCandidate] = []
    caveats: list[str] = []

    for raw_cpe in service.cpes:
        try:
            parts: CpeParts = parse_cpe(raw_cpe)
        except CpeError as exc:
            caveats.append(f"Nmap emitted an unparseable CPE {raw_cpe!r}: {exc}")
            continue

        # Only application CPEs are useful here; Nmap also emits OS CPEs.
        if parts.part != "a":
            continue

        if parts.has_version:
            # Nmap's CPE inherits whatever the banner advertised, quirks and
            # all, so it needs the same normalization as the raw version
            # string. Measured against the laboratory's MariaDB on 2026-08-30:
            # Nmap emitted cpe:/a:mariadb:mariadb:5.5.5-10.5.29, which returned
            # 202 CVE candidates, against 3 for the normalized 10.5.29 — a ~67x
            # over-report from trusting Nmap's CPE verbatim.
            cleaned = normalize_version(parts.version)
            if cleaned.version and cleaned.version != parts.version:
                caveats.append(
                    f"Nmap's CPE carried version {parts.version!r}; normalized to "
                    f"{cleaned.version!r} before lookup. {cleaned.note or ''}".strip()
                )
                parts = parts.with_version(cleaned.version)
        elif version:
            # Nmap often omits the version from its CPE even when the banner
            # had one.
            parts = parts.with_version(version)

        effective_version = parts.version if parts.has_version else None
        confidence, extra = _confidence_for(
            service, has_version=effective_version is not None, source="nmap_cpe", mapping=None
        )
        caveats.extend(extra)

        candidates.append(
            SignatureCandidate(
                vendor=parts.vendor,
                product=parts.product,
                version=effective_version,
                part=parts.part,
                cpe23=parts.to_cpe23(),
                mapping_source="nmap_cpe",
                confidence=confidence,
                notes=f"Derived from Nmap CPE {raw_cpe!r}.",
            )
        )

    return candidates, caveats


def _from_curated_map(
    service: ParsedService, version: str | None
) -> tuple[list[SignatureCandidate], list[str]]:
    """Candidates built from the curated product map."""
    mapping = lookup_product(service.product)
    if mapping is None:
        return [], [
            f"Nmap product {service.product!r} is not in the curated map, so no "
            "verified CPE could be constructed. Correlation will fall back to a "
            "keyword search, which is known to under-report."
        ]

    confidence, caveats = _confidence_for(
        service, has_version=version is not None, source="curated_map", mapping=mapping
    )

    candidates: list[SignatureCandidate] = []
    for vendor, product in mapping.candidates():
        parts = CpeParts(
            part=mapping.part, vendor=vendor, product=product, version=version or ANY
        )
        is_primary = (vendor, product) == (mapping.vendor, mapping.product)
        candidates.append(
            SignatureCandidate(
                vendor=vendor,
                product=product,
                version=version,
                part=mapping.part,
                cpe23=parts.to_cpe23(),
                mapping_source="curated_map",
                # An alternate vendor is by definition the less likely one.
                confidence=confidence if is_primary else _cap(confidence, "MEDIUM"),
                notes=(mapping.note if is_primary else f"Alternate vendor prefix. {mapping.note}"),
            )
        )

    return candidates, caveats


def normalize_service(service: ParsedService) -> NormalizationResult:
    """Normalize one detected service into CPE candidates."""
    result = NormalizationResult()

    normalized = normalize_version(service.version)
    result.version_confidence = normalized.confidence
    result.identification_status = service.identification_status

    if normalized.changed and normalized.note:
        result.caveats.append(normalized.note)

    # A service with no product string yields nothing to correlate. That is
    # "undetermined", explicitly not "no vulnerabilities".
    if not service.product and not service.cpes:
        result.caveats.append(
            "Nmap identified no product for this service. It is undetermined, "
            "which is not the same as having no vulnerabilities."
        )
        return result

    nmap_candidates, nmap_caveats = _from_nmap_cpes(service, normalized.version)
    result.caveats.extend(nmap_caveats)

    curated_candidates, curated_caveats = _from_curated_map(service, normalized.version)
    result.caveats.extend(curated_caveats)

    # Deduplicate on the CPE string, keeping the highest-confidence origin.
    merged: dict[str, SignatureCandidate] = {}
    for candidate in [*nmap_candidates, *curated_candidates]:
        key = candidate.cpe23 or f"{candidate.vendor}:{candidate.product}"
        existing = merged.get(key)
        if existing is None or _rank(candidate.confidence) > _rank(existing.confidence):
            merged[key] = candidate

    result.candidates = sorted(
        merged.values(), key=lambda c: (-_rank(c.confidence), c.vendor, c.product)
    )

    if not result.candidates:
        result.caveats.append(
            "No CPE candidate could be constructed for this service."
        )

    return result
