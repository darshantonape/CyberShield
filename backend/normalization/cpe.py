"""CPE 2.2 and 2.3 handling.

Nmap emits CPE in **2.2 URI form** (`cpe:/a:apache:http_server:2.4.49`), while
the NVD REST API requires **2.3 formatted-string form**
(`cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`). Passing Nmap's output
straight to NVD returns nothing, so conversion happens here.

A 2.3 formatted string has 13 colon-separated components:

    cpe:2.3:part:vendor:product:version:update:edition:language:
            sw_edition:target_sw:target_hw:other

Unspecified components are `*` (ANY). This module never substitutes a real
value for `*` — an unknown version stays unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

__all__ = [
    "CpeParts",
    "CpeError",
    "parse_cpe",
    "parse_cpe22",
    "parse_cpe23",
    "build_cpe23",
    "cpe22_to_cpe23",
    "is_valid_cpe23",
    "ANY",
]

ANY = "*"

VALID_PARTS = frozenset({"a", "o", "h"})

# In 2.3 formatted strings these must be backslash-escaped inside a component.
_SPECIAL = r"!\"#$%&'()+,/:;<=>@[]^`{|}~"

_CPE23_RE = re.compile(r"^cpe:2\.3:[aoh](:(?:[^:]|\\:)*){10}$")


class CpeError(ValueError):
    """Raised when a CPE string is malformed."""


def _escape(value: str) -> str:
    """Escape special characters for a 2.3 component."""
    out: list[str] = []
    for char in value:
        if char in _SPECIAL:
            out.append("\\" + char)
        elif char == " ":
            # Spaces are not permitted; CPE uses underscore.
            out.append("_")
        else:
            out.append(char)
    return "".join(out)


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _split_escaped(value: str, sep: str = ":") -> list[str]:
    """Split on `sep`, honouring backslash escapes."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == sep:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


@dataclass(frozen=True)
class CpeParts:
    """The components of a CPE, stored unescaped."""

    part: str = "a"
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    def __post_init__(self) -> None:
        if self.part not in VALID_PARTS:
            raise CpeError(
                f"CPE part must be one of {sorted(VALID_PARTS)} "
                f"(a=application, o=os, h=hardware), got {self.part!r}."
            )

    @property
    def has_version(self) -> bool:
        """True only when a concrete version is present.

        `*` and `-` (NA) are not versions, and must never be treated as one.
        """
        return self.version not in (ANY, "-", "")

    @property
    def vendor_product(self) -> str:
        return f"{self.vendor}:{self.product}"

    def with_version(self, version: str | None) -> "CpeParts":
        return replace(self, version=version if version else ANY)

    def to_cpe23(self) -> str:
        return build_cpe23(self)

    def to_dict(self) -> dict[str, str]:
        return {
            "part": self.part,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
        }


def build_cpe23(parts: CpeParts) -> str:
    """Render a 2.3 formatted string."""
    fields = [
        parts.part,
        parts.vendor,
        parts.product,
        parts.version,
        parts.update,
        parts.edition,
        parts.language,
        parts.sw_edition,
        parts.target_sw,
        parts.target_hw,
        parts.other,
    ]
    rendered = [f if f in (ANY, "-") else _escape(f) for f in fields]
    return "cpe:2.3:" + ":".join(rendered)


def parse_cpe23(value: str) -> CpeParts:
    """Parse a 2.3 formatted string.

    Raises:
        CpeError: if the string is not a well-formed 2.3 CPE.
    """
    if not isinstance(value, str) or not value.strip():
        raise CpeError("CPE string is empty.")

    text = value.strip()
    if not text.startswith("cpe:2.3:"):
        raise CpeError(f"{text!r} is not a CPE 2.3 formatted string.")

    body = text[len("cpe:2.3:") :]
    fields = _split_escaped(body)
    if len(fields) != 11:
        raise CpeError(
            f"CPE 2.3 requires 11 components after the prefix, found {len(fields)} "
            f"in {text!r}."
        )

    unescaped = [f if f in (ANY, "-") else _unescape(f) for f in fields]
    return CpeParts(*unescaped)


def parse_cpe22(value: str) -> CpeParts:
    """Parse a 2.2 URI, the form Nmap emits.

    2.2 defines seven components:
        cpe:/part:vendor:product:version:update:edition:language

    Trailing components may be omitted; those become ANY.
    """
    if not isinstance(value, str) or not value.strip():
        raise CpeError("CPE string is empty.")

    text = value.strip()
    if not text.startswith("cpe:/"):
        raise CpeError(f"{text!r} is not a CPE 2.2 URI.")

    body = text[len("cpe:/") :]
    fields = _split_escaped(body)
    if not fields or not fields[0]:
        raise CpeError(f"{text!r} has no part component.")
    if len(fields) > 7:
        raise CpeError(
            f"CPE 2.2 allows at most 7 components, found {len(fields)} in {text!r}."
        )

    # Pad the omitted trailing components with ANY.
    padded = fields + [ANY] * (7 - len(fields))
    part, vendor, product, version, update, edition, language = [
        (f.strip() or ANY) for f in padded
    ]

    # 2.2 percent-encodes; decode the couple of sequences that actually occur.
    def decode(field: str) -> str:
        return field.replace("%3a", ":").replace("%3A", ":").replace("~", "")

    return CpeParts(
        part=part,
        vendor=decode(vendor),
        product=decode(product),
        version=decode(version),
        update=decode(update),
        edition=decode(edition),
        language=decode(language),
    )


def parse_cpe(value: str) -> CpeParts:
    """Parse either CPE form, dispatching on the prefix."""
    text = (value or "").strip()
    if text.startswith("cpe:2.3:"):
        return parse_cpe23(text)
    if text.startswith("cpe:/"):
        return parse_cpe22(text)
    raise CpeError(f"{text!r} is neither a CPE 2.2 URI nor a 2.3 formatted string.")


def cpe22_to_cpe23(value: str) -> str:
    """Convert an Nmap CPE 2.2 URI to a 2.3 formatted string."""
    return parse_cpe22(value).to_cpe23()


def is_valid_cpe23(value: str) -> bool:
    try:
        parse_cpe23(value)
        return True
    except CpeError:
        return False
