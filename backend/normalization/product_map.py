"""Curated Nmap product string -> CPE vendor:product map.

Nmap's `product` field is a human-readable name ("Apache httpd", "Redis
key-value store"); NVD needs a CPE vendor and product. There is no algorithm
that derives one from the other, so this map is curated.

**Every entry below was verified against the live NVD API**, not assumed. The
verification method and date are recorded in `VERIFICATION_NOTE`, and each
entry carries its own `source`.

Three things this exercise established, all worth reporting as limitations:

  1. Plausible guesses are frequently wrong. nginx is `igor_sysoev:nginx`, not
     `f5:nginx` or `nginx:nginx`.
  2. Some products have several real vendor prefixes carrying different CVE
     sets. MySQL 5.7.44 returns 12 CVEs under `oracle:mysql` but 2 under
     `mysql:mysql`. Both exist; neither is complete.
  3. The NVD CPE *dictionary* keyword search does not reliably rank the vendor
     that actually carries the CVEs. Searching "redis" ranks `redislabs:redis`
     and `pivotal_software:redis` highest, yet for Redis 5.0.14 both return
     **0** CVEs while `redis:redis` returns **21**.

Because of (2) and (3), entries may declare `alternates`. The normalizer emits
a signature for each candidate and correlation reports which one matched, so an
ambiguous product is visible rather than silently resolved to one guess.

An unmapped product is NOT an error and NOT "clean" — it is reported as
unmapped, and correlation falls back to a clearly-labelled keyword search.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["ProductMapping", "PRODUCT_MAP", "lookup_product", "VERIFICATION_NOTE"]

VERIFICATION_NOTE = (
    "Vendor:product pairs verified 2026-08-30 against the NVD REST API 2.0. "
    "Dictionary lookups used /rest/json/cpes/2.0?keywordSearch=; ambiguous "
    "products were resolved by comparing totalResults from "
    "/rest/json/cves/2.0?cpeName= for a concrete version of each candidate."
)


@dataclass(frozen=True)
class ProductMapping:
    vendor: str
    product: str
    part: str = "a"
    # Additional real vendor prefixes for the same software. Each yields its
    # own candidate signature rather than being discarded.
    alternates: tuple[tuple[str, str], ...] = ()
    source: str = "nvd_cpe_dictionary"
    note: str = ""

    def candidates(self) -> tuple[tuple[str, str], ...]:
        return ((self.vendor, self.product), *self.alternates)


# Keys are lowercased Nmap `product` strings.
PRODUCT_MAP: dict[str, ProductMapping] = {
    # --- verified: single unambiguous vendor -----------------------------
    "vsftpd": ProductMapping(
        "vsftpd_project", "vsftpd", note="Dictionary: 42/42 products under this vendor."
    ),
    "apache httpd": ProductMapping(
        "apache", "http_server", note="Verified: 2.4.49 returns 81 CVE candidates."
    ),
    "openssh": ProductMapping("openbsd", "openssh"),
    "samba smbd": ProductMapping("samba", "samba"),
    "apache tomcat": ProductMapping("apache", "tomcat"),
    "proftpd": ProductMapping("proftpd", "proftpd"),
    "postgresql db": ProductMapping("postgresql", "postgresql"),
    "nginx": ProductMapping(
        "igor_sysoev",
        "nginx",
        note="Verified: dictionary returns igor_sysoev:nginx, NOT f5 or nginx:nginx.",
    ),

    # --- verified: genuinely ambiguous, alternates retained ---------------
    "mysql": ProductMapping(
        "oracle",
        "mysql",
        alternates=(("mysql", "mysql"),),
        note=(
            "MySQL 5.7.44: oracle:mysql -> 12 CVEs, mysql:mysql -> 2. Both are "
            "real and neither is a superset; both are correlated."
        ),
    ),
    "redis key-value store": ProductMapping(
        "redis",
        "redis",
        alternates=(("redislabs", "redis"),),
        note=(
            "Redis 5.0.14: redis:redis -> 21 CVEs, while redislabs:redis and "
            "pivotal_software:redis both -> 0, despite ranking higher in the "
            "CPE dictionary keyword search."
        ),
    ),

    # --- verified: present in the local test environment ------------------
    "mariadb": ProductMapping(
        "mariadb",
        "mariadb",
        note=(
            "MariaDB has its own CPE vendor and must NOT be aliased to MySQL. "
            "Measured for the laboratory's 10.5.29: mariadb:mariadb -> 3 CVEs, "
            "oracle:mysql -> 0. Treating MariaDB as MySQL is a total false "
            "negative."
        ),
    ),

    "simplehttpserver": ProductMapping(
        "python",
        "simplehttpserver",
        source="nmap_cpe",
        note="Nmap emits cpe:/a:python:simplehttpserver directly.",
    ),
}

# Alternative spellings Nmap uses for the same software.
_ALIASES: dict[str, str] = {
    "apache http server": "apache httpd",
    "httpd": "apache httpd",
    "redis": "redis key-value store",
    "mysql community server": "mysql",
    "mariadb server": "mariadb",
    "samba": "samba smbd",
    "tomcat": "apache tomcat",
    "postgresql": "postgresql db",
    "openssh server": "openssh",
    "simplehttp": "simplehttpserver",
}


def lookup_product(product: str | None) -> ProductMapping | None:
    """Resolve an Nmap product string to a mapping, or None if unmapped.

    Returning None is a legitimate outcome that the caller must surface, not an
    error to suppress: an unmapped product means correlation confidence drops,
    never that the service is considered safe.
    """
    if not product:
        return None

    key = product.strip().lower()
    if key in PRODUCT_MAP:
        return PRODUCT_MAP[key]
    if key in _ALIASES:
        return PRODUCT_MAP[_ALIASES[key]]

    # Nmap often appends a role word: "Samba smbd", "Postfix smtpd".
    # Try progressively shorter prefixes, longest first.
    words = key.split()
    for length in range(len(words) - 1, 0, -1):
        prefix = " ".join(words[:length])
        if prefix in PRODUCT_MAP:
            return PRODUCT_MAP[prefix]
        if prefix in _ALIASES:
            return PRODUCT_MAP[_ALIASES[prefix]]

    return None
