"""IOC-ların təmizlənməsi və yoxlanması."""

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import tldextract

_HEX = re.compile(r"^[a-f0-9]+$")
_HASH_TYPES = {32: "hash_md5", 40: "hash_sha1", 64: "hash_sha256"}
# şəbəkəsiz (paketin daxili siyahısı); private suffix-lər: duckdns.org kimi provayderlərdə alt domen saxlanılır
_tld = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def refang(s: str) -> str:
    """hxxp://bad[.]example → http://bad.example"""
    s = s.strip()
    s = re.sub(r"^hxxp", "http", s, flags=re.IGNORECASE)
    for a, b in (("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[://]", "://")):
        s = s.replace(a, b)
    return s


def hash_type(value: str) -> str:
    v = value.strip().lower()
    if not _HEX.match(v) or len(v) not in _HASH_TYPES:
        raise ValueError(f"hash deyil: {value[:24]!r}")
    return _HASH_TYPES[len(v)]


def is_internal_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.strip())  # səhv IP-də ValueError
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def normalize_url(value: str) -> str:
    parts = urlsplit(refang(value))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"URL deyil: {value[:40]!r}")
    # sxem və host kiçik hərflə; path böyük/kiçik hərfə həssasdır, toxunmuruq
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def domain_of(url: str) -> str | None:
    host = urlsplit(url).hostname
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # URL-də domain yox, IP var
    except ValueError:
        pass
    ext = _tld(host)
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or host


def fingerprint(alert_type: str, observables: list) -> str:
    """Eyni hadisənin təkrarını tanımaq üçün sabit açar."""
    parts = sorted(f"{o.type}:{o.value}" for o in observables if o.type != "host")
    raw = "|".join([alert_type, *parts])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
