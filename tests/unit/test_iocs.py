import pytest

from app.normalize.iocs import domain_of, fingerprint, hash_type, is_internal_ip, normalize_url, refang
from app.schemas.alert import Observable


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("hxxp://a[.]b/c", "http://a.b/c"),
        ("hxxps://x[.]y[.]z", "https://x.y.z"),
        ("http://ok.com", "http://ok.com"),
        ("HXXP://a(.)b", "http://a.b"),
    ],
)
def test_refang(raw, expected):
    assert refang(raw) == expected


@pytest.mark.parametrize(
    "value,kind",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash_sha1"),
        ("A" * 64, "hash_sha256"),
    ],
)
def test_hash_type(value, kind):
    assert hash_type(value) == kind


@pytest.mark.parametrize("bad", ["xyz", "a" * 63, "g" * 64, ""])
def test_hash_type_rejects(bad):
    with pytest.raises(ValueError):
        hash_type(bad)


@pytest.mark.parametrize(
    "ip,internal",
    [
        ("10.1.2.3", True),
        ("192.168.0.1", True),
        ("127.0.0.1", True),
        ("203.0.113.10", True),  # TEST-NET: sənədləşmə diapazonu
        ("8.8.8.8", False),
        ("::1", True),
        ("2001:4860:4860::8888", False),
    ],
)
def test_internal_ip(ip, internal):
    assert is_internal_ip(ip) is internal


def test_internal_ip_rejects_garbage():
    with pytest.raises(ValueError):
        is_internal_ip("not-an-ip")


def test_url_normalized_and_domain():
    u = normalize_url("HTTP://Sub.Example.CO.UK/Path")
    assert u == "http://sub.example.co.uk/Path"
    assert domain_of(u) == "example.co.uk"
    assert domain_of("http://1.2.3.4/x") is None


@pytest.mark.parametrize(
    "url,domain",
    [
        ("https://backup-storage.duckdns.org/", "backup-storage.duckdns.org"),
        ("https://camera-office.hopto.org/", "camera-office.hopto.org"),
        ("https://www.google.com/", "google.com"),
    ],
)
def test_domain_keeps_dynamic_dns_subdomain(url, domain):
    assert domain_of(url) == domain


@pytest.mark.parametrize("bad", ["ftp://x.y/z", "not a url", "http://"])
def test_url_rejects_non_http(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


def test_fingerprint_order_independent_and_ignores_host():
    a = [Observable(type="ip", value="1.2.3.4"), Observable(type="user", value="u")]
    b = [
        Observable(type="user", value="u"),
        Observable(type="ip", value="1.2.3.4"),
        Observable(type="host", value="h"),
    ]
    assert fingerprint("suspicious_login", a) == fingerprint("suspicious_login", b)
    assert fingerprint("suspicious_login", a) != fingerprint("malicious_hash", a)
