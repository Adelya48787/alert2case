"""dataset/demo: korrelyasiya demo alert-ləri öz ssenarilərinə uyğun qalır."""

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from app.normalize import normalize

DEMO = Path("dataset/demo")
NOW = datetime.now(timezone.utc)


def load(ref: str):
    doc = json.loads((DEMO / f"{ref}.json").read_text(encoding="utf-8"))
    return normalize(doc["source"], doc["payload"], NOW)


def test_every_demo_alert_normalizes_with_external_ioc():
    files = sorted(DEMO.glob("*.json"))
    assert len(files) == 11
    for f in files:
        a = load(f.stem)
        assert a.source_ref == f.stem and a.external_iocs()


def test_fingerprints_are_unique():
    fps = [load(f.stem).fingerprint for f in DEMO.glob("*.json")]
    assert len(fps) == len(set(fps))  # heç biri dedup-a düşmür


def test_c1_pair_shares_url_but_not_user():
    a, b = load("DEMO-C1-A"), load("DEMO-C1-B")
    url = lambda x: [o.value for o in x.observables if o.type == "url"]  # noqa: E731
    assert url(a) == url(b) and a.user != b.user


def test_c3_pair_shares_host():
    u, h = load("DEMO-C3-URL"), load("DEMO-C3-HASH")
    assert (u.alert_type, h.alert_type) == ("suspicious_url", "malicious_hash")
    assert u.host == h.host == "WS-034"


def test_c4_logins_share_one_subnet():
    nets = {
        str(ipaddress.ip_network(f"{load(f'DEMO-C4-{k}').external_iocs()[0].value}/24", strict=False))
        for k in range(1, 8)
    }
    assert nets == {"185.220.101.0/24"}


def test_proxy_host_name_is_read():
    assert load("DEMO-C1-A").host == "WS-031"
