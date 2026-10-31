from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.errors import PermanentError
from app.normalize import normalize
from app.schemas.alert import Severity

FILES = sorted(Path("dataset/raw").glob("*.json"))


def test_dataset_has_36_alerts():
    assert len(FILES) == 36


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_every_dataset_alert_normalizes(path, raw_doc, now):
    doc = raw_doc(path.stem)
    a = normalize(doc["source"], doc["payload"], now)
    assert a.source_ref == path.stem
    assert a.observables and len(a.fingerprint) == 32


def test_dataset_fingerprints_unique(raw_doc, now):
    fps = {normalize(d["source"], d["payload"], now).fingerprint for d in (raw_doc(p.stem) for p in FILES)}
    assert len(fps) == len(FILES)


def test_fingerprint_is_stable_and_ignores_time(raw_doc, now):
    doc = raw_doc("HASH-01")
    a = normalize("edr", doc["payload"], now)
    doc["payload"]["event_time"] = "2030-01-01T00:00:00+00:00"
    b = normalize("edr", doc["payload"], now)
    assert a.fingerprint == b.fingerprint and a.alert_id != b.alert_id


def test_internal_src_ip_marked(raw_doc, now):
    a = normalize("proxy", raw_doc("URL-01")["payload"], now)
    src = [o for o in a.observables if o.type == "ip" and o.role == "src"][0]
    assert src.internal and src not in a.external_iocs()


def test_ip_url_gets_dst_ip_observable(raw_doc, now):
    a = normalize("proxy", raw_doc("URL-02")["payload"], now)
    dst = [o for o in a.observables if o.type == "ip" and o.role == "dst"]
    assert len(dst) == 1 and not dst[0].internal and dst[0] in a.external_iocs()


def test_user_lowercased(raw_doc, now):
    doc = raw_doc("LOGIN-01")
    doc["payload"]["data"]["dstuser"] = "Elcin.Admin"
    assert normalize("wazuh", doc["payload"], now).user == "elcin.admin"


@pytest.mark.parametrize(
    "level,sev",
    [
        (15, Severity.CRITICAL),
        (12, Severity.HIGH),
        (8, Severity.MEDIUM),
        (4, Severity.LOW),
        (1, Severity.INFORMATIONAL),
    ],
)
def test_wazuh_severity(level, sev, raw_doc, now):
    doc = raw_doc("LOGIN-01")
    doc["payload"]["rule"]["level"] = level
    assert normalize("wazuh", doc["payload"], now).severity_id == sev


def test_edr_unknown_severity(raw_doc, now):
    doc = raw_doc("HASH-01")
    doc["payload"]["detection"]["severity"] = "weird"
    assert normalize("edr", doc["payload"], now).severity_id == Severity.UNKNOWN


def test_timestamp_without_timezone_rejected(raw_doc, now):
    doc = raw_doc("LOGIN-01")
    doc["payload"]["timestamp"] = "2026-11-02T08:00:00"
    with pytest.raises(PermanentError):
        normalize("wazuh", doc["payload"], now)


def test_unknown_source(now):
    with pytest.raises(PermanentError):
        normalize("splunk", {}, now)


@settings(max_examples=200, deadline=None)
@given(
    payload=st.dictionaries(st.text(max_size=8), st.text(max_size=8) | st.integers(), max_size=6),
    source=st.sampled_from(["wazuh", "edr", "proxy"]),
)
def test_garbage_never_crashes_differently(payload, source):
    # Hər cür zibil giriş yalnız PermanentError verməlidir, başqa heç nə
    try:
        normalize(source, payload, datetime.now(timezone.utc))
    except PermanentError:
        pass
