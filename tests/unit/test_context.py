"""4.1b: daxili kontekst yükləyicisi. Real context/ fayllarına toxunmur: test öz müvəqqəti qovluğunu yaradır."""

import os
from datetime import date, datetime, timezone

import pytest

from app.context import loader
from app.context.loader import allowlist_match, apply_context
from app.schemas.alert import NormalizedAlert, Observable

TODAY = date(2026, 11, 1)


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    (tmp_path / "assets.csv").write_text(
        "hostname,criticality,owner\nDC-01,crown_jewel,it-infra\nvpn-gw,high,it-infra\n", encoding="utf-8"
    )
    (tmp_path / "identities.csv").write_text(
        "user,is_privileged,is_vip,department\nelcin.admin,true,false,it\nceo.office,no,yes,management\n",
        encoding="utf-8",
    )
    (tmp_path / "allowlist.yaml").write_text(
        "entries:\n"
        "  - {type: ip_cidr, value: 203.0.113.0/24, owner: elvin, reason: corporate VPN egress, expires_at: 2027-06-30}\n"
        "  - {type: domain, value: example-corp.az, owner: adile, reason: company domain, expires_at: 2027-06-30}\n"
        "  - {type: hash, value: AAAA, owner: x, reason: old hash, expires_at: 2020-01-01}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(loader, "CTX_DIR", tmp_path)
    monkeypatch.setattr(loader, "_cache", {"stamp": None, "data": None})
    return tmp_path


def alert(user=None, host=None, obs=()):
    now = datetime.now(timezone.utc)
    return NormalizedAlert(
        source_system="wazuh",
        alert_type="suspicious_login",
        title="t",
        time=now,
        received_at=now,
        user=user,
        host=host,
        raw={},
        observables=list(obs) or [Observable(type="user", value="x", role="actor")],
    )


def ip(v, internal=False):
    return Observable(type="ip", value=v, role="src", internal=internal)


def test_load_reads_all_files(ctx):
    d = loader.load()
    assert d["assets"] == {"dc-01": "crown_jewel", "vpn-gw": "high"}
    assert set(d["identities"]) == {"elcin.admin", "ceo.office"}
    assert len(d["allow"]) == 3


def test_load_without_files(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "CTX_DIR", tmp_path)
    monkeypatch.setattr(loader, "_cache", {"stamp": None, "data": None})
    assert loader.load() == {"assets": {}, "identities": {}, "allow": []}


def test_hot_reload_on_change(ctx):
    assert "ws-014" not in loader.load()["assets"]
    p = ctx / "assets.csv"
    p.write_text(p.read_text() + "WS-014,medium,adile\n", encoding="utf-8")
    st = p.stat()
    os.utime(p, (st.st_atime, st.st_mtime + 5))
    assert loader.load()["assets"]["ws-014"] == "medium"


def test_privileged_user_on_high_asset(ctx):
    a = alert("Elcin.Admin", "VPN-GW", [ip("171.25.193.25")])
    apply_context(a, TODAY)
    assert a.context == {
        "asset_criticality": "high",
        "user_privileged": True,
        "user_vip": False,
        "allowlisted": False,
        "allowlist_reason": "",
    }


def test_unknown_host_and_vip(ctx):
    a = alert("ceo.office", "LAPTOP-99", [ip("1.2.3.4")])
    apply_context(a, TODAY)
    assert a.context["asset_criticality"] == "unknown"
    assert a.context["user_vip"] is True and a.context["user_privileged"] is False


def test_vpn_ip_allowlisted(ctx):
    a = alert("samir", "vpn-gw", [ip("203.0.113.10")])
    apply_context(a, TODAY)
    assert a.context["allowlisted"] is True and a.context["allowlist_reason"] == "corporate VPN egress"


def test_all_external_iocs_must_match(ctx):
    a = alert("samir", "vpn-gw", [ip("203.0.113.10"), ip("171.25.193.25")])
    apply_context(a, TODAY)
    assert a.context["allowlisted"] is False


def test_internal_ip_ignored(ctx):
    a = alert("samir", "vpn-gw", [ip("203.0.113.10"), ip("10.0.4.21", internal=True)])
    apply_context(a, TODAY)
    assert a.context["allowlisted"] is True


def test_no_external_iocs_not_allowlisted(ctx):
    a = alert("samir", "vpn-gw", [ip("10.0.4.21", internal=True)])
    apply_context(a, TODAY)
    assert a.context["allowlisted"] is False


@pytest.mark.parametrize(
    "obs,hit",
    [
        (Observable(type="url", value="https://mail.example-corp.az/x"), True),
        (Observable(type="domain", value="example-corp.az"), True),
        (Observable(type="domain", value="evil-example-corp.az"), False),
        (Observable(type="url", value="http://example-corp.az.evil.top/"), False),
    ],
)
def test_domain_and_url(ctx, obs, hit):
    entries = loader.load()["allow"]
    assert (allowlist_match(obs, entries, TODAY) is not None) is hit


def test_expired_entry_ignored(ctx):
    entries = loader.load()["allow"]
    assert allowlist_match(Observable(type="hash_md5", value="aaaa"), entries, TODAY) is None
    assert allowlist_match(Observable(type="hash_md5", value="aaaa"), entries, date(2019, 1, 1)) == "old hash"


def test_entry_expires_after_date(ctx):
    a = alert("samir", "vpn-gw", [ip("203.0.113.10")])
    apply_context(a, date(2027, 7, 1))
    assert a.context["allowlisted"] is False
