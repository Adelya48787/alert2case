"""Auto-close qoruyucuları, shadow mode və kill switch testləri."""

import pytest

from app.config import settings
from app.rules.engine import decide
from app.rules.guards import apply_guards
from app.schemas.alert import Severity
from tests.unit.factories import make


@pytest.fixture(autouse=True)
def safe_defaults(monkeypatch):
    monkeypatch.setattr(settings, "shadow_mode", False)
    monkeypatch.setattr(settings, "auto_close_enabled", True)


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"status": "partial"}, "natamam"),
        ({"conflict": True}, "ziddiyyət"),
        ({"confidence": 0.33}, "etibarlılıq"),
        ({"ctx": {"user_vip": True}}, "VIP"),
        ({"ctx": {"user_privileged": True}}, "imtiyazlı"),
        ({"ctx": {"asset_criticality": "crown_jewel"}}, "crown_jewel"),
    ],
)
def test_guards_block_auto_close(kwargs, reason):
    alert = make(**kwargs)
    decision = decide(alert).model_copy(update={"action": "auto_close"})

    result = apply_guards(alert, decision)

    assert result.action == "create_case"
    assert result.severity_id >= Severity.LOW
    assert any(reason in item for item in result.reasons)


def test_clean_alert_can_auto_close():
    alert = make()
    result = apply_guards(alert, decide(alert))
    assert result.action == "auto_close"


def test_create_case_decision_is_unchanged():
    alert = make(verdict="malicious", score=89)
    decision = decide(alert)

    assert decision.action == "create_case"
    assert apply_guards(alert, decision) is decision


def test_shadow_mode(monkeypatch):
    monkeypatch.setattr(settings, "shadow_mode", True)
    alert = make()

    result = apply_guards(alert, decide(alert))

    assert result.action == "create_case"
    assert result.shadow is True
    assert "shadow mode" in result.reasons[-1]


def test_kill_switch(monkeypatch):
    monkeypatch.setattr(settings, "auto_close_enabled", False)
    alert = make()

    result = apply_guards(alert, decide(alert))

    assert result.action == "create_case"
    assert result.shadow is True
    assert "kill switch" in result.reasons[-1]


# ---------- qızıl qayda: malicious heç vaxt avtomatik bağlanmır (4.3, 4.8) ----------
def test_malicious_never_auto_closed_by_any_rule():
    for verdict in ("malicious", "suspicious", "unknown"):
        for status in ("ok", "partial", "failed"):
            a = make(verdict=verdict, status=status, score=80)
            assert apply_guards(a, decide(a)).action == "create_case"


BASE_CTX = {"asset_criticality": "medium", "user_privileged": False, "user_vip": False, "allowlisted": False}


@pytest.mark.parametrize("alert_type", ["malicious_hash", "suspicious_login", "suspicious_url"])
@pytest.mark.parametrize("status", ["ok", "partial", "failed"])
@pytest.mark.parametrize("score", [None, 0, 5, 29, 40, 80, 100])
@pytest.mark.parametrize(
    "ctx",
    [{}, {"allowlisted": True}, {"user_privileged": True}, {"asset_criticality": "crown_jewel"}],
    ids=["normal", "allowlisted", "privileged", "crown_jewel"],
)
def test_malicious_verdict_blocked_in_every_combination(alert_type, status, score, ctx):
    # Aggregate malicious-i yalnız skor >= 70-də verir, amma qoruyucu buna güvənmir:
    # allowlist + aşağı skor (R02) kimi kombinasiyalarda da bağlanmamalıdır.
    a = make(alert_type=alert_type, verdict="malicious", status=status, score=score, ctx={**BASE_CTX, **ctx})
    assert apply_guards(a, decide(a)).action == "create_case"


def test_guard_blocks_even_if_rule_file_says_close():
    # kimsə qayda faylında səhvən "malicious → auto_close" yazsa belə
    from app.rules.engine import RuleSet

    bad = RuleSet.model_validate(
        {
            "version": "bad",
            "rules": [
                {
                    "id": "BAD",
                    "when": {"enrichment.verdict": {"eq": "malicious"}},
                    "then": {"verdict": "malicious", "severity_id": 5, "action": "auto_close"},
                },
                {
                    "id": "DEF",
                    "when": {},
                    "then": {"verdict": "unknown", "severity_id": 3, "action": "create_case"},
                },
            ],
        }
    )
    a = make(verdict="malicious", score=95)
    result = apply_guards(a, decide(a, bad))
    assert result.action == "create_case"
    assert any("malicious" in r for r in result.reasons)
