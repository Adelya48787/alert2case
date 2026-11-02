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
