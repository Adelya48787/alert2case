"""Testlər üçün alert fabriki."""

from datetime import datetime, timezone

from app.schemas.alert import Enrichment, NormalizedAlert, Observable

NOW = datetime.now(timezone.utc)


def make(
    alert_type="malicious_hash",
    verdict="clean",
    score=0,
    status="ok",
    confidence=1.0,
    conflict=False,
    user="adile",
    host="WS-014",
    ioc=None,
    ctx=None,
) -> NormalizedAlert:
    obs = (
        ioc
        or {
            "malicious_hash": Observable(type="hash_sha256", value="a" * 64),
            "suspicious_login": Observable(type="ip", value="185.220.101.4"),
            "suspicious_url": Observable(type="url", value="http://x.example/a"),
        }[alert_type]
    )

    alert = NormalizedAlert(
        source_system="edr",
        alert_type=alert_type,
        title="t",
        time=NOW,
        received_at=NOW,
        user=user,
        host=host,
        observables=[obs],
        raw={},
        enrichment=Enrichment(
            status=status,
            verdict=verdict,
            reputation_score=score,
            confidence=confidence,
            conflict=conflict,
        ),
    )
    alert.context = ctx or {
        "asset_criticality": "medium",
        "user_privileged": False,
        "user_vip": False,
        "allowlisted": False,
    }
    return alert
