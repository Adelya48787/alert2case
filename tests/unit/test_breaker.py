"""Circuit breaker vəziyyət keçidlərinin testləri."""

from app.enrich.breaker import CircuitBreaker


def test_breaker_opens_after_five_failures_and_half_opens(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.enrich.breaker.time.monotonic", lambda: now[0])
    b = CircuitBreaker("x", fail_max=5, reset_s=60)

    assert b.state == "closed"
    assert b.allow()

    for _ in range(4):
        b.failure()
        assert b.state == "closed"

    b.failure()
    assert b.state == "open"
    assert not b.allow()

    now[0] = 159.0
    assert b.state == "open"

    now[0] = 160.0
    assert b.state == "half_open"
    assert b.allow()

    b.failure()
    assert b.state == "open"
    assert not b.allow()


def test_breaker_success_resets_failures_and_closes(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.enrich.breaker.time.monotonic", lambda: now[0])
    b = CircuitBreaker("x")

    b.failure()
    b.success()
    assert b.failures == 0
    assert b.state == "closed"

    for _ in range(5):
        b.failure()

    now[0] = 160.0
    assert b.state == "half_open"

    b.success()
    assert b.failures == 0
    assert b.opened_at is None
    assert b.state == "closed"
    assert b.allow()
