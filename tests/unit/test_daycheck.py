"""tools/daycheck.py: faktlardan Yekun sətirlərinin çıxarılması (xarici servis lazım deyil)."""

from tools.daycheck import DEMO_CONFIG, Facts, verdicts


def healthy() -> Facts:
    return Facts(
        config=dict(DEMO_CONFIG),
        containers={s: "running" for s in ("api", "worker", "postgres", "redis", "thehive")},
        web={k: True for k in ("api", "thehive", "mailpit", "n8n", "grafana", "prometheus")},
        db_ok=True,
        redis_ok=True,
        pending=0,
        lag=0,
        alerts_dlq=0,
        cases_dlq=0,
    )


def levels(f: Facts) -> list[str]:
    return [lvl for lvl, _ in verdicts(f)]


def test_healthy_stack_has_no_findings():
    assert verdicts(healthy()) == []


def test_api_running_but_health_fails_is_critical():
    # 11 noyabr halı: konteyner "running", içində ModuleNotFoundError
    f = healthy()
    f.web["api"] = False
    out = verdicts(f)
    assert ("KRİTİK" in levels(f)) and any("force-recreate" in m for _, m in out)


def test_stopped_worker_is_critical():
    f = healthy()
    f.containers["worker"] = "exited"
    assert "KRİTİK" in levels(f)


def test_thehive_down_is_critical_only_with_thehive_backend():
    f = healthy()
    f.web["thehive"] = False
    assert "KRİTİK" in levels(f)
    f.config["CASE_BACKEND"] = "file"
    assert "KRİTİK" not in levels(f)


def test_queues_and_config_are_warnings():
    f = healthy()
    f.cases_dlq, f.alerts_dlq, f.lag = 1, 2, 50
    f.config["AUTO_CLOSE_ENABLED"] = "true"
    assert levels(f) and set(levels(f)) == {"XƏBƏRDARLIQ"}


def test_broken_audit_chain_and_bad_intel_key_are_critical():
    f = healthy()
    f.audit, f.audit_ok = "ZƏNCİR QIRILIB: id=7", False
    f.intel = {"virustotal": {"auth_error": 1}}
    assert levels(f).count("KRİTİK") == 2
