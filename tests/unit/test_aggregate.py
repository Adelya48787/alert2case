"""3.5: provider nəticələrinin birləşdirilməsi. Runbook cədvəlindəki 7 hal + kənar hallar."""

import pytest

from app.enrich import aggregate as agg
from app.enrich.base import ProviderResult, score_to_verdict


def ok(provider: str, score: int, ioc: str = "x") -> ProviderResult:
    return ProviderResult(
        provider=provider, ioc_type="ip", ioc=ioc, status="ok", score=score, verdict=score_to_verdict(score)
    )


def bad(provider: str, status: str) -> ProviderResult:
    return ProviderResult(provider=provider, ioc_type="ip", ioc="x", status=status)


@pytest.fixture(autouse=True)
def fresh_weights():
    agg.load_weights.cache_clear()
    yield
    agg.load_weights.cache_clear()


@pytest.mark.parametrize(
    "results,score,verdict,status",
    [
        ([ok("virustotal", 100), ok("otx", 0)], 89, "malicious", "ok"),  # zərərli hash
        ([ok("virustotal", 20), ok("abuseipdb", 100), ok("otx", 60)], 81, "malicious", "ok"),  # Tor exit IP
        ([ok("virustotal", 0), ok("abuseipdb", 0), ok("otx", 60)], 5, "clean", "ok"),  # təmiz DNS IP
        ([ok("virustotal", 20), ok("abuseipdb", 0), ok("otx", 0)], 16, "suspicious", "ok"),  # 1 VT mühərriki
        ([ok("virustotal", 0), ok("abuseipdb", 100)], 75, "suspicious", "ok"),  # ziddiyyət
        ([bad("virustotal", "not_found"), bad("otx", "not_found")], None, "unknown", "ok"),  # heç kim tanımır
        (
            [bad("virustotal", "timeout"), bad("abuseipdb", "error"), bad("otx", "skipped")],
            None,
            "unknown",
            "failed",
        ),
    ],
    ids=[
        "zererli-hash",
        "tor-exit",
        "temiz-dns",
        "1-vt-muherriki",
        "ziddiyyet",
        "hec-kim-tanimir",
        "hamisi-cokub",
    ],
)
def test_runbook_table(results, score, verdict, status):
    e = agg.aggregate(results)
    assert (e.reputation_score, e.verdict, e.status) == (score, verdict, status)


def test_conflict_flag_only_between_strong_sources():
    assert agg.aggregate([ok("virustotal", 0), ok("abuseipdb", 100)]).conflict
    assert not agg.aggregate([ok("virustotal", 0), ok("otx", 60)]).conflict  # OTX güclü mənbə deyil


def test_no_iocs_is_skipped():
    e = agg.aggregate([])
    assert (e.status, e.verdict, e.confidence) == ("skipped", "unknown", 0.0)


def test_partial_and_low_confidence_is_not_clean():
    # VT təmiz deyir, amma 3 sorğudan yalnız 1-i cavab verib → 0.33 < 0.67 → clean demirik
    e = agg.aggregate([ok("virustotal", 0), bad("abuseipdb", "timeout"), bad("otx", "error")])
    assert e.status == "partial"
    assert e.confidence == 0.33
    assert e.verdict == "unknown"


def test_highest_score_per_provider_wins():
    # bir alert-də iki IOC: VT birinə 0, digərinə 100 deyir → 100 götürülür
    e = agg.aggregate([ok("virustotal", 0, ioc="a"), ok("virustotal", 100, ioc="b")])
    assert e.reputation_score == 100 and e.verdict == "malicious"


def test_provider_summary_is_kept():
    e = agg.aggregate([ok("virustotal", 100)])
    assert e.providers[0]["provider"] == "virustotal" and e.providers[0]["score"] == 100


def test_weights_file_is_valid():
    cfg = agg.load_weights()
    assert cfg["version"]
    assert set(cfg["providers"]) == {"virustotal", "abuseipdb", "otx"}
    assert cfg["thresholds"]["malicious"] > cfg["thresholds"]["suspicious"]
