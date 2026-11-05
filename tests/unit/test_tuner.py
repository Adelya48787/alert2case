"""5.2b: tuner təklifləri və safety gate. Baza, git və şəbəkə istifadə olunmur."""

import pytest

from tools import tuner

W = {
    "providers": {
        "virustotal": {"weight": 0.5},
        "abuseipdb": {"weight": 0.3},
        "otx": {"weight": 0.2},
    },
    "thresholds": {"malicious": 70, "suspicious": 30},
}


def fb(rule="R07-CLEAN", auto="clean", human="clean", auto_sev=1, human_sev=None, providers=(), obs=()):
    return {
        "rule_id": rule,
        "auto_verdict": auto,
        "human_verdict": human,
        "auto_severity": auto_sev,
        "human_severity": human_sev,
        "doc": {"enrichment": {"providers": list(providers)}, "observables": list(obs)},
    }


def prov(name, score, status="ok"):
    return {"provider": name, "status": status, "score": score}


@pytest.mark.parametrize("before,after,ok", [(0, 0, True), (2, 1, True), (0, 1, False), (10, 11, False)])
def test_is_safe_never_allows_more_fn(before, after, ok):
    assert tuner.is_safe({"fn": before}, {"fn": after}) is ok


def test_rule_stats_counts_fp_fn_and_severity():
    rows = [
        fb("R04", auto="malicious", human="clean"),  # FP
        fb("R04", auto="malicious", human="malicious", auto_sev=4, human_sev=5),
        fb("R07", auto="clean", human="malicious"),  # FN
        fb("R07", auto="clean", human="clean", human_sev=1),
    ]
    s = tuner.rule_stats(rows)
    assert (s["R04"]["n"], s["R04"]["fp"], s["R04"]["fn"], s["R04"]["sev_diff"]) == (2, 1, 0, 1)
    assert (s["R07"]["n"], s["R07"]["fp"], s["R07"]["fn"], s["R07"]["sev_diff"]) == (2, 0, 1, 0)


def test_weights_unchanged_below_min_samples():
    rows = [fb(human="malicious", providers=[prov("virustotal", 100)])] * (tuner.MIN_SAMPLES - 1)
    new, notes = tuner.propose_weights(rows, W)
    assert new == W and notes == []


def test_weight_up_when_provider_agrees():
    rows = [fb(human="malicious", providers=[prov("virustotal", 100)])] * tuner.MIN_SAMPLES
    new, notes = tuner.propose_weights(rows, W)
    assert new["providers"]["virustotal"]["weight"] == 0.55 and "virustotal" in notes[0]
    assert W["providers"]["virustotal"]["weight"] == 0.5  # orijinal dəyişmir


def test_weight_down_when_provider_disagrees():
    rows = [fb(human="clean", providers=[prov("otx", 60)])] * tuner.MIN_SAMPLES
    new, _ = tuner.propose_weights(rows, W)
    assert new["providers"]["otx"]["weight"] == 0.15


def test_weight_respects_bounds():
    w = {**W, "providers": {"virustotal": {"weight": tuner.W_MAX}, "otx": {"weight": tuner.W_MIN}}}
    up = [fb(human="malicious", providers=[prov("virustotal", 100)])] * tuner.MIN_SAMPLES
    down = [fb(human="clean", providers=[prov("otx", 60)])] * tuner.MIN_SAMPLES
    new, notes = tuner.propose_weights(up + down, w)
    assert new["providers"]["virustotal"]["weight"] == tuner.W_MAX
    assert new["providers"]["otx"]["weight"] == tuner.W_MIN and notes == []


def test_weight_ignores_failed_and_unknown_providers():
    rows = [fb(human="malicious", providers=[prov("virustotal", None, "timeout"), prov("greynoise", 90)])]
    new, notes = tuner.propose_weights(rows * tuner.MIN_SAMPLES, W)
    assert new == W and notes == []


def test_threshold_raised_for_noisy_rule():
    rows = [fb("R06", auto="suspicious", human="clean")] * 4 + [
        fb("R06", auto="suspicious", human="suspicious")
    ] * 6
    new, notes = tuner.propose_thresholds(tuner.rule_stats(rows), W)
    assert new["thresholds"]["suspicious"] == 35 and "R06" in notes[0]


def test_threshold_capped_at_60():
    w = {**W, "thresholds": {"malicious": 70, "suspicious": 58}}
    rows = [fb("R06", auto="suspicious", human="clean")] * tuner.MIN_SAMPLES
    new, _ = tuner.propose_thresholds(tuner.rule_stats(rows), w)
    assert new["thresholds"]["suspicious"] == 60


def test_threshold_unchanged_when_quiet_or_few():
    quiet = [fb("R06", auto="suspicious", human="suspicious")] * tuner.MIN_SAMPLES
    few = [fb("R04", auto="malicious", human="clean")] * (tuner.MIN_SAMPLES - 1)
    new, notes = tuner.propose_thresholds(tuner.rule_stats(quiet + few), W)
    assert new == W and notes == []


def obs(t, v, internal=False):
    return {"type": t, "value": v, "internal": internal}


def test_allowlist_after_three_fp():
    rows = [fb(auto="suspicious", human="clean", obs=[obs("ip", "1.0.0.1")])] * 3
    rows += [fb(auto="suspicious", human="clean", obs=[obs("domain", "x.example")])] * 2
    out = tuner.propose_allowlist(rows)
    assert len(out) == 1
    e = out[0]
    assert (e["type"], e["value"], e["owner"]) == ("ip_cidr", "1.0.0.1/32", "tuner")
    assert e["reason"] and e["expires_at"]


def test_allowlist_ignores_internal_hash_and_true_positives():
    rows = [fb(auto="suspicious", human="clean", obs=[obs("ip", "10.0.0.1", internal=True)])] * 5
    rows += [fb(auto="suspicious", human="clean", obs=[obs("hash_sha256", "ab" * 32)])] * 5
    rows += [fb(auto="malicious", human="malicious", obs=[obs("ip", "6.6.6.6")])] * 5
    assert tuner.propose_allowlist(rows) == []


def test_allowlist_domain_entry():
    rows = [fb(auto="suspicious", human="clean", obs=[obs("domain", "cdn.example")])] * 3
    assert tuner.propose_allowlist(rows)[0]["value"] == "cdn.example"
