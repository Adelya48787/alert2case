"""Provider nəticələrini bir skora, etibarlılığa və verdict-ə çevirir."""

from functools import lru_cache
from pathlib import Path

import yaml

from app.enrich.base import ProviderResult
from app.schemas.alert import Enrichment

WEIGHTS_FILE = Path("rules/weights.yaml")


@lru_cache(maxsize=1)
def load_weights(path: str = str(WEIGHTS_FILE)) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def aggregate(results: list[ProviderResult], cfg: dict | None = None) -> Enrichment:
    cfg = cfg or load_weights()
    pcfg = cfg["providers"]
    summary = [
        r.model_dump(
            include={"provider", "ioc_type", "status", "score", "cached", "latency_ms", "evidence", "note"}
        )
        for r in results
    ]
    if not results:  # xarici IOC yoxdur
        return Enrichment(status="skipped", confidence=0.0, verdict="unknown", providers=summary)

    answered = [r for r in results if r.status in ("ok", "not_found")]
    ok = [r for r in results if r.status == "ok"]
    confidence = round(len(answered) / len(results), 2)
    status = "ok" if len(answered) == len(results) else ("failed" if not answered else "partial")

    # hər provider üçün ən yüksək skor (bir alert-də bir neçə IOC ola bilər)
    best: dict[str, int] = {}
    for r in ok:
        best[r.provider] = max(best.get(r.provider, 0), r.score or 0)

    score = None
    if best:
        weights = {p: pcfg.get(p, {}).get("weight", 0.1) for p in best}
        avg = sum(best[p] * weights[p] for p in best) / sum(weights.values())
        strong = [s for p, s in best.items() if pcfg.get(p, {}).get("strong")]
        top = max(strong) if strong else avg
        score = round(cfg["blend_max"] * top + (1 - cfg["blend_max"]) * avg)

    strong_scores = [best[p] for p in best if pcfg.get(p, {}).get("strong")]
    conflict = (
        len(strong_scores) >= 2
        and max(strong_scores) >= cfg["conflict"]["high"]
        and min(strong_scores) <= cfg["conflict"]["low"]
    )
    weak_signal = any(
        best[p] >= pcfg[p]["weak_signal"]
        for p in best
        if pcfg.get(p, {}).get("strong") and "weak_signal" in pcfg[p]
    )

    th = cfg["thresholds"]
    if score is None:
        verdict = "unknown"  # heç kim tanımır və ya cavab yoxdur
    elif score >= th["malicious"] and not conflict:
        verdict = "malicious"
    elif score >= th["suspicious"] or conflict or weak_signal:
        verdict = "suspicious"
    elif confidence >= cfg["min_confidence_clean"]:
        verdict = "clean"
    else:
        verdict = "unknown"

    return Enrichment(
        status=status,
        reputation_score=score,
        confidence=confidence,
        conflict=conflict,
        verdict=verdict,
        providers=summary,
    )
