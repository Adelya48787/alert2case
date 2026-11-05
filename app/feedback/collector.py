"""Analitik rəyinin toplanması: TheHive case bağlananda və ya əl ilə (/feedback)."""

import logging
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from app import db
from app.audit.log import audit

log = logging.getLogger("feedback")
Verdict = Literal["malicious", "suspicious", "clean"]

# TheHive resolutionStatus → analitikin verdict-i
RESOLUTION = {
    "TruePositive": "malicious",
    "FalsePositive": "clean",
    "Indeterminate": "suspicious",
    "Other": "suspicious",
}
# TheHive severity (1–4) → OCSF severity_id
SEVERITY = {1: 2, 2: 3, 3: 4, 4: 5}


class FeedbackIn(BaseModel):
    alert_id: UUID
    human_verdict: Verdict
    human_severity: int | None = None
    analyst: str = "unknown"
    source: Literal["thehive", "manual", "qa"] = "manual"
    comment: str = ""


async def from_thehive(body: dict) -> FeedbackIn | None:
    """TheHive webhook-u. Format versiyadan asılıdır, ona görə ehtiyatla oxuyuruq."""
    obj = body.get("object") or body.get("details") or body
    case_id = obj.get("_id") or body.get("objectId")
    resolution = obj.get("resolutionStatus")
    if not case_id or resolution not in RESOLUTION:
        log.info("rəy deyil və ya case bağlanmayıb: %s", body.get("operation") or body.get("action"))
        return None
    alert_id = await db.alert_for_case(case_id)
    if alert_id is None:
        log.warning("case %s üçün alert tapılmadı", case_id)
        return None
    sev = SEVERITY.get(int(obj["severity"])) if str(obj.get("severity", "")).isdigit() else None
    analyst = obj.get("assignee") or obj.get("_updatedBy") or "thehive"
    return FeedbackIn(
        alert_id=alert_id,
        human_verdict=RESOLUTION[resolution],
        human_severity=sev,
        analyst=analyst,
        source="thehive",
        comment=(obj.get("summary") or "")[:500],
    )


async def record(fb: FeedbackIn) -> dict:
    dec = await db.last_decision(fb.alert_id)
    if dec is None:
        return {"error": "bu alert üçün qərar yoxdur"}
    agree = dec["verdict"] == fb.human_verdict or (
        dec["verdict"] == "unknown" and fb.human_verdict == "suspicious"
    )
    await db.save_feedback(fb, dec)
    await audit(
        fb.alert_id,
        "feedback",
        "agree" if agree else "disagree",
        {
            "auto": dec["verdict"],
            "human": fb.human_verdict,
            "rule": dec["rule_id"],
            "analyst": fb.analyst,
            "source": fb.source,
        },
        actor=fb.analyst,
    )
    return {"saved": True, "agree": agree, "rule": dec["rule_id"]}
