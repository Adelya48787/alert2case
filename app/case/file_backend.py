"""TheHive olmadan inkişaf üçün: case-ləri JSON fayl kimi yazır (var/cases/)."""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.case.base import PLAYBOOK_TASKS, CaseBackend, CaseRef, description, title
from app.schemas.alert import Decision, NormalizedAlert

CASE_DIR = Path("var/cases")


class FileBackend(CaseBackend):
    name = "file"

    async def create(self, alert: NormalizedAlert, d: Decision) -> CaseRef:
        CASE_DIR.mkdir(parents=True, exist_ok=True)
        case_id = f"FILE-{uuid4().hex[:8]}"
        doc = {
            "case_id": case_id,
            "title": title(alert, d),
            "description": description(alert, d),
            "priority": d.priority,
            "severity": d.severity_id.name,
            "verdict": d.verdict,
            "tags": [alert.alert_type, f"rule:{d.rule_id}", f"fp:{alert.fingerprint}"],
            "observables": [o.model_dump() for o in alert.observables],
            "tasks": PLAYBOOK_TASKS[alert.alert_type],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "comments": [],
        }
        path = CASE_DIR / f"{case_id}.json"
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        return CaseRef(backend=self.name, case_id=case_id, url=str(path))

    async def comment(self, ref: CaseRef, text: str) -> None:
        path = Path(ref.url)
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["comments"].append({"at": datetime.now(timezone.utc).isoformat(), "text": text})
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
