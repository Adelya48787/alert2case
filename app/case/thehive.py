"""TheHive 5 REST API backend (service account açarı ilə)."""

import logging

import httpx

from app.case.base import PLAYBOOK_TASKS, CaseBackend, CaseError, CaseRef, description, title
from app.config import settings
from app.schemas.alert import Decision, NormalizedAlert

log = logging.getLogger("case.thehive")

SEVERITY = {0: 1, 1: 1, 2: 1, 3: 2, 4: 3, 5: 4, 6: 4}  # OCSF → TheHive (1 low … 4 critical)
DATATYPE = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "hash_md5": "hash",
    "hash_sha1": "hash",
    "hash_sha256": "hash",
    "user": "other",
    "host": "hostname",
}


class TheHiveBackend(CaseBackend):
    name = "thehive"

    def __init__(self) -> None:
        self.base = settings.thehive_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {settings.thehive_api_key}"}

    async def _post(self, client: httpx.AsyncClient, path: str, body: dict) -> dict:
        try:
            r = await client.post(f"{self.base}{path}", json=body, headers=self.headers)
        except httpx.TransportError as e:
            raise CaseError(f"TheHive əlçatmazdır: {e!r}") from e
        if r.status_code >= 300:
            raise CaseError(f"TheHive {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}

    async def create(self, alert: NormalizedAlert, d: Decision) -> CaseRef:
        tags = [
            alert.alert_type,
            f"rule:{d.rule_id}",
            f"fp:{alert.fingerprint}",
            f"verdict:{d.verdict}",
            "alert2case",
        ] + (["shadow-autoclose"] if d.shadow else [])
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as c:
            case = await self._post(
                c,
                "/api/v1/case",
                {
                    "title": title(alert, d),
                    "description": description(alert, d),
                    "severity": SEVERITY[int(d.severity_id)],
                    "tlp": 2,
                    "pap": 2,
                    "tags": tags,
                },
            )
            cid = case["_id"]
            # case yarandı: bundan sonrakı xətalar case-i itirmir, yalnız loglanır
            for o in alert.observables:
                try:
                    await self._post(
                        c,
                        f"/api/v1/case/{cid}/observable",
                        {
                            "dataType": DATATYPE[o.type],
                            "data": o.value,
                            "ioc": d.verdict == "malicious"
                            and o.type not in ("user", "host")
                            and not o.internal,
                            "tags": [f"role:{o.role}"]
                            + (["internal"] if o.internal else [])
                            + ([f"type:{o.type}"] if o.type in ("user",) else []),
                        },
                    )
                except CaseError as e:
                    log.warning("observable əlavə olunmadı (%s): %s", o.value, e)
            for t in PLAYBOOK_TASKS[alert.alert_type]:
                try:
                    await self._post(c, f"/api/v1/case/{cid}/task", {"title": t})
                except CaseError as e:
                    log.warning("task əlavə olunmadı: %s", e)
        return CaseRef(backend=self.name, case_id=cid, url=f"{self.base}/cases/{cid}/details")

    async def comment(self, ref: CaseRef, text: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as c:
            await self._post(c, f"/api/v1/case/{ref.case_id}/comment", {"message": text})
