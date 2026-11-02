"""n8n üçün mərhələ endpoint-ləri. Worker-in istifadə etdiyi eyni funksiyaları çağırır,
yəni n8n və worker eyni qərarı verir. Admin token tələb olunur."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import pipeline
from app.case.base import CaseRef
from app.errors import PermanentError
from app.schemas.alert import NormalizedAlert


def build_router(require_admin) -> APIRouter:
    r = APIRouter(prefix="/stage", dependencies=[Depends(require_admin)], tags=["n8n stages"])

    class RawIn(BaseModel):
        source: str
        payload: dict

    class ActOut(BaseModel):
        alert: NormalizedAlert
        case: CaseRef | None = None

    @r.post("/normalize")
    async def normalize(body: RawIn) -> dict:
        try:
            alert = await pipeline.stage_normalize(body.source, body.payload, datetime.now(timezone.utc))
        except PermanentError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        return {"duplicate": alert is None, "alert": alert.model_dump(mode="json") if alert else None}

    @r.post("/enrich")
    async def enrich(alert: NormalizedAlert) -> NormalizedAlert:
        return await pipeline.stage_enrich(alert)

    @r.post("/decide")
    async def decide(alert: NormalizedAlert) -> NormalizedAlert:
        return await pipeline.stage_decide(alert)

    @r.post("/act")
    async def act(alert: NormalizedAlert) -> ActOut:
        related = await pipeline.stage_correlate(alert)
        ref = await pipeline.stage_act(alert, related)
        return ActOut(alert=alert, case=ref)

    @r.post("/notify")
    async def notify(body: ActOut) -> dict:
        return {"channels": await pipeline.stage_notify(body.alert, body.case)}

    return r
