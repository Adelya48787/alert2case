import hashlib
import hmac
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from app import queue
from app.config import settings

app = FastAPI(title="alert2case")

SOURCES = {"wazuh", "edr", "proxy"}
MAX_BODY = 256 * 1024


def verify_signature(body: bytes, signature: str | None) -> None:
    expected = "sha256=" + hmac.new(settings.webhook_hmac_secret.encode(), body, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="invalid signature")


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    if not settings.admin_token or not hmac.compare_digest(settings.admin_token, x_admin_token or ""):
        raise HTTPException(status_code=403, detail="forbidden")


@app.post("/ingest/{source}", status_code=202)
async def ingest(source: str, request: Request, x_signature: str | None = Header(default=None)):
    if source not in SOURCES:
        raise HTTPException(status_code=404, detail="unknown source")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status_code=413, detail="payload too large")
    verify_signature(body, x_signature)
    received_at = datetime.now(timezone.utc).isoformat()
    msg_id = await queue.enqueue(source, body.decode("utf-8", errors="replace"), received_at)
    return {"queued": msg_id, "received_at": received_at}


@app.get("/health")
async def health():
    await queue.get_redis().ping()
    return {"status": "ok"}


@app.get("/dlq", dependencies=[Depends(require_admin)])
async def dlq_list(count: int = 50):
    rows = await queue.get_redis().xrange(queue.STREAM_DLQ, count=count)
    return [{"id": i, **f} for i, f in rows]


@app.post("/dlq/replay", dependencies=[Depends(require_admin)])
async def dlq_replay(count: int = 50):
    r = queue.get_redis()
    moved = 0
    for msg_id, f in await r.xrange(queue.STREAM_DLQ, count=count):
        await queue.enqueue(f["source"], f["body"], f["received_at"])
        await r.xdel(queue.STREAM_DLQ, msg_id)
        moved += 1
    return {"replayed": moved}
