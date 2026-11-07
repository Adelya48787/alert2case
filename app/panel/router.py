"""Panel API-si (/api/panel/*) və statik fayllar (/panel). Bütün məlumat admin token tələb edir."""

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles

from app.panel import health, queries

STATIC = Path(__file__).parent / "static"

# Panel yalnız öz fayllarını yükləyir: inline script, xarici CDN və iframe qadağandır
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


def build_router(require_admin) -> APIRouter:
    r = APIRouter(prefix="/api/panel", dependencies=[Depends(require_admin)], tags=["panel"])

    @r.get("/alerts")
    async def alerts(
        view: str = Query("open"),
        limit: int = Query(100, ge=1, le=500),
        priority: str | None = Query(None),
        alert_type: str | None = Query(None),
        verdict: str | None = Query(None),
        q: str | None = Query(None, max_length=100),
    ):
        # Filtr dəyərləri bağlı siyahılardan yoxlanılır; axtarış mətni yalnız parametr kimi ötürülür
        for name, value, allowed in (
            ("view", view, queries.VIEWS),
            ("priority", priority, queries.PRIORITIES),
            ("alert_type", alert_type, queries.TYPES),
            ("verdict", verdict, queries.VERDICTS),
        ):
            if value is not None and value not in allowed:
                raise HTTPException(status_code=400, detail=f"{name}: {', '.join(sorted(allowed))}")
        filters = {"priority": priority, "alert_type": alert_type, "verdict": verdict, "q": q}
        return await queries.list_alerts(view, limit, filters)

    @r.get("/alerts/{alert_id}")
    async def alert(alert_id: UUID):
        d = await queries.detail(alert_id)
        if d is None:
            raise HTTPException(status_code=404, detail="alert tapılmadı")
        return d

    @r.get("/stats")
    async def stats():
        return await queries.stats()

    @r.get("/health")
    async def system_health():
        return await health.snapshot()

    @r.get("/rules")
    async def rule_performance():
        return await queries.rules()

    return r


def mount(app) -> None:
    """Statik paneli /panel-də yerləşdirir və təhlükəsizlik başlıqlarını əlavə edir."""
    app.mount("/panel", StaticFiles(directory=STATIC, html=True), name="panel")

    @app.middleware("http")
    async def panel_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(("/panel", "/api/panel")):
            response.headers.update(HEADERS)
        return response
