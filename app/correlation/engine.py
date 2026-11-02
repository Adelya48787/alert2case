"""Phase 4 müvəqqəti versiyası: korrelyasiya hələ yoxdur. Task 5.3 bu faylı tam versiya ilə əvəz edir."""

from app.audit.log import audit  # noqa: F401  (5.3-də istifadə olunur)
from app.case.base import CaseRef
from app.schemas.alert import NormalizedAlert


async def correlate(alert: NormalizedAlert) -> CaseRef | None:
    return None


async def index_case(alert: NormalizedAlert, ref: CaseRef) -> None:
    return None
