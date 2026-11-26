from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.session import get_db
from app.models import CheckLog, Entity, Report
from app.models.enums import ReportStatus, Role, Verdict
from app.schemas.analytics import DailyChecks, ScamTypeShare, TrendingEntity

router = APIRouter(prefix="/v1/analytics", tags=["analytics"],
                   dependencies=[Depends(require_role(Role.moderator, Role.admin))])


def since(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


@router.get("/trending", response_model=list[TrendingEntity])
async def trending(days: int = Query(7, ge=1, le=90), limit: int = Query(10, ge=1, le=50),
                   db: AsyncSession = Depends(get_db)):
    """Most-reported scam numbers/UPI IDs/links in the window. Uses a window function (RANK)."""
    n = func.count(Report.id)
    q = (select(Entity.type, Entity.value, n.label("verified_reports"),
                func.rank().over(order_by=n.desc()).label("rank"))
         .join(Report, Report.entity_id == Entity.id)
         .where(Report.status == ReportStatus.verified, Report.created_at >= since(days))
         .group_by(Entity.id, Entity.type, Entity.value)
         .order_by(n.desc(), Entity.value).limit(limit))
    return [TrendingEntity(**r._mapping) for r in (await db.execute(q)).all()]


@router.get("/scam-types", response_model=list[ScamTypeShare])
async def scam_type_share(days: int = Query(30, ge=1, le=365), db: AsyncSession = Depends(get_db)):
    """Share of each scam type. SUM(COUNT(*)) OVER () gives the grand total in the same query."""
    n = func.count(Report.id)
    total = func.sum(n).over()
    q = (select(Report.scam_type, n.label("reports"), (100.0 * n / total).label("share_pct"))
         .where(Report.status == ReportStatus.verified, Report.created_at >= since(days))
         .group_by(Report.scam_type).order_by(n.desc()))
    return [ScamTypeShare(scam_type=r.scam_type, reports=r.reports, share_pct=round(float(r.share_pct), 1))
            for r in (await db.execute(q)).all()]


@router.get("/daily-checks", response_model=list[DailyChecks])
async def daily_checks(days: int = Query(14, ge=1, le=90), db: AsyncSession = Depends(get_db)):
    """API usage per day: volume, high-risk share, average latency."""
    day = func.date(CheckLog.created_at)
    high = func.sum(cast(CheckLog.verdict == Verdict.high_risk, Integer))
    q = (select(day.label("day"), func.count().label("checks"), high.label("high_risk"),
                func.avg(CheckLog.latency_ms).label("avg_latency_ms"))
         .where(CheckLog.created_at >= since(days)).group_by(day).order_by(day))
    out = []
    for r in (await db.execute(q)).all():
        d = r.day if not isinstance(r.day, str) else datetime.fromisoformat(r.day).date()
        out.append(DailyChecks(day=d, checks=r.checks, high_risk=r.high_risk or 0,
                               high_risk_pct=round(100 * (r.high_risk or 0) / r.checks, 1),
                               avg_latency_ms=round(float(r.avg_latency_ms), 1)))
    return out
