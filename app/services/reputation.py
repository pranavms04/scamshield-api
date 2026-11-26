import math

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, Report
from app.models.enums import EntityType, ReportStatus
from app.schemas.report import EntityReputation


def reputation_score(verified: int, pending: int) -> float:
    """Saturating curve: 1 verified report ≈ 0.55, 3 ≈ 0.91. Pending reports count a little
    (they're unconfirmed — a rival could file fake reports). Bounded to [0, 1]."""
    evidence = verified + 0.25 * pending
    return round(1 - math.exp(-0.8 * evidence), 3)


async def get_reputation(db: AsyncSession, etype: EntityType, value: str) -> EntityReputation:
    verified = func.count(case((Report.status == ReportStatus.verified, 1)))
    pending = func.count(case((Report.status == ReportStatus.pending, 1)))
    row = (await db.execute(
        select(Entity.id, verified.label("verified"), pending.label("pending"))
        .outerjoin(Report, Report.entity_id == Entity.id)
        .where(Entity.type == etype, Entity.value == value)
        .group_by(Entity.id)
    )).first()
    if row is None:
        return EntityReputation(type=etype, value=value, known=False, verified_reports=0,
                                pending_reports=0, reputation_score=0.0, top_scam_type=None)

    top = (await db.execute(
        select(Report.scam_type).where(Report.entity_id == row.id, Report.status == ReportStatus.verified)
        .group_by(Report.scam_type).order_by(func.count().desc()).limit(1)
    )).scalar_one_or_none()
    return EntityReputation(type=etype, value=value, known=True, verified_reports=row.verified,
                            pending_reports=row.pending,
                            reputation_score=reputation_score(row.verified, row.pending), top_scam_type=top)
