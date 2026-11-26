from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Client, get_client, get_current_user, require_role
from app.db.session import SessionLocal, get_db
from app.models import Entity, Report, ScamPattern, User
from app.models.enums import EntityType, ReportStatus, Role
from app.schemas.common import MAX_DB_ID, entity_value_for, no_control_chars
from app.schemas.report import EntityReputation, ModerationDecision, ReportCreate, ReportRead
from app.services.reputation import get_reputation

router = APIRouter(prefix="/v1", tags=["reports"])


async def get_or_create_entity(db: AsyncSession, etype: EntityType, value: str) -> Entity:
    entity = (await db.execute(select(Entity).where(Entity.type == etype, Entity.value == value))).scalar_one_or_none()
    if entity is None:
        entity = Entity(type=etype, value=value)
        db.add(entity)
        await db.flush()  # get entity.id without committing yet — one transaction for entity + report
    return entity


@router.post("/reports", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
async def create_report(payload: ReportCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # entity_value arrives already validated and normalised by ReportCreate
    entity = await get_or_create_entity(db, payload.entity_type, payload.entity_value)
    already_pending = await db.scalar(select(Report.id).where(
        Report.entity_id == entity.id, Report.reporter_id == user.id, Report.status == ReportStatus.pending))
    if already_pending:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"You already have a pending report (#{already_pending}) for this {payload.entity_type.value}")
    report = Report(entity_id=entity.id, reporter_id=user.id, scam_type=payload.scam_type,
                    description=payload.description, message_text=payload.message_text)
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/reports/mine", response_model=list[ReportRead])
async def my_reports(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
                     skip: int = Query(0, ge=0, le=10_000), limit: int = Query(20, ge=1, le=100)):
    q = select(Report).where(Report.reporter_id == user.id).order_by(Report.id.desc()).offset(skip).limit(limit)
    return (await db.execute(q)).scalars().all()


@router.get("/entities/lookup", response_model=EntityReputation)
async def lookup_entity(type: EntityType, value: Annotated[str, Query(min_length=3, max_length=500)],
                        _: Client = Depends(get_client), db: AsyncSession = Depends(get_db)):
    try:
        normalized = entity_value_for(type, no_control_chars(value.strip()))
    except ValueError as e:
        raise RequestValidationError([{"loc": ("query", "value"), "msg": f"value {e}", "type": "value_error"}]) from None
    return await get_reputation(db, type, normalized)


# --- Moderation -------------------------------------------------------------
moderators = Depends(require_role(Role.moderator, Role.admin))


@router.get("/moderation/reports", response_model=list[ReportRead], tags=["moderation"])
async def moderation_queue(status_: ReportStatus = Query(ReportStatus.pending, alias="status"),
                           skip: int = Query(0, ge=0, le=10_000), limit: int = Query(50, ge=1, le=200),
                           _: User = moderators, db: AsyncSession = Depends(get_db)):
    q = (select(Report).where(Report.status == status_).order_by(Report.created_at, Report.id)
         .offset(skip).limit(limit))
    return (await db.execute(q)).scalars().all()


async def add_pattern_from_report(report_id: int, embedder) -> None:
    """Runs AFTER the response is sent. Opens its own DB session — the request's session is closed by now."""
    async with SessionLocal() as db:
        report = await db.get(Report, report_id)
        if report and report.message_text:
            vec = embedder.embed([report.message_text])[0]
            db.add(ScamPattern(text=report.message_text, scam_type=report.scam_type,
                               embedding=vec, source_report_id=report.id))
            await db.commit()


@router.post("/moderation/reports/{report_id}/decision", response_model=ReportRead, tags=["moderation"])
async def decide(report_id: Annotated[int, Path(ge=1, le=MAX_DB_ID)], decision: ModerationDecision,
                 request: Request, background: BackgroundTasks,
                 mod: User = moderators, db: AsyncSession = Depends(get_db)):
    # SELECT ... FOR UPDATE: locks the row so two moderators can't decide the same report at once
    report = (await db.execute(select(Report).where(Report.id == report_id).with_for_update())).scalar_one_or_none()
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if report.reporter_id == mod.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot moderate your own report")
    if report.status != ReportStatus.pending:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Report already {report.status.value}")
    report.status, report.moderator_id = decision.status, mod.id
    report.moderator_note, report.reviewed_at = decision.note, datetime.now(UTC)
    await db.commit()
    await db.refresh(report)
    if report.status == ReportStatus.verified:
        background.add_task(add_pattern_from_report, report.id, request.app.state.embedder)
    return report
