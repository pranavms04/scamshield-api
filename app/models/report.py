from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import ReportStatus, ScamType


class Report(TimestampMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_status_created", "status", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    scam_type: Mapped[ScamType] = mapped_column(Enum(ScamType, native_enum=False, length=20))
    description: Mapped[str] = mapped_column(Text)
    message_text: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, native_enum=False, length=10), default=ReportStatus.pending
    )
    moderator_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    moderator_note: Mapped[str | None] = mapped_column(String(500))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    entity: Mapped["Entity"] = relationship(back_populates="reports")  # noqa: F821
    reporter: Mapped["User"] = relationship(back_populates="reports", foreign_keys=[reporter_id])  # noqa: F821
