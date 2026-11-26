from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, Enum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.config import get_settings
from app.db.base import Base, TimestampMixin
from app.models.enums import ScamType

# Real pgvector column on PostgreSQL; plain JSON list on SQLite (tests / quick local runs).
EmbeddingType = Vector(get_settings().embedding_dim).with_variant(JSON(), "sqlite")


class ScamPattern(TimestampMixin, Base):
    """A verified scam message, embedded so we can find 'messages like this one'."""

    __tablename__ = "scam_patterns"

    id: Mapped[int] = mapped_column(primary_key=True)
    text: Mapped[str] = mapped_column(Text)
    scam_type: Mapped[ScamType] = mapped_column(Enum(ScamType, native_enum=False, length=20))
    embedding: Mapped[list[float]] = mapped_column(EmbeddingType)
    source_report_id: Mapped[int | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"))
