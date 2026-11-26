from sqlalchemy import Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.models.enums import ScamType, Verdict


class CheckLog(TimestampMixin, Base):
    """Audit log of every /check call. We store a HASH of the input, never the raw
    message — users paste private SMS text, and we don't need to keep it."""

    __tablename__ = "check_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    api_key_id: Mapped[int | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict, native_enum=False, length=12))
    scam_type: Mapped[ScamType | None] = mapped_column(Enum(ScamType, native_enum=False, length=20))
    latency_ms: Mapped[int] = mapped_column(Integer)
    cached: Mapped[bool] = mapped_column(default=False)
