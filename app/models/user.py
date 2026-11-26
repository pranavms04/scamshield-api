from datetime import datetime

from sqlalchemy import DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import IndianState, Role


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=20), default=Role.citizen)
    is_active: Mapped[bool] = mapped_column(default=True)

    # Profile details collected at sign-up (nullable so seeded staff accounts and older rows stay valid)
    full_name: Mapped[str | None] = mapped_column(String(100))
    phone: Mapped[str | None] = mapped_column(String(13), unique=True, index=True)  # normalised +91XXXXXXXXXX
    state: Mapped[IndianState | None] = mapped_column(
        Enum(IndianState, native_enum=False, length=60, values_callable=lambda e: [m.value for m in e])
    )
    city: Mapped[str | None] = mapped_column(String(60))
    terms_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="owner", cascade="all, delete-orphan")  # noqa: F821
    reports: Mapped[list["Report"]] = relationship(back_populates="reporter", foreign_keys="Report.reporter_id")  # noqa: F821
