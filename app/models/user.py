from sqlalchemy import Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import Role


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=20), default=Role.citizen)
    is_active: Mapped[bool] = mapped_column(default=True)

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="owner", cascade="all, delete-orphan")  # noqa: F821
    reports: Mapped[list["Report"]] = relationship(back_populates="reporter", foreign_keys="Report.reporter_id")  # noqa: F821
