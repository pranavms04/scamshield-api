from sqlalchemy import Enum, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import EntityType


class Entity(TimestampMixin, Base):
    """A phone number, UPI ID or URL that someone has reported. Stored NORMALISED so
    '+91 98765-43210' and '9876543210' are the same row."""

    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_entity_type_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[EntityType] = mapped_column(Enum(EntityType, native_enum=False, length=10))
    value: Mapped[str] = mapped_column(String(500))

    reports: Mapped[list["Report"]] = relationship(back_populates="entity")  # noqa: F821
