"""user profile fields: full name, phone, state, city, terms acceptance

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-26
"""
import sqlalchemy as sa
from alembic import op

from app.models.enums import IndianState

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(100)))
    op.add_column("users", sa.Column("phone", sa.String(13)))
    op.add_column("users", sa.Column("state", sa.Enum(*[s.value for s in IndianState], name="indianstate",
                                                       native_enum=False, length=60, create_constraint=True)))
    op.add_column("users", sa.Column("city", sa.String(60)))
    op.add_column("users", sa.Column("terms_accepted_at", sa.DateTime(timezone=True)))
    op.create_index("ix_users_phone", "users", ["phone"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_phone", table_name="users")
    for col in ("terms_accepted_at", "city", "state", "phone", "full_name"):
        op.drop_column("users", col)
