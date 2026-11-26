"""initial schema: users, api keys, entities, reports, check logs, scam patterns (pgvector)

Revision ID: 0001
Revises:
Create Date: 2026-11-26
"""
import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

ts = lambda: sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)  # noqa: E731


def enum(name: str, *values: str, length: int) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=length, create_constraint=True)


SCAM_TYPES = ("kyc_update", "fake_job", "lottery_prize", "upi_collect", "loan_app",
              "impersonation", "investment", "delivery", "other")


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", enum("role", "citizen", "moderator", "admin", length=20), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        ts(),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_created_at", "users", ["created_at"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        ts(),
    )
    op.create_index("ix_api_keys_owner_id", "api_keys", ["owner_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_index("ix_api_keys_created_at", "api_keys", ["created_at"])

    op.create_table(
        "entities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("type", enum("entitytype", "phone", "upi", "url", length=10), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        ts(),
        sa.UniqueConstraint("type", "value", name="uq_entity_type_value"),
    )
    op.create_index("ix_entities_created_at", "entities", ["created_at"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("entity_id", sa.Integer, sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reporter_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("scam_type", enum("scamtype", *SCAM_TYPES, length=20), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("message_text", sa.Text),
        sa.Column("status", enum("reportstatus", "pending", "verified", "rejected", length=10), nullable=False),
        sa.Column("moderator_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("moderator_note", sa.String(500)),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        ts(),
    )
    op.create_index("ix_reports_entity_id", "reports", ["entity_id"])
    op.create_index("ix_reports_reporter_id", "reports", ["reporter_id"])
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_status_created", "reports", ["status", "created_at"])

    op.create_table(
        "check_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("api_key_id", sa.Integer, sa.ForeignKey("api_keys.id", ondelete="SET NULL")),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("verdict", enum("verdict", "likely_safe", "suspicious", "high_risk", length=12), nullable=False),
        sa.Column("scam_type", enum("scamtype_log", *SCAM_TYPES, length=20)),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column("cached", sa.Boolean, nullable=False, server_default=sa.false()),
        ts(),
    )
    for col in ("api_key_id", "user_id", "input_hash", "created_at"):
        op.create_index(f"ix_check_logs_{col}", "check_logs", [col])

    op.create_table(
        "scam_patterns",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("scam_type", enum("scamtype_pattern", *SCAM_TYPES, length=20), nullable=False),
        sa.Column("embedding", pgvector.sqlalchemy.Vector(384), nullable=False),
        sa.Column("source_report_id", sa.Integer, sa.ForeignKey("reports.id", ondelete="SET NULL")),
        ts(),
    )
    op.create_index("ix_scam_patterns_created_at", "scam_patterns", ["created_at"])
    # HNSW = approximate nearest-neighbour index: fast similarity search even with millions of rows
    op.execute("CREATE INDEX ix_scam_patterns_embedding ON scam_patterns USING hnsw (embedding vector_cosine_ops)")


def downgrade() -> None:
    for table in ("scam_patterns", "check_logs", "reports", "entities", "api_keys", "users"):
        op.drop_table(table)
