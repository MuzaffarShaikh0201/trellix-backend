"""Remove access_token from sessions (not persisted; JWT only).

Revision ID: 20260406_0002
Revises: 20260404_0001
Create Date: 2026-04-06
"""

from alembic import op
import sqlalchemy as sa

revision = "20260406_0002"
down_revision = "20260404_0001"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()
    op.drop_column("sessions", "access_token", schema=schema)


def downgrade() -> None:
    schema = _table_schema()
    op.add_column(
        "sessions",
        sa.Column("access_token", sa.String(length=1024), nullable=False),
        schema=schema,
    )
