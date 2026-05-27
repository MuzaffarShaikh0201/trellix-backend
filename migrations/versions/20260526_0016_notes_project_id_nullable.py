"""Make notes.project_id optional for personal notes.

Revision ID: 20260526_0016
Revises: 20260526_0015
Create Date: 2026-05-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260526_0016"
down_revision = "20260526_0015"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()

    op.alter_column(
        "notes",
        "project_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
        schema=schema,
    )


def downgrade() -> None:
    schema = _table_schema()

    op.alter_column(
        "notes",
        "project_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
        schema=schema,
    )
