"""Remove project priority column while keeping enum type.

Revision ID: 20260415_0007
Revises: 20260409_0006
Create Date: 2026-04-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260415_0007"
down_revision = "20260409_0006"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()
    op.drop_column("projects", "priority", schema=schema)


def downgrade() -> None:
    schema = _table_schema()
    op.add_column(
        "projects",
        sa.Column(
            "priority",
            postgresql.ENUM(
                "LOW",
                "MEDIUM",
                "HIGH",
                name="project_priority_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'MEDIUM'"),
        ),
        schema=schema,
    )
