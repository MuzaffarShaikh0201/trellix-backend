"""Hard-delete projects: drop is_deleted column.

Revision ID: 20260524_0013
Revises: 20260524_0012
Create Date: 2026-05-24

Related tasks are removed via tasks.project_id ON DELETE CASCADE (revision 20260504_0008).
"""

from alembic import op
import sqlalchemy as sa

revision = "20260524_0013"
down_revision = "20260524_0012"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()

    op.drop_index("idx_projects_is_deleted", table_name="projects", schema=schema)
    op.drop_column("projects", "is_deleted", schema=schema)


def downgrade() -> None:
    schema = _table_schema()

    op.add_column(
        "projects",
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        schema=schema,
    )
    op.create_index(
        "idx_projects_is_deleted",
        "projects",
        ["is_deleted"],
        schema=schema,
    )
