"""Create notes table.

Revision ID: 20260526_0015
Revises: 20260524_0014
Create Date: 2026-05-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260526_0015"
down_revision = "20260524_0014"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()

    op.create_table(
        "notes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column(
            "is_pinned",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema=schema,
    )
    op.create_index(
        "idx_notes_project_id",
        "notes",
        ["project_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_notes_user_id",
        "notes",
        ["user_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_notes_is_pinned",
        "notes",
        ["is_pinned"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_notes_is_deleted",
        "notes",
        ["is_deleted"],
        unique=False,
        schema=schema,
    )


def downgrade() -> None:
    schema = _table_schema()

    op.drop_index("idx_notes_is_deleted", table_name="notes", schema=schema)
    op.drop_index("idx_notes_is_pinned", table_name="notes", schema=schema)
    op.drop_index("idx_notes_user_id", table_name="notes", schema=schema)
    op.drop_index("idx_notes_project_id", table_name="notes", schema=schema)
    op.drop_table("notes", schema=schema)
