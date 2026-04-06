"""Replace sessions.refresh_token with hashed_refresh_token (SHA-256 hex).

Revision ID: 20260406_0003
Revises: 20260406_0002
Create Date: 2026-04-06

Expect empty ``sessions`` (or truncate) before upgrade; plaintext tokens cannot
be migrated to hashes.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260406_0003"
down_revision = "20260406_0002"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()
    qualified_sessions = "sessions" if not schema else f'"{schema}".sessions'
    op.execute(sa.text(f"TRUNCATE TABLE {qualified_sessions} RESTART IDENTITY CASCADE"))

    op.drop_constraint(
        "unique_sessions_refresh_token",
        "sessions",
        schema=schema,
        type_="unique",
    )
    op.drop_column("sessions", "refresh_token", schema=schema)
    op.add_column(
        "sessions",
        sa.Column("hashed_refresh_token", sa.String(length=64), nullable=False),
        schema=schema,
    )


def downgrade() -> None:
    schema = _table_schema()

    op.drop_column("sessions", "hashed_refresh_token", schema=schema)
    op.add_column(
        "sessions",
        sa.Column("refresh_token", sa.String(length=2048), nullable=False),
        schema=schema,
    )
    op.create_unique_constraint(
        "unique_sessions_refresh_token",
        "sessions",
        ["refresh_token"],
        schema=schema,
    )
