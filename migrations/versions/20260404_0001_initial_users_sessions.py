"""Initial users and sessions tables.

Revision ID: 20260404_0001
Revises:
Create Date: 2026-04-04

Requires: PostgreSQL (gen_random_uuid). Creates citext extension if missing.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260404_0001"
down_revision = None
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    op.execute(sa.text("CREATE EXTENSION IF NOT EXISTS citext"))

    schema = _table_schema()
    if schema:
        op.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))

    auth_enum = postgresql.ENUM(
        "email",
        name="auth_type_enum",
        schema=schema,
    )
    auth_enum.create(op.get_bind(), checkfirst=True)

    auth_enum_no_ddl = postgresql.ENUM(
        "email",
        name="auth_type_enum",
        schema=schema,
        create_type=False,
    )

    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("first_name", sa.String(32), nullable=False),
        sa.Column("last_name", sa.String(32), nullable=False),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("auth_type", auth_enum_no_ddl, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column(
            "last_logged_in",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="unique_users_email"),
        schema=schema,
    )

    op.create_table(
        "sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("access_token", sa.String(1024), nullable=False),
        sa.Column("refresh_token", sa.String(2048), nullable=False),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="unique_sessions_user_id"),
        sa.UniqueConstraint("refresh_token", name="unique_sessions_refresh_token"),
        schema=schema,
    )
    op.create_index(
        "idx_users_email",
        "users",
        ["email"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )


def downgrade() -> None:
    schema = _table_schema()

    op.drop_index("idx_users_email", table_name="users", schema=schema)
    op.drop_table("sessions", schema=schema)
    op.drop_table("users", schema=schema)

    auth_enum = postgresql.ENUM(
        "email",
        name="auth_type_enum",
        schema=schema,
    )
    auth_enum.drop(op.get_bind(), checkfirst=True)
