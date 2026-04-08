"""Align project_status_enum with PENDING and CANCELLED labels.

Revision ID: 20260409_0006
Revises: 20260408_0005
Create Date: 2026-04-09

If revision 20260408_0005 already ran with ``PLANNED`` (and without ``CANCELLED``),
editing that migration file does not re-apply. This revision updates the live
PostgreSQL enum type in place.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260409_0006"
down_revision = "20260408_0005"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def _enum_label_exists(connection, label: str, schema_name: str) -> bool:
    row = connection.execute(
        sa.text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE t.typname = 'project_status_enum'
                  AND e.enumlabel = :label
                  AND n.nspname = :schema_name
            )
            """
        ),
        {"label": label, "schema_name": schema_name},
    ).scalar()
    return bool(row)


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    nsp = schema if schema else "public"

    alter_prefix = (
        f'ALTER TYPE "{schema}".project_status_enum'
        if schema
        else "ALTER TYPE project_status_enum"
    )

    if _enum_label_exists(connection, "PLANNED", nsp):
        connection.execute(sa.text(f"{alter_prefix} RENAME VALUE 'PLANNED' TO 'PENDING'"))

    if not _enum_label_exists(connection, "CANCELLED", nsp):
        connection.execute(sa.text(f"{alter_prefix} ADD VALUE 'CANCELLED'"))


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    nsp = schema if schema else "public"

    alter_prefix = (
        f'ALTER TYPE "{schema}".project_status_enum'
        if schema
        else "ALTER TYPE project_status_enum"
    )

    # Cannot remove CANCELLED from a PostgreSQL enum without recreating the type.

    if _enum_label_exists(connection, "PENDING", nsp) and not _enum_label_exists(
        connection, "PLANNED", nsp
    ):
        connection.execute(sa.text(f"{alter_prefix} RENAME VALUE 'PENDING' TO 'PLANNED'"))
