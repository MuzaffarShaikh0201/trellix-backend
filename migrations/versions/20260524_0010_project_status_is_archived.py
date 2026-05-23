"""Project status enum refresh; add projects.is_archived.

Revision ID: 20260524_0010
Revises: 20260505_0009
Create Date: 2026-05-24

- PLANNED -> PLANNING, ACTIVE -> IN_PROGRESS
- Remove ARCHIVED from status enum (use is_archived flag)
- Add ABANDONED status
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260524_0010"
down_revision = "20260505_0009"
branch_labels = None
depends_on = None

_NEW_STATUS_VALUES = (
    "PLANNING",
    "IN_PROGRESS",
    "ON_HOLD",
    "COMPLETED",
    "ABANDONED",
)

_OLD_STATUS_VALUES = (
    "PLANNED",
    "ACTIVE",
    "ON_HOLD",
    "COMPLETED",
    "ARCHIVED",
)


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def _qualified_table(schema: str | None, name: str) -> str:
    if schema:
        return f'"{schema}"."{name}"'
    return f'"{name}"'


def _status_enum_sql_name(schema: str | None) -> str:
    if schema:
        return f'"{schema}".project_status_enum'
    return "project_status_enum"


def _replace_project_status_enum(
    connection,
    schema: str | None,
    *,
    new_values: tuple[str, ...],
    status_using_sql: str,
    server_default: str,
) -> None:
    projects = _qualified_table(schema, "projects")
    type_prefix = f'"{schema}".' if schema else ""
    enum_name = _status_enum_sql_name(schema)

    connection.execute(
        sa.text(f"ALTER TABLE {projects} ALTER COLUMN status DROP DEFAULT")
    )
    connection.execute(
        sa.text(
            f"ALTER TABLE {projects} ALTER COLUMN status TYPE varchar "
            f"USING status::text"
        )
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_status_enum")
    )

    status_enum = postgresql.ENUM(
        *new_values,
        name="project_status_enum",
        schema=schema,
    )
    status_enum.create(connection, checkfirst=True)

    connection.execute(
        sa.text(
            f"ALTER TABLE {projects} ALTER COLUMN status TYPE {enum_name} "
            f"USING ({status_using_sql})::{enum_name}"
        )
    )
    connection.execute(
        sa.text(
            f"ALTER TABLE {projects} ALTER COLUMN status "
            f"SET DEFAULT '{server_default}'"
        )
    )


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    projects = _qualified_table(schema, "projects")

    op.add_column(
        "projects",
        sa.Column(
            "is_archived",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        schema=schema,
    )

    connection.execute(
        sa.text(
            f"UPDATE {projects} SET is_archived = true WHERE status::text = 'ARCHIVED'"
        )
    )

    _replace_project_status_enum(
        connection,
        schema,
        new_values=_NEW_STATUS_VALUES,
        status_using_sql="""
            CASE status
                WHEN 'PLANNED' THEN 'PLANNING'
                WHEN 'ACTIVE' THEN 'IN_PROGRESS'
                WHEN 'ARCHIVED' THEN 'PLANNING'
                ELSE status
            END
        """.strip(),
        server_default="PLANNING",
    )


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    projects = _qualified_table(schema, "projects")

    connection.execute(
        sa.text(
            f"UPDATE {projects} SET status = 'ARCHIVED' "
            f"WHERE is_archived = true AND status::text != 'ARCHIVED'"
        )
    )

    _replace_project_status_enum(
        connection,
        schema,
        new_values=_OLD_STATUS_VALUES,
        status_using_sql="""
            CASE status
                WHEN 'PLANNING' THEN 'PLANNED'
                WHEN 'IN_PROGRESS' THEN 'ACTIVE'
                WHEN 'ABANDONED' THEN 'ON_HOLD'
                ELSE status
            END
        """.strip(),
        server_default="PLANNED",
    )

    op.drop_column("projects", "is_archived", schema=schema)
