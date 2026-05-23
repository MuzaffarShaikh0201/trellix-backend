"""Drop project_type column and project_tech_stack table.

Revision ID: 20260524_0012
Revises: 20260524_0011
Create Date: 2026-05-24
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260524_0012"
down_revision = "20260524_0011"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    type_prefix = f'"{schema}".' if schema else ""

    op.drop_index(
        "idx_project_tech_stack_is_deleted",
        table_name="project_tech_stack",
        schema=schema,
    )
    op.drop_index(
        "idx_project_tech_stack_type",
        table_name="project_tech_stack",
        schema=schema,
    )
    op.drop_index(
        "idx_project_tech_stack_project_id",
        table_name="project_tech_stack",
        schema=schema,
    )
    op.drop_table("project_tech_stack", schema=schema)

    op.drop_index("idx_projects_project_type", table_name="projects", schema=schema)
    op.drop_column("projects", "project_type", schema=schema)

    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_tech_stack_type_enum")
    )
    connection.execute(sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_type_enum"))


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    type_prefix = f'"{schema}".' if schema else ""

    project_type_enum = postgresql.ENUM(
        "WEB_APP",
        "MOBILE_APP",
        "API",
        "CLI",
        "LIBRARY",
        "FULL_STACK",
        name="project_type_enum",
        schema=schema,
    )
    project_type_enum.create(connection, checkfirst=True)

    op.add_column(
        "projects",
        sa.Column(
            "project_type",
            postgresql.ENUM(
                "WEB_APP",
                "MOBILE_APP",
                "API",
                "CLI",
                "LIBRARY",
                "FULL_STACK",
                name="project_type_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'WEB_APP'"),
        ),
        schema=schema,
    )
    op.create_index(
        "idx_projects_project_type",
        "projects",
        ["project_type"],
        schema=schema,
    )

    project_tech_stack_type_enum = postgresql.ENUM(
        "BACKEND",
        "FRONTEND",
        "DATABASE",
        "DEVOPS",
        "OTHER",
        name="project_tech_stack_type_enum",
        schema=schema,
    )
    project_tech_stack_type_enum.create(connection, checkfirst=True)

    op.create_table(
        "project_tech_stack",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("project_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "type",
            postgresql.ENUM(
                "BACKEND",
                "FRONTEND",
                "DATABASE",
                "DEVOPS",
                "OTHER",
                name="project_tech_stack_type_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=True,
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
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_project_id",
        "project_tech_stack",
        ["project_id"],
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_type",
        "project_tech_stack",
        ["type"],
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_is_deleted",
        "project_tech_stack",
        ["is_deleted"],
        schema=schema,
    )
