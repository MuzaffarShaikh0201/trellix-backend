"""Drop project stage; rename due_date to end_date; drop completed_at.

Revision ID: 20260524_0011
Revises: 20260524_0010
Create Date: 2026-05-24
"""

from alembic import op
import sqlalchemy as sa

revision = "20260524_0011"
down_revision = "20260524_0010"
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

    op.drop_index("idx_projects_stage", table_name="projects", schema=schema)
    op.drop_index("idx_projects_due_date", table_name="projects", schema=schema)

    op.drop_column("projects", "stage", schema=schema)
    op.drop_column("projects", "completed_at", schema=schema)

    op.alter_column(
        "projects",
        "due_date",
        new_column_name="end_date",
        schema=schema,
    )

    op.create_index(
        "idx_projects_end_date",
        "projects",
        ["end_date"],
        schema=schema,
    )

    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_stage_enum")
    )


def downgrade() -> None:
    from sqlalchemy.dialects import postgresql

    connection = op.get_bind()
    schema = _table_schema()
    type_prefix = f'"{schema}".' if schema else ""

    op.drop_index("idx_projects_end_date", table_name="projects", schema=schema)

    op.alter_column(
        "projects",
        "end_date",
        new_column_name="due_date",
        schema=schema,
    )

    op.add_column(
        "projects",
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        schema=schema,
    )

    project_stage_enum = postgresql.ENUM(
        "IDEA",
        "DEVELOPMENT",
        "TESTING",
        "PRODUCTION",
        "MAINTENANCE",
        "DEPRECATED",
        name="project_stage_enum",
        schema=schema,
    )
    project_stage_enum.create(connection, checkfirst=True)

    op.add_column(
        "projects",
        sa.Column(
            "stage",
            postgresql.ENUM(
                "IDEA",
                "DEVELOPMENT",
                "TESTING",
                "PRODUCTION",
                "MAINTENANCE",
                "DEPRECATED",
                name="project_stage_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'IDEA'"),
        ),
        schema=schema,
    )

    op.create_index(
        "idx_projects_stage",
        "projects",
        ["stage"],
        schema=schema,
    )
    op.create_index(
        "idx_projects_due_date",
        "projects",
        ["due_date"],
        schema=schema,
    )
