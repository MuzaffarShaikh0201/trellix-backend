"""Drop projects.category; add tasks.domain (task_domain_enum).

Revision ID: 20260505_0009
Revises: 20260504_0008
Create Date: 2026-05-05

Existing task rows receive domain = OTHER (server default). No mapping from
former project categories.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260505_0009"
down_revision = "20260504_0008"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()

    task_domain_enum = postgresql.ENUM(
        "BACKEND",
        "FRONTEND",
        "DEVOPS",
        "DATABASE",
        "TESTING",
        "INFRA",
        "OTHER",
        name="task_domain_enum",
        schema=schema,
    )
    task_domain_enum.create(connection, checkfirst=True)

    op.add_column(
        "tasks",
        sa.Column(
            "domain",
            postgresql.ENUM(
                "BACKEND",
                "FRONTEND",
                "DEVOPS",
                "DATABASE",
                "TESTING",
                "INFRA",
                "OTHER",
                name="task_domain_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'OTHER'"),
        ),
        schema=schema,
    )
    op.create_index(
        "idx_tasks_domain",
        "tasks",
        ["domain"],
        unique=False,
        schema=schema,
    )

    op.drop_index("idx_projects_category", table_name="projects", schema=schema)
    op.drop_column("projects", "category", schema=schema)

    type_prefix = f'"{schema}".' if schema else ""
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_category_enum")
    )


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()
    type_prefix = f'"{schema}".' if schema else ""

    op.drop_index("idx_tasks_domain", table_name="tasks", schema=schema)
    op.drop_column("tasks", "domain", schema=schema)
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}task_domain_enum")
    )

    project_category_enum = postgresql.ENUM(
        "BACKEND",
        "FRONTEND",
        "FULL_STACK",
        "MOBILE",
        "DEVOPS",
        "AI_ML",
        "OPEN_SOURCE",
        "TOOLS",
        "EXPERIMENTAL",
        "OTHER",
        name="project_category_enum",
        schema=schema,
    )
    project_category_enum.create(connection, checkfirst=True)

    op.add_column(
        "projects",
        sa.Column(
            "category",
            postgresql.ENUM(
                "BACKEND",
                "FRONTEND",
                "FULL_STACK",
                "MOBILE",
                "DEVOPS",
                "AI_ML",
                "OPEN_SOURCE",
                "TOOLS",
                "EXPERIMENTAL",
                "OTHER",
                name="project_category_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'OTHER'"),
        ),
        schema=schema,
    )
    op.create_index(
        "idx_projects_category",
        "projects",
        ["category"],
        unique=False,
        schema=schema,
    )
