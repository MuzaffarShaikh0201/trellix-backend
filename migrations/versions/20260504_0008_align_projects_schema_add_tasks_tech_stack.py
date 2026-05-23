"""Align projects with current ORM enums/columns; add project_tech_stack and tasks.

Revision ID: 20260504_0008
Revises: 20260415_0007
Create Date: 2026-05-04

**Prerequisite:** All rows must be removed from ``projects`` and any tables that
reference ``projects`` (``project_tech_stack``, ``tasks``) before upgrading.
Otherwise this revision raises with an explicit error. Empty those tables
(or run the cleanup SQL your team uses) before upgrading.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260504_0008"
down_revision = "20260415_0007"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def _qualified_table(schema: str | None, name: str) -> str:
    if schema:
        return f'"{schema}"."{name}"'
    return f'"{name}"'


def _table_exists(connection, schema: str | None, table: str) -> bool:
    if schema:
        row = connection.execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM pg_tables "
                "WHERE schemaname = :schema AND tablename = :table)"
            ),
            {"schema": schema, "table": table},
        ).scalar()
    else:
        row = connection.execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename = :table)"
            ),
            {"table": table},
        ).scalar()
    return bool(row)


def _assert_table_empty(connection, schema: str | None, table: str) -> None:
    if not _table_exists(connection, schema, table):
        return
    qtbl = _qualified_table(schema, table)
    count = connection.execute(sa.text(f"SELECT COUNT(*) FROM {qtbl}")).scalar()
    if count and int(count) > 0:
        raise RuntimeError(
            f"Table {qtbl} must be empty before this migration. "
            "Delete or truncate dependent data first (see migration docstring)."
        )


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()

    _assert_table_empty(connection, schema, "tasks")
    _assert_table_empty(connection, schema, "project_tech_stack")
    _assert_table_empty(connection, schema, "projects")

    if _table_exists(connection, schema, "tasks"):
        op.drop_table("tasks", schema=schema)
    if _table_exists(connection, schema, "project_tech_stack"):
        op.drop_table("project_tech_stack", schema=schema)

    op.drop_index("idx_projects_status", table_name="projects", schema=schema)
    op.drop_index("idx_projects_category", table_name="projects", schema=schema)

    op.execute(
        sa.text(
            f"ALTER TABLE {_qualified_table(schema, 'projects')} "
            "ALTER COLUMN status DROP DEFAULT"
        )
    )
    op.execute(
        sa.text(
            f"ALTER TABLE {_qualified_table(schema, 'projects')} "
            "ALTER COLUMN category DROP DEFAULT"
        )
    )
    op.drop_column("projects", "status", schema=schema)
    op.drop_column("projects", "category", schema=schema)

    type_prefix = f'"{schema}".' if schema else ""
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_status_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_category_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_priority_enum CASCADE")
    )

    project_status_enum = postgresql.ENUM(
        "PLANNED",
        "ACTIVE",
        "ON_HOLD",
        "COMPLETED",
        "ARCHIVED",
        name="project_status_enum",
        schema=schema,
    )
    project_status_enum.create(connection, checkfirst=True)

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

    task_status_enum = postgresql.ENUM(
        "TODO",
        "IN_PROGRESS",
        "IN_REVIEW",
        "DONE",
        "BLOCKED",
        name="task_status_enum",
        schema=schema,
    )
    task_status_enum.create(connection, checkfirst=True)

    task_type_enum = postgresql.ENUM(
        "FEATURE",
        "BUG",
        "REFACTOR",
        "DOCS",
        "TEST",
        "CHORE",
        name="task_type_enum",
        schema=schema,
    )
    task_type_enum.create(connection, checkfirst=True)

    task_priority_enum = postgresql.ENUM(
        "LOW",
        "MEDIUM",
        "HIGH",
        "URGENT",
        name="task_priority_enum",
        schema=schema,
    )
    task_priority_enum.create(connection, checkfirst=True)

    op.add_column(
        "projects",
        sa.Column(
            "status",
            postgresql.ENUM(
                "PLANNED",
                "ACTIVE",
                "ON_HOLD",
                "COMPLETED",
                "ARCHIVED",
                name="project_status_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'PLANNED'"),
        ),
        schema=schema,
    )
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
    op.add_column(
        "projects",
        sa.Column("repo_url", sa.String(length=500), nullable=True),
        schema=schema,
    )
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
        "idx_projects_status",
        "projects",
        ["status"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_projects_category",
        "projects",
        ["category"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_projects_project_type",
        "projects",
        ["project_type"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_projects_stage",
        "projects",
        ["stage"],
        unique=False,
        schema=schema,
    )

    op.create_table(
        "project_tech_stack",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_project_id",
        "project_tech_stack",
        ["project_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_type",
        "project_tech_stack",
        ["type"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_project_tech_stack_is_deleted",
        "project_tech_stack",
        ["is_deleted"],
        unique=False,
        schema=schema,
    )

    op.create_table(
        "tasks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("parent_task_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(
                "TODO",
                "IN_PROGRESS",
                "IN_REVIEW",
                "DONE",
                "BLOCKED",
                name="task_status_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'TODO'"),
        ),
        sa.Column(
            "task_type",
            postgresql.ENUM(
                "FEATURE",
                "BUG",
                "REFACTOR",
                "DOCS",
                "TEST",
                "CHORE",
                name="task_type_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'CHORE'"),
        ),
        sa.Column(
            "priority",
            postgresql.ENUM(
                "LOW",
                "MEDIUM",
                "HIGH",
                "URGENT",
                name="task_priority_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'MEDIUM'"),
        ),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_task_id"], ["tasks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema=schema,
    )
    op.create_index(
        "idx_tasks_project_id",
        "tasks",
        ["project_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_tasks_user_id",
        "tasks",
        ["user_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_tasks_status",
        "tasks",
        ["status"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_tasks_parent_task_id",
        "tasks",
        ["parent_task_id"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_tasks_is_deleted",
        "tasks",
        ["is_deleted"],
        unique=False,
        schema=schema,
    )


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()

    op.drop_index("idx_tasks_is_deleted", table_name="tasks", schema=schema)
    op.drop_index("idx_tasks_parent_task_id", table_name="tasks", schema=schema)
    op.drop_index("idx_tasks_status", table_name="tasks", schema=schema)
    op.drop_index("idx_tasks_user_id", table_name="tasks", schema=schema)
    op.drop_index("idx_tasks_project_id", table_name="tasks", schema=schema)
    op.drop_table("tasks", schema=schema)

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

    op.drop_index("idx_projects_stage", table_name="projects", schema=schema)
    op.drop_index("idx_projects_project_type", table_name="projects", schema=schema)
    op.drop_index("idx_projects_category", table_name="projects", schema=schema)
    op.drop_index("idx_projects_status", table_name="projects", schema=schema)

    op.drop_column("projects", "stage", schema=schema)
    op.drop_column("projects", "project_type", schema=schema)
    op.drop_column("projects", "repo_url", schema=schema)
    op.drop_column("projects", "category", schema=schema)
    op.drop_column("projects", "status", schema=schema)

    type_prefix = f'"{schema}".' if schema else ""
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}task_priority_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}task_type_enum CASCADE")
    )
    connection.execute(sa.text(f"DROP TYPE IF EXISTS {type_prefix}task_status_enum CASCADE"))
    connection.execute(
        sa.text(
            f"DROP TYPE IF EXISTS {type_prefix}project_tech_stack_type_enum CASCADE"
        )
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_stage_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_type_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_category_enum CASCADE")
    )
    connection.execute(
        sa.text(f"DROP TYPE IF EXISTS {type_prefix}project_status_enum CASCADE")
    )

    project_status_enum = postgresql.ENUM(
        "ACTIVE",
        "PENDING",
        "ON_HOLD",
        "COMPLETED",
        "CANCELLED",
        "ARCHIVED",
        name="project_status_enum",
        schema=schema,
    )
    project_status_enum.create(connection, checkfirst=True)

    project_category_enum = postgresql.ENUM(
        "WORK",
        "PERSONAL",
        "LEARNING",
        "HEALTH",
        "FINANCE",
        "SIDE_PROJECT",
        "CREATIVE",
        "TRAVEL",
        "HOME",
        "OTHER",
        name="project_category_enum",
        schema=schema,
    )
    project_category_enum.create(connection, checkfirst=True)

    op.add_column(
        "projects",
        sa.Column(
            "status",
            postgresql.ENUM(
                "ACTIVE",
                "PENDING",
                "ON_HOLD",
                "COMPLETED",
                "CANCELLED",
                "ARCHIVED",
                name="project_status_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'ACTIVE'"),
        ),
        schema=schema,
    )
    op.add_column(
        "projects",
        sa.Column(
            "category",
            postgresql.ENUM(
                "WORK",
                "PERSONAL",
                "LEARNING",
                "HEALTH",
                "FINANCE",
                "SIDE_PROJECT",
                "CREATIVE",
                "TRAVEL",
                "HOME",
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
        "idx_projects_status",
        "projects",
        ["status"],
        unique=False,
        schema=schema,
    )
    op.create_index(
        "idx_projects_category",
        "projects",
        ["category"],
        unique=False,
        schema=schema,
    )
