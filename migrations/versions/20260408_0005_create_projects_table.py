"""Create projects table and related enums.

Revision ID: 20260408_0005
Revises: 20260407_0004
Create Date: 2026-04-08
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20260408_0005"
down_revision = "20260407_0004"
branch_labels = None
depends_on = None


def _table_schema() -> str | None:
    from src.config import settings

    s = settings.postgres_schema
    return None if not s or s == "public" else s


def upgrade() -> None:
    schema = _table_schema()

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
    project_status_enum.create(op.get_bind(), checkfirst=True)

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
    project_category_enum.create(op.get_bind(), checkfirst=True)

    project_priority_enum = postgresql.ENUM(
        "LOW",
        "MEDIUM",
        "HIGH",
        name="project_priority_enum",
        schema=schema,
    )
    project_priority_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "projects",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
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
        sa.Column(
            "priority",
            postgresql.ENUM(
                "LOW",
                "MEDIUM",
                "HIGH",
                name="project_priority_enum",
                schema=schema,
                create_type=False,
            ),
            nullable=False,
            server_default=sa.text("'MEDIUM'"),
        ),
        sa.Column("start_date", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("color", sa.String(length=32), nullable=True),
        sa.Column("is_favorite", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
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
        schema=schema,
    )
    op.create_index(
        "idx_projects_user_id",
        "projects",
        ["user_id"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )
    op.create_index(
        "idx_projects_status",
        "projects",
        ["status"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )
    op.create_index(
        "idx_projects_category",
        "projects",
        ["category"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )
    op.create_index(
        "idx_projects_is_deleted",
        "projects",
        ["is_deleted"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )
    op.create_index(
        "idx_projects_start_date",
        "projects",
        ["start_date"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )
    op.create_index(
        "idx_projects_due_date",
        "projects",
        ["due_date"],
        unique=False,
        schema=schema,
        postgresql_using="btree",
    )


def downgrade() -> None:
    schema = _table_schema()
    op.drop_index("idx_projects_due_date", table_name="projects", schema=schema)
    op.drop_index("idx_projects_start_date", table_name="projects", schema=schema)
    op.drop_index("idx_projects_is_deleted", table_name="projects", schema=schema)
    op.drop_index("idx_projects_category", table_name="projects", schema=schema)
    op.drop_index("idx_projects_status", table_name="projects", schema=schema)
    op.drop_index("idx_projects_user_id", table_name="projects", schema=schema)
    op.drop_table("projects", schema=schema)

    project_priority_enum = postgresql.ENUM(
        "LOW",
        "MEDIUM",
        "HIGH",
        name="project_priority_enum",
        schema=schema,
    )
    project_priority_enum.drop(op.get_bind(), checkfirst=True)

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
    project_category_enum.drop(op.get_bind(), checkfirst=True)

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
    project_status_enum.drop(op.get_bind(), checkfirst=True)
