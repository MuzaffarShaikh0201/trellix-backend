"""Hard-delete tasks: drop is_deleted; parent_task_id ON DELETE CASCADE.

Revision ID: 20260524_0014
Revises: 20260524_0013
Create Date: 2026-05-24

Deleting a task permanently removes its subtasks via parent_task_id CASCADE.
"""

from alembic import op
import sqlalchemy as sa

revision = "20260524_0014"
down_revision = "20260524_0013"
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


def _fk_name(connection, schema: str | None, table: str, column: str) -> str | None:
    nsp = schema if schema else "public"
    row = connection.execute(
        sa.text(
            """
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
            WHERE c.contype = 'f'
              AND t.relname = :table
              AND n.nspname = :nsp
              AND a.attname = :column
            LIMIT 1
            """
        ),
        {"table": table, "nsp": nsp, "column": column},
    ).scalar()
    return row


def _set_parent_task_cascade(connection, schema: str | None) -> None:
    tasks = _qualified_table(schema, "tasks")
    fk = _fk_name(connection, schema, "tasks", "parent_task_id")
    if fk:
        connection.execute(sa.text(f'ALTER TABLE {tasks} DROP CONSTRAINT "{fk}"'))
    connection.execute(
        sa.text(
            f"""
            ALTER TABLE {tasks}
            ADD CONSTRAINT tasks_parent_task_id_fkey
            FOREIGN KEY (parent_task_id) REFERENCES {tasks}(id)
            ON DELETE CASCADE
            """
        )
    )


def _set_parent_task_set_null(connection, schema: str | None) -> None:
    tasks = _qualified_table(schema, "tasks")
    fk = _fk_name(connection, schema, "tasks", "parent_task_id")
    if fk:
        connection.execute(sa.text(f'ALTER TABLE {tasks} DROP CONSTRAINT "{fk}"'))
    connection.execute(
        sa.text(
            f"""
            ALTER TABLE {tasks}
            ADD CONSTRAINT tasks_parent_task_id_fkey
            FOREIGN KEY (parent_task_id) REFERENCES {tasks}(id)
            ON DELETE SET NULL
            """
        )
    )


def upgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()

    op.drop_index("idx_tasks_is_deleted", table_name="tasks", schema=schema)
    op.drop_column("tasks", "is_deleted", schema=schema)
    _set_parent_task_cascade(connection, schema)


def downgrade() -> None:
    connection = op.get_bind()
    schema = _table_schema()

    _set_parent_task_set_null(connection, schema)

    op.add_column(
        "tasks",
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        schema=schema,
    )
    op.create_index(
        "idx_tasks_is_deleted",
        "tasks",
        ["is_deleted"],
        schema=schema,
    )
