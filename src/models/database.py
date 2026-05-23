"""SQLAlchemy ORM models and PostgreSQL-backed enums."""

import uuid
from datetime import date, datetime
from uuid import UUID as PythonUUID

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.schema import MetaData
from sqlalchemy.dialects.postgresql import CITEXT, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..config import settings
from .enums import (
    AuthTypeEnum,
    ProjectStageEnum,
    ProjectStatusEnum,
    ProjectTechStackTypeEnum,
    ProjectTypeEnum,
    TaskDomainEnum,
    TaskPriorityEnum,
    TaskStatusEnum,
    TaskTypeEnum,
)


_ORM_SCHEMA = (
    settings.postgres_schema
    if settings.postgres_schema and settings.postgres_schema != "public"
    else None
)


class Base(DeclarativeBase):
    """Declarative base with schema-bound metadata."""

    __abstract__ = True
    metadata = MetaData(schema=_ORM_SCHEMA)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(id={getattr(self, 'id', None)})>"


class TimestampMixin:
    """Created/updated timestamps with server-side defaults."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
        server_onupdate=func.current_timestamp(),
        nullable=False,
    )


class User(Base, TimestampMixin):
    """Application user."""

    __tablename__ = "users"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    first_name: Mapped[str] = mapped_column(String(32), nullable=False)
    last_name: Mapped[str] = mapped_column(String(32), nullable=False)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    auth_type: Mapped[AuthTypeEnum] = mapped_column(
        Enum(
            AuthTypeEnum,
            name="auth_type_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=AuthTypeEnum.EMAIL,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_logged_in: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
        nullable=False,
    )

    # Relationships
    projects: Mapped[list["Project"]] = relationship(
        back_populates="user",
        lazy="raise",
    )
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="user",
        lazy="raise",
    )

    # Indexes, constraints, and unique constraints
    __table_args__ = (
        Index("idx_users_email", "email"),
        UniqueConstraint("email", name="unique_users_email"),
    )


class Project(Base, TimestampMixin):
    """User-owned project."""

    __tablename__ = "projects"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[ProjectStatusEnum] = mapped_column(
        Enum(
            ProjectStatusEnum,
            name="project_status_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectStatusEnum.PLANNED,
        nullable=False,
    )
    project_type: Mapped[ProjectTypeEnum] = mapped_column(
        Enum(
            ProjectTypeEnum,
            name="project_type_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectTypeEnum.WEB_APP,
        nullable=False,
    )
    stage: Mapped[ProjectStageEnum] = mapped_column(
        Enum(
            ProjectStageEnum,
            name="project_stage_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectStageEnum.IDEA,
        nullable=False,
    )
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    color: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="projects", lazy="raise")
    tech_stack_entries: Mapped[list["ProjectTechStack"]] = relationship(
        back_populates="project",
        lazy="raise",
    )
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="project",
        lazy="raise",
    )

    # Indexes, constraints, and unique constraints
    __table_args__ = (
        Index("idx_projects_user_id", "user_id"),
        Index("idx_projects_status", "status"),
        Index("idx_projects_project_type", "project_type"),
        Index("idx_projects_stage", "stage"),
        Index("idx_projects_is_deleted", "is_deleted"),
        Index("idx_projects_start_date", "start_date"),
        Index("idx_projects_due_date", "due_date"),
    )


class ProjectTechStack(Base, TimestampMixin):
    """Technology stack entries for a software project."""

    __tablename__ = "project_tech_stack"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[ProjectTechStackTypeEnum | None] = mapped_column(
        Enum(
            ProjectTechStackTypeEnum,
            name="project_tech_stack_type_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=True,
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship(
        back_populates="tech_stack_entries",
        lazy="raise",
    )

    __table_args__ = (
        Index("idx_project_tech_stack_project_id", "project_id"),
        Index("idx_project_tech_stack_type", "type"),
        Index("idx_project_tech_stack_is_deleted", "is_deleted"),
    )


class Task(Base, TimestampMixin):
    """Project task with hierarchy and scheduling support."""

    __tablename__ = "tasks"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id"),
        nullable=False,
    )
    user_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    parent_task_id: Mapped[PythonUUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tasks.id"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    status: Mapped[TaskStatusEnum] = mapped_column(
        Enum(
            TaskStatusEnum,
            name="task_status_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=TaskStatusEnum.TODO,
        nullable=False,
    )
    task_type: Mapped[TaskTypeEnum] = mapped_column(
        Enum(
            TaskTypeEnum,
            name="task_type_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=TaskTypeEnum.CHORE,
        nullable=False,
    )
    priority: Mapped[TaskPriorityEnum] = mapped_column(
        Enum(
            TaskPriorityEnum,
            name="task_priority_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=TaskPriorityEnum.MEDIUM,
        nullable=False,
    )
    domain: Mapped[TaskDomainEnum] = mapped_column(
        Enum(
            TaskDomainEnum,
            name="task_domain_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=TaskDomainEnum.OTHER,
        nullable=False,
    )
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship(back_populates="tasks", lazy="raise")
    user: Mapped["User"] = relationship(back_populates="tasks", lazy="raise")
    parent_task: Mapped["Task | None"] = relationship(
        "Task",
        remote_side="Task.id",
        back_populates="subtasks",
        lazy="raise",
    )
    subtasks: Mapped[list["Task"]] = relationship(
        "Task",
        back_populates="parent_task",
        lazy="raise",
    )

    __table_args__ = (
        Index("idx_tasks_project_id", "project_id"),
        Index("idx_tasks_user_id", "user_id"),
        Index("idx_tasks_status", "status"),
        Index("idx_tasks_domain", "domain"),
        Index("idx_tasks_parent_task_id", "parent_task_id"),
        Index("idx_tasks_is_deleted", "is_deleted"),
    )
