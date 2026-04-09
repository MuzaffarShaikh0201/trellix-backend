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
    ProjectCategoryEnum,
    ProjectPriorityEnum,
    ProjectStatusEnum,
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
        cascade="all, delete-orphan",
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
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    status: Mapped[ProjectStatusEnum] = mapped_column(
        Enum(
            ProjectStatusEnum,
            name="project_status_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectStatusEnum.ACTIVE,
        nullable=False,
    )
    category: Mapped[ProjectCategoryEnum] = mapped_column(
        Enum(
            ProjectCategoryEnum,
            name="project_category_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectCategoryEnum.OTHER,
        nullable=False,
    )
    priority: Mapped[ProjectPriorityEnum] = mapped_column(
        Enum(
            ProjectPriorityEnum,
            name="project_priority_enum",
            schema=_ORM_SCHEMA,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        default=ProjectPriorityEnum.MEDIUM,
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

    # Indexes, constraints, and unique constraints
    __table_args__ = (
        Index("idx_projects_user_id", "user_id"),
        Index("idx_projects_status", "status"),
        Index("idx_projects_category", "category"),
        Index("idx_projects_is_deleted", "is_deleted"),
        Index("idx_projects_start_date", "start_date"),
        Index("idx_projects_due_date", "due_date"),
    )
