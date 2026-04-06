"""SQLAlchemy ORM models and PostgreSQL-backed enums."""

import uuid
from datetime import datetime
from uuid import UUID as PythonUUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.schema import MetaData
from sqlalchemy.dialects.postgresql import CITEXT, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..config import settings
from .enums import AuthTypeEnum


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

    user_session: Mapped["UserSession | None"] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="raise",
    )

    __table_args__ = (UniqueConstraint("email", name="unique_users_email"),)


class UserSession(Base, TimestampMixin):
    """Single active session per user; SHA-256 hex of refresh JWT (plaintext not stored)."""

    __tablename__ = "sessions"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    hashed_refresh_token: Mapped[str] = mapped_column(String(64), nullable=False)

    user: Mapped[User] = relationship(
        back_populates="user_session",
        foreign_keys=[user_id],
        lazy="raise",
    )

    __table_args__ = (UniqueConstraint("user_id", name="unique_sessions_user_id"),)
