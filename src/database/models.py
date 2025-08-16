import uuid
from sqlalchemy import (
    Column,
    Index,
    String,
    Boolean,
    DateTime,
    func,
    Enum,
    UniqueConstraint,
    ForeignKey,
)
from uuid import UUID as PythonUUID
from sqlalchemy.schema import MetaData
from sqlalchemy.dialects.postgresql import CITEXT, UUID
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)

from ..core.config import settings
from ..database.enums import AuthTypeEnum


class Base(DeclarativeBase):
    __abstract__ = True
    metadata = MetaData(schema=settings.DB_SCHEMA)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(id={getattr(self, 'id', None)})>"


class TimestampMixin:
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.current_timestamp(), nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.current_timestamp(), nullable=False
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    first_name: Mapped[str] = mapped_column(String(32), nullable=False)
    last_name: Mapped[str] = mapped_column(String(32), nullable=False)
    email: Mapped[str] = mapped_column(CITEXT, unique=True, index=True, nullable=False)
    auth_type: Mapped[AuthTypeEnum] = mapped_column(
        Enum(AuthTypeEnum, name="auth_type_enum", schema=settings.DB_SCHEMA),
        default=AuthTypeEnum.EMAIL,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=True)

    last_logged_in: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.current_timestamp(), nullable=False
    )

    user_session: Mapped["UserSession"] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="raise"
    )

    # Constraints
    __table_args__ = (
        UniqueConstraint("email", name="unique_users_email"),
        Index("idx_users_email", "email"),
    )


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[PythonUUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    access_token: Mapped[str] = Column(String(1024), nullable=False)
    refresh_token: Mapped[str] = Column(String(2048), nullable=False)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.current_timestamp(), nullable=False
    )

    user: Mapped["User"] = relationship(
        back_populates="user_session",
        foreign_keys=[user_id],
        lazy="raise",
    )

    # Constraints
    __table_args__ = (
        UniqueConstraint("user_id", name="unique_sessions_user_id"),
        UniqueConstraint("refresh_token", name="unique_sessions_refresh_token"),
        Index("idx_sessions_user_id", "user_id"),
    )
