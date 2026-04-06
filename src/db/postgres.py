"""
PostgreSQL database connection and session management.
Uses async SQLAlchemy with asyncpg driver.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import settings


class DatabaseManager:
    """Database connection manager."""

    def __init__(self):
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    def init(self) -> None:
        """Initialize database engine and session factory."""
        self._engine = create_async_engine(
            settings.postgres_url,
            echo=settings.log_level == "DEBUG",
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

    async def close(self) -> None:
        """Close database connections."""
        if self._engine:
            await self._engine.dispose()

    @asynccontextmanager
    async def session_scope(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Transactional scope for database operations: rollback on exception, close on exit.

        Usage:
            async with db_manager.session_scope() as session:
                result = await session.execute(query)
                await session.commit()
        """
        if self._session_factory is None:
            raise RuntimeError("DatabaseManager not initialized. Call init() first.")

        async with self._session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    @property
    def engine(self) -> AsyncEngine:
        """Get the database engine."""
        if self._engine is None:
            raise RuntimeError("DatabaseManager not initialized. Call init() first.")
        return self._engine

    async def ping(self) -> bool:
        """
        Ping the database to check connection.

        Returns:
            True if connected, False otherwise
        """

        try:
            async with self.session_scope() as session:
                await session.execute(text("SELECT 1"))
                return True
        except Exception:
            return False


db_manager = DatabaseManager()


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency: yields one ``AsyncSession`` for the request (via ``session_scope``).

    Usage:
        async def endpoint(db: AsyncSession = Depends(get_db_session)):
            ...
    """
    async with db_manager.session_scope() as session:
        yield session
