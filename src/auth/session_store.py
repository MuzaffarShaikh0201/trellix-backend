from pydantic import UUID4
from redis.asyncio import Redis

from ..config import settings
from ..models.auth import SessionData
from ..db.redis_client import redis_manager


class SessionStore:
    def __init__(self, redis_client: Redis) -> None:
        self.redis_client = redis_client

    async def get_user_session(self, user_id: UUID4) -> UUID4 | None:
        return await self.redis_client.get(f"user_session:{str(user_id)}")

    async def set_user_session(self, user_id: UUID4, session_id: UUID4) -> None:
        await self.redis_client.set(
            f"user_session:{str(user_id)}",
            str(session_id),
            ex=settings.jwt_refresh_time * 60 * 60,
        )

    async def delete_user_session(self, user_id: UUID4) -> None:
        await self.redis_client.delete(f"user_session:{str(user_id)}")

    async def get_session(self, session_id: UUID4) -> SessionData | None:
        session_data = await self.redis_client.get(f"session:{str(session_id)}")
        if not session_data:
            return None
        return SessionData.model_validate_json(session_data)

    async def set_session(self, session_data: SessionData) -> None:
        await self.redis_client.set(
            f"session:{str(session_data.session_id)}",
            session_data.model_dump_json(),
            ex=settings.jwt_refresh_time * 60 * 60,
        )

    async def delete_session(self, session_id: UUID4) -> None:
        await self.redis_client.delete(f"session:{str(session_id)}")


def get_session_store() -> SessionStore:
    return SessionStore(redis_manager.client)
