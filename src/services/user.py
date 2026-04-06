"""
User services.
These services are used for user-related operations.
"""

from sqlalchemy import select
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import User
from ..utils import get_logger


logger = get_logger(__name__)


async def get_user_by_email(email: str, db_session: AsyncSession) -> User | None:
    """
    Get a user by email.

    # Args:
    - email: str - The email of the user.
    - db_session: AsyncSession - The database session.

    # Returns:
    - User: The user object.
    """

    try:
        result = await db_session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
    except Exception as e:
        logger.exception(f"Error getting user by email: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get user by email. Please try again.",
        )
