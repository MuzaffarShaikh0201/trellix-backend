"""
User services.
These services are used for user-related operations.
"""

from sqlalchemy import select
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuthTypeEnum, User
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

    # Raises:
    - HTTPException: If the user retrieval fails.
    """

    try:
        result = await db_session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
    except Exception as e:
        logger.error(f"Error getting user by email: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get user by email. Please try again.",
        )


async def create_user(
    db_session: AsyncSession,
    email: str,
    first_name: str,
    last_name: str,
    hashed_password: str,
    auth_type: AuthTypeEnum = AuthTypeEnum.EMAIL,
) -> User:
    """
    Create a new user in the database.

    # Args:
    - db_session: AsyncSession - The database session.
    - email: str - The email of the user.
    - first_name: str - The first name of the user.
    - last_name: str - The last name of the user.
    - hashed_password: str - The hashed password of the user.
    - auth_type: AuthTypeEnum - The authentication type of the user (default: EMAIL).

    # Returns:
    - User: The created user.

    # Raises:
    - HTTPException: If the user creation fails.
    """

    try:
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            hashed_password=hashed_password,
            auth_type=auth_type,
        )
        db_session.add(user)
        await db_session.commit()

        logger.info(f"User created successfully: {user.id}")
        return user
    except Exception as e:
        await db_session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create user. Please try again.",
        )
