import hashlib

import bcrypt
from sqlalchemy import select
from pydantic import SecretStr
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from ..utils import get_logger
from ..models import AuthTypeEnum, User


logger = get_logger(__name__)


def _password_digest_for_bcrypt(password: str) -> bytes:
    """
    SHA-256 digest of the password UTF-8 bytes (32 bytes).

    Bcrypt only accepts inputs up to 72 bytes; validated passwords can still
    exceed that in UTF-8 (e.g. multi-byte characters). Hashing first keeps
    storage compatible with bcrypt for any string the API validators allow.

    # Args:
    - password: str - The password to hash.

    # Returns:
    - bytes - The SHA-256 digest of the password UTF-8 bytes (32 bytes).
    """

    return hashlib.sha256(password.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    # Args:
    - password: str - The password to hash.

    # Returns:
    - str - The hashed password.
    """
    return bcrypt.hashpw(
        _password_digest_for_bcrypt(password), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password.

    # Args:
    - password: str - The password to verify.
    - hashed_password: str - The hashed password to verify against.

    # Returns:
    - bool - True if the password is verified, False otherwise.
    """
    return bcrypt.checkpw(
        _password_digest_for_bcrypt(password), hashed_password.encode("utf-8")
    )


async def user_exists(email: str, db_session: AsyncSession) -> bool:
    """
    Check if a user exists in the database.

    # Args:
    - email: str - The email of the user.
    - db_session: AsyncSession - The database session.

    # Returns:
    - bool - True if the user exists, False otherwise.

    # Raises:
    - HTTPException: If the user check fails.
    """

    try:
        result = await db_session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none() is not None
    except Exception as e:
        logger.exception(f"Error checking if user exists: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not verify email availability. Please try again.",
        )


async def create_user(
    email: str,
    first_name: str,
    last_name: str,
    password: SecretStr,
    db_session: AsyncSession,
) -> User:
    """
    Create a new user in the database.

    # Args:
    - email: str - The email of the user.
    - first_name: str - The first name of the user.
    - last_name: str - The last name of the user.
    - password: SecretStr - The password of the user.
    - db_session: AsyncSession - The database session.

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
            hashed_password=hash_password(password.get_secret_value()),
            auth_type=AuthTypeEnum.EMAIL,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        return user
    except Exception as e:
        await db_session.rollback()
        logger.exception(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create your account. Please try again.",
        )
