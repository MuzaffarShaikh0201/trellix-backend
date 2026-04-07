"""
Authentication services.
These services are used for authentication-related operations.
"""

import hmac
import bcrypt
import hashlib
from jose import jwt
from uuid import UUID
from sqlalchemy import select
from pydantic import SecretStr
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from ..config import settings
from ..utils import get_logger
from ..models import AuthTypeEnum, User, UserSession


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

        return user
    except Exception as e:
        await db_session.rollback()
        logger.exception(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create your account. Please try again.",
        )


def generate_jwt_tokens(user_id: UUID, session_id: UUID) -> tuple[str, str]:
    """
    Generate JWT tokens for a user.

    # Args:
    - user_id: UUID - The ID of the user.
    - session_id: UUID - The ID of the session.

    # Returns:
    - tuple[str, str]: A tuple containing the access token and refresh token.

    # Raises:
    - HTTPException: If the JWT token generation fails.
    """
    try:
        access_token_exp = datetime.now(timezone.utc) + timedelta(
            minutes=settings.jwt_expiration_time
        )
        access_token_claims = {
            "sub": str(user_id),
            "jti": str(session_id),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(access_token_exp.timestamp()),
        }
        access_token = jwt.encode(
            claims=access_token_claims,
            key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )

        refresh_token_exp = datetime.now(timezone.utc) + timedelta(
            hours=settings.jwt_refresh_time
        )
        refresh_token_claims = {
            "sub": str(user_id),
            "jti": str(session_id),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(refresh_token_exp.timestamp()),
        }
        refresh_token = jwt.encode(
            claims=refresh_token_claims,
            key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
            access_token=access_token,
        )

        return access_token, refresh_token
    except Exception as e:
        logger.exception(f"Error generating JWT tokens: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not generate JWT tokens. Please try again.",
        )


def verify_password(password: SecretStr, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password using bcrypt.

    # Args:
    - password: SecretStr - The password to verify.
    - hashed_password: str - The hashed password to verify against.

    # Returns:
    - bool - True if the password is verified, False otherwise.

    # Raises:
    - HTTPException: If the password verification fails.
    """
    try:
        return bcrypt.checkpw(
            _password_digest_for_bcrypt(password.get_secret_value()),
            hashed_password.encode("utf-8"),
        )
    except Exception as e:
        logger.exception(f"Error verifying password: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not verify password. Please try again.",
        )


def hash_refresh_token(refresh_token: str) -> str:
    """
    Hash a refresh token using SHA-256.

    # Args:
    - refresh_token: str - The refresh token to hash.

    # Returns:
    - str: The hashed refresh token.
    """

    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def verify_refresh_token_hash(token: str, stored_hash: str) -> bool:
    """
    Verify a refresh token against a hashed refresh token using SHA-256.

    # Args:
    - token: str - The refresh token to verify.
    - stored_hash: str - The hashed refresh token to verify against.

    # Returns:
    - bool: True if the refresh token is verified, False otherwise.
    """

    return hmac.compare_digest(hash_refresh_token(token), stored_hash)


def verify_refresh_token(token: str, access_token: str) -> dict | None:
    """
    Verify a JWT refresh token.

    # Args:
    - token: str - The refresh token to verify.
    - access_token: str - The access token to verify.

    # Returns:
    - dict | None: The payload of the JWT refresh token.

    # Raises:
    - HTTPException: If the JWT refresh token verification fails.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            access_token=access_token,
        )

        return payload
    except jwt.ExpiredSignatureError as e:
        logger.exception(f"JWT refresh token expired: {str(e)}")
        raise HTTPException(status_code=401, detail="JWT refresh token expired")
    except jwt.JWTError as e:
        logger.exception(f"Invalid JWT refresh token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid JWT refresh token")
    except Exception as e:
        logger.exception(f"Error verifying JWT refresh token: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not verify JWT refresh token. Please try again.",
        )


async def create_user_session(
    session_id: UUID,
    user_id: UUID,
    refresh_token: str,
    db_session: AsyncSession,
) -> UserSession:
    """
    Create a new user session for a user.

    # Args:
    - session_id: UUID - The ID of the session.
    - user_id: UUID - The ID of the user.
    - refresh_token: str - The refresh token.
    - db_session: AsyncSession - The database session.

    # Returns:
    - UserSession: The user session object.

    # Raises:
    - HTTPException: If the user session creation fails.
    """
    try:
        user_session_query = select(UserSession).where(UserSession.user_id == user_id)
        user_session = await db_session.execute(user_session_query)
        user_session = user_session.scalar_one_or_none()

        if user_session:
            await db_session.delete(user_session)

        new_user_session = UserSession(
            id=session_id,
            user_id=user_id,
            hashed_refresh_token=hash_refresh_token(refresh_token),
        )
        db_session.add(new_user_session)
        await db_session.commit()

        return new_user_session
    except Exception as e:
        await db_session.rollback()
        logger.exception(f"Error creating user session: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create user session. Please try again.",
        )


async def get_user_session(
    session_id: UUID,
    db_session: AsyncSession,
) -> UserSession | None:
    """
    Get a user session by session ID.

    # Args:
    - session_id: UUID - The ID of the session.
    - db_session: AsyncSession - The database session.

    # Returns:
    - UserSession: The user session object.

    # Raises:
    - HTTPException: If the user session retrieval fails.
    """
    try:
        user_session_query = select(UserSession).where(UserSession.id == session_id)
        user_session = await db_session.execute(user_session_query)
        return user_session.scalar_one_or_none()
    except Exception as e:
        logger.exception(f"Error getting user session: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get user session. Please try again.",
        )
