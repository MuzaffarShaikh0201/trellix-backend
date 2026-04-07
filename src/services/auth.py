"""
Authentication services.
These services are used for authentication-related operations.
"""

import bcrypt
import hashlib
from jose import jwt
from uuid import UUID
from pydantic import SecretStr
from fastapi import HTTPException
from datetime import datetime, timedelta, timezone

from ..config import settings
from ..utils import get_logger


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


def verify_password(password: SecretStr, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password.

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
            options={"verify_exp": False},
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
