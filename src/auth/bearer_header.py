"""
Bearer token authentication.
"""

from jose import jwt
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, Header, Request
from fastapi.security.utils import get_authorization_scheme_param

from ..config import settings
from ..utils import get_logger
from ..models import UserCreds


logger = get_logger(__name__)


class BearerHeaderAuth(OAuth2PasswordBearer):
    def __init__(
        self,
        tokenUrl: str = "/swagger-ui-auth",
        refreshUrl: str = "/refresh",
        scheme_name: str = "Bearer",
        scopes: dict = {},
        description: str = "Bearer header authentication",
        auto_error: bool = True,
    ):
        super().__init__(
            tokenUrl=tokenUrl,
            refreshUrl=refreshUrl,
            scheme_name=scheme_name,
            scopes=scopes,
            description=description,
            auto_error=auto_error,
        )

    async def verify_access_token(
        self, token: str, skip_expiration: bool = False
    ) -> UserCreds | None:
        """
        Verify a JWT access token.

        # Args:
        - token: str - The JWT access token to verify.
        - skip_expiration: bool - Whether to skip the expiration check.

        # Returns:
        - UserCreds | None: The user credentials.
        """
        try:
            decode_options = {"verify_exp": not skip_expiration}

            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                options=decode_options,
            )

            return UserCreds(
                session_id=payload["jti"],
                user_id=payload["sub"],
            )
        except jwt.ExpiredSignatureError as e:
            logger.error(f"Token expired: {str(e)}")
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid token")
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Could not verify token. Please try again."
            )

    async def __call__(
        self,
        request: Request,
        Authorization: Annotated[
            str | None,
            Header(description="Authorization header", examples=["Bearer <token>"]),
        ] = None,
    ) -> UserCreds:
        if not Authorization:
            logger.error("No authorization header provided")
            raise HTTPException(
                status_code=401, detail="No authorization header provided"
            )

        scheme, token = get_authorization_scheme_param(Authorization)

        if not scheme or scheme.lower() != "bearer":
            logger.error("Invalid authorization scheme")
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")

        user_creds = await self.verify_access_token(
            token, skip_expiration=request.url.path == "/refresh"
        )
        if not user_creds:
            logger.error("Invalid access token")
            raise HTTPException(status_code=401, detail="Invalid access token")

        return user_creds


bearer_header_auth = BearerHeaderAuth()
