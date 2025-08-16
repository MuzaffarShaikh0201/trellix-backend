from typing import Annotated
from sqlalchemy.orm import Session, selectinload
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import Request, HTTPException, status, Depends, Header


from ..database.connect import get_db
from ..database.models import UserSession
from ..schemas.auth_schemas import SessionData
from ..schemas.responses import CustomHttpException
from ..controllers.auth_services import decode_token


class OAuth2PasswordBearerHeader(OAuth2PasswordBearer):
    def __init__(
        self,
        token_url: str = "/token",
        scheme_name: str = "bearer",
        scopes: dict = None,
        description: str = "OAuth2 Password Grant",
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}

        super().__init__(
            tokenUrl=token_url,
            scheme_name=scheme_name,
            scopes=scopes,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(
        self,
        request: Request,
        Authorization: Annotated[
            str | None,
            Header(description="Authorization header", example="Bearer <token>"),
        ] = None,
        db: Session = Depends(get_db),
    ) -> HTTPException | SessionData:
        try:
            authorization_header = Authorization

            if not authorization_header:
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Missing Authorization header. Please provide a valid Bearer token.",
                    )

            scheme, param = get_authorization_scheme_param(authorization_header)

            if not param or scheme.lower() != "bearer":
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid Authorization header. Please provide a valid Bearer token.",
                    )

            token_data = decode_token(token=param)

            if not token_data:
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token. Please provide a valid Bearer token.",
                    )

            if token_data == "expired_token":
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Token expired. Please refresh the token or login again.",
                    )

            if not all(
                keys in token_data.keys() for keys in ["jti", "iat", "sub", "exp"]
            ):
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token structure. Please provide a valid Bearer token.",
                    )

            user_session = (
                db.query(UserSession)
                .options(selectinload(UserSession.user))
                .filter(UserSession.id == token_data.get("jti"))
                .one_or_none()
            )

            if not user_session or user_session.access_token != param:
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        message="Unauthorized access",
                        error_code="UNAUTHORIZED",
                        error_details="Invalid token data. Please provide a valid Bearer token.",
                    )

            # if device_id not in token_data.get("allowed_ids", []):
            #     if self.auto_error:
            #         raise CustomHttpException(
            #             status_code=status.HTTP_403_FORBIDDEN,
            #             message="Forbidden",
            #             error_code="FORBIDDEN",
            #             error_details="Access from this device is not allowed. Please contact support if needed.",
            #             headers={"X-RateLimit-Policy": "IP-Restriction"},
            #         )

            if user_session.user.email != token_data.get("sub"):
                if self.auto_error:
                    raise CustomHttpException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        message="Forbidden access",
                        error_code="FORBIDDEN",
                        error_details="You are not authorized to access this resource. Please contact support if required.",
                    )

            session_id = user_session.id
            user_id = user_session.user_id
            email = user_session.user.email

            return {"session_id": session_id, "user_id": user_id, "email": email}
        except CustomHttpException as e:
            print("Error in OAuth2PasswordBearerHeader middleware:", e)
            raise e
        except Exception as e:
            print("Error in OAuth2PasswordBearerHeader middleware:", e)
            raise CustomHttpException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="User authorization failed",
                error_code="INTERNAL_SERVER_ERROR",
                error_details="Something went wrong while authorizing the user. Please try again later or contact support if the issue persists.",
            )
        finally:
            db.close()


oauth2_scheme = OAuth2PasswordBearerHeader()
