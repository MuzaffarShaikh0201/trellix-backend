from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends

from ..database.connect import get_db
from ..middleware.logging import logger
from ..schemas.responses import CustomJSONResponse
from ..middleware.authorization import oauth2_scheme
from ..schemas.requests import LoginForm, RefreshTokenForm, RegistrationForm
from ..controllers.auth_services import (
    login_handler,
    refresh_session_handler,
    registration_handler,
    logout_handler,
)
from ..schemas.auth_schemas import (
    LOGIN_RESPONSE_MODEL,
    REFRESH_SESSION_RESPONSE_MODEL,
    REGISTRATION_RESPONSE_MODEL,
    LOGOUT_RESPONSE_MODEL,
    SessionData,
)


router = APIRouter(tags=["Auth APIs"], prefix="/auth")


@router.post(
    path="/register",
    description="<b>This endpoint handles the user registration functionality.<b>",
    responses=REGISTRATION_RESPONSE_MODEL,
)
async def register(
    creds: RegistrationForm = Depends(), db: Session = Depends(get_db)
) -> CustomJSONResponse:
    """
    This endpoint handles the user registration functionality.

    Args:
        creds (RegistrationForm): The credentials for user registration.
        db (Session): The database session for performing database operations.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info("Register API is being called")

    return await registration_handler(
        email=creds.email,
        first_name=creds.first_name,
        last_name=creds.last_name,
        password=creds.password,
        db=db,
    )


@router.post(
    path="/login",
    description="<b>This endpoint handles the user login functionality.<b>",
    responses=LOGIN_RESPONSE_MODEL,
)
async def login(
    form_data: LoginForm = Depends(),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    This endpoint handles the user login functionality.

    Args:
        form_data (LoginForm): The form data containing the user's credentials.
        db (Session): The database session for performing database operations.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info("Login API is being called")

    return await login_handler(
        email=form_data.email,
        password=form_data.password.get_secret_value(),
        db=db,
    )


@router.post(
    path="/refresh",
    description="<b>This endpoint handles the session refresh functionality.<b>",
    responses=REFRESH_SESSION_RESPONSE_MODEL,
)
async def refresh_session(
    form_data: RefreshTokenForm = Depends(),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    This endpoint handles the session refresh functionality.

    Args:
        form_data (RefreshTokenForm): The form data containing the refresh token.
        db (Session): The database session for performing database operations.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info("Refresh Session API is being called")
    return await refresh_session_handler(refresh_token=form_data.refresh_token, db=db)


@router.get(
    path="/logout",
    description="<b>This endpoint handles the user logout functionality.<b>",
    responses=LOGOUT_RESPONSE_MODEL,
)
async def logout(
    session_data: SessionData = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    This endpoint handles the user logout functionality.

    Args:
        session_data (SessionData): The session data containing the user ID and session ID.
        db (Session): The database session for performing database operations.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info("Logout API is being called")

    return await logout_handler(
        session_id=session_data["session_id"], email=session_data["email"], db=db
    )
