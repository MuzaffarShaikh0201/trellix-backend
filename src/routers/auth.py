"""
Authentication routes.
"""

import uuid
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, HTTPException, status

from ..db import get_db_session
from ..utils import get_logger
from ..auth import bearer_header_auth
from ..services import (
    create_user,
    create_user_session,
    generate_jwt_tokens,
    hash_refresh_token,
    user_exists,
    get_user_by_email,
    verify_password,
    verify_refresh_token,
    verify_refresh_token_hash,
    get_user_session,
)
from ..models import (
    Login200Response,
    LoginRequest,
    RegisterRequest,
    Register201Response,
    SessionData,
    RefreshRequest,
    Refresh200Response,
)


logger = get_logger(__name__)
router = APIRouter(tags=["Authentication APIs"])


@router.post(
    path="/register",
    summary="Register a new user",
    description="Register a new user with email and password.",
    status_code=status.HTTP_201_CREATED,
    response_model=Register201Response,
)
async def register(
    request: RegisterRequest, db_session: AsyncSession = Depends(get_db_session)
) -> JSONResponse:
    """
    Register a new user with email and password.

    # Args:
    - request: RegisterRequest - The request object.

    # Returns:
    - JSONResponse: A JSON response containing the user information.
        - status_code: The status code of the response.
        - content: A dictionary containing the user information.
            - message: The message of the response.
    """

    logger.info("POST /register - Register a new user endpoint called")

    if await user_exists(request.email, db_session):
        raise HTTPException(
            status_code=409, detail="An account with this email already exists."
        )

    await create_user(
        request.email,
        request.first_name,
        request.last_name,
        request.password,
        db_session,
    )

    logger.info("POST /register - Response: 201 Created - User registered successfully")

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=Register201Response(message="User registered successfully").model_dump(
            mode="json"
        ),
    )


@router.post(
    path="/login",
    summary="User Login",
    description="User login with email and password.",
    status_code=status.HTTP_200_OK,
    response_model=Login200Response,
)
async def login(
    request: LoginRequest, db_session: AsyncSession = Depends(get_db_session)
) -> JSONResponse:
    """
    User login with email and password.

    # Args:
    - request: LoginRequest - The request object.

    # Returns:
    - JSONResponse: A JSON response containing the user information.
        - status_code: The status code of the response.
        - content: A dictionary containing the user information.
            - message: The message of the response.
    """

    logger.info("POST /login - User login endpoint called")

    user = await get_user_by_email(request.email, db_session)

    if not user:
        raise HTTPException(
            status_code=404, detail="User with this email does not exists."
        )

    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    session_id = uuid.uuid4()

    access_token, refresh_token = generate_jwt_tokens(user.id, session_id)

    user_session = await create_user_session(
        session_id, user.id, refresh_token, db_session
    )

    user.last_logged_in = datetime.now(timezone.utc)
    await db_session.commit()

    logger.info("POST /login - Response: 200 OK - User logged in successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Login200Response(
            message="User logged in successfully",
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=user_session.id,
        ).model_dump(mode="json"),
    )


@router.post(
    path="/refresh",
    summary="Refresh access token",
    description="Refresh access token with refresh token.",
    status_code=status.HTTP_200_OK,
    response_model=Refresh200Response,
)
async def refresh(
    request: RefreshRequest,
    session_data: SessionData = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Refresh access token with refresh token.

    # Args:
    - request: RefreshRequest - The request object.
    - session_data: SessionData - The session data from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the user information.
        - status_code: The status code of the response.
        - content: A dictionary containing the user information.
            - message: The message of the response.
            - access_token: The access token of the user.
            - refresh_token: The refresh token of the user.
            - session_id: The ID of the session.
    """
    logger.info("POST /refresh - Refresh access token endpoint called")

    user_session = await get_user_session(session_data.session_id, db_session)

    if not user_session or not verify_refresh_token_hash(
        request.refresh_token, user_session.hashed_refresh_token
    ):
        logger.error(
            f"Invalid refresh token. User session not found or refresh token hash mismatch."
        )
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    refresh_token_claims = verify_refresh_token(
        request.refresh_token, session_data.access_token
    )

    if uuid.UUID(refresh_token_claims["jti"]) != user_session.id:
        logger.error(
            f"Invalid refresh token. Session ID mismatch: {refresh_token_claims['jti']} != {user_session.id}"
        )
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    access_token, refresh_token = generate_jwt_tokens(
        user_session.user_id, user_session.id
    )

    user_session.hashed_refresh_token = hash_refresh_token(refresh_token)
    await db_session.commit()

    logger.info(
        "POST /refresh - Response: 200 OK - Access token refreshed successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Refresh200Response(
            message="Access token refreshed successfully",
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=user_session.id,
        ).model_dump(mode="json"),
    )
