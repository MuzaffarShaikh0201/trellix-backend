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
from ..auth import SessionStoreType, bearer_header_auth, get_session_store
from ..services import (
    create_user,
    generate_jwt_tokens,
    get_user_by_email,
    hash_password,
    verify_password,
    verify_refresh_token,
)
from ..models import (
    Login200Response,
    LoginRequest,
    Logout200Response,
    RegisterRequest,
    Register201Response,
    SessionData,
    RefreshRequest,
    Refresh200Response,
    UserCreds,
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
    request: RegisterRequest = Depends(),
    db_session: AsyncSession = Depends(get_db_session),
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

    user = await get_user_by_email(request.email, db_session)

    if user:
        raise HTTPException(
            status_code=409, detail="An account with this email already exists."
        )

    user = await create_user(
        db_session=db_session,
        email=request.email,
        first_name=request.first_name,
        last_name=request.last_name,
        hashed_password=hash_password(request.password.get_secret_value()),
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
    request: LoginRequest = Depends(),
    db_session: AsyncSession = Depends(get_db_session),
    session_store: SessionStoreType = Depends(get_session_store),
) -> JSONResponse:
    """
    User login with email and password.

    # Args:
    - request: LoginRequest - The request object.
    - db_session: AsyncSession - The database session.
    - session_store: SessionStoreType - The session store.

    # Returns:
    - JSONResponse: A JSON response containing the user information.
    """

    logger.info("POST /login - User login endpoint called")

    user = await get_user_by_email(request.email, db_session)

    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    active_session = await session_store.get_user_session(user.id)

    if active_session:
        await session_store.delete_user_session(user.id)
        await session_store.delete_session(active_session)

    session_id = uuid.uuid4()

    access_token, refresh_token = generate_jwt_tokens(user.id, session_id)

    session_data = SessionData(
        session_id=session_id,
        user_id=user.id,
        access_token=access_token,
    )
    await session_store.set_session(session_data)
    await session_store.set_user_session(user.id, session_id)

    user.last_logged_in = datetime.now(timezone.utc)
    await db_session.commit()

    logger.info("POST /login - Response: 200 OK - User logged in successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Login200Response(
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=session_id,
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
    request: RefreshRequest = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    session_store: SessionStoreType = Depends(get_session_store),
) -> JSONResponse:
    """
    Refresh access token with refresh token.

    # Args:
    - request: RefreshRequest - The request object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - session_store: SessionStoreType - The session store.

    # Returns:
    - JSONResponse: A JSON response containing the access token and refresh token.
    """
    logger.info("POST /refresh - Refresh access token endpoint called")

    session_data = await session_store.get_session(user_creds.session_id)

    if not session_data:
        logger.error(f"Session data not found: {user_creds.session_id}")
        raise HTTPException(status_code=401, detail="Session data not found.")

    refresh_token_claims = verify_refresh_token(
        request.refresh_token, session_data.access_token
    )

    if (
        uuid.UUID(refresh_token_claims["jti"]) != session_data.session_id
        or uuid.UUID(refresh_token_claims["sub"]) != session_data.user_id
    ):
        logger.error(f"Invalid refresh token (Claims mismatch)")
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    access_token, refresh_token = generate_jwt_tokens(
        session_data.user_id, session_data.session_id
    )

    session_data.access_token = access_token
    session_data.updated_at = datetime.now(timezone.utc)
    await session_store.set_session(session_data)
    await session_store.set_user_session(session_data.user_id, session_data.session_id)

    logger.info(
        "POST /refresh - Response: 200 OK - Access token refreshed successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Refresh200Response(
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=session_data.session_id,
        ).model_dump(mode="json"),
    )


@router.post(
    path="/logout",
    summary="Logout user",
    description="Logout user from the system.",
    status_code=status.HTTP_200_OK,
    response_model=Logout200Response,
)
async def logout(
    user_creds: UserCreds = Depends(bearer_header_auth),
    session_store: SessionStoreType = Depends(get_session_store),
) -> JSONResponse:
    """
    Logout user from the system.

    # Args:
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - session_store: SessionStoreType - The session store.

    # Returns:
    - JSONResponse: A JSON response containing the message.
    """
    logger.info("POST /logout - Logout user endpoint called")

    session_data = await session_store.get_session(user_creds.session_id)

    if not session_data:
        logger.error(f"Session data not found: {user_creds.session_id}")
        raise HTTPException(status_code=401, detail="Session data not found.")

    await session_store.delete_session(user_creds.session_id)
    await session_store.delete_user_session(session_data.user_id)

    logger.info("POST /logout - Response: 200 OK - User logged out successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Logout200Response(message="User logged out successfully").model_dump(
            mode="json"
        ),
    )
