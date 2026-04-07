"""
Miscellaneous routes for the Trellix Backend.
"""

import uuid
from typing import Annotated
from pydantic import SecretStr
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..config import settings
from ..utils import get_logger
from ..db import get_db_session, redis_manager, db_manager
from ..services import (
    generate_jwt_tokens,
    get_user_by_email,
    verify_password,
)
from ..auth import SessionStoreType, get_session_store
from ..models import Login200Response, Root200Response, Health200Response, SessionData


logger = get_logger(__name__)
router = APIRouter(tags=["Miscellaneous APIs"])


@router.get(
    path="/",
    summary="Root endpoint",
    description="Root endpoint for the Trellix Backend.",
    status_code=status.HTTP_200_OK,
    response_model=Root200Response,
)
async def root(request: Request) -> JSONResponse:
    """
    Root endpoint with API information.

    # Args:
    - request: Request - The request object.

    # Returns:
    - JSONResponse: A JSON response containing the service information.
        - status_code: The status code of the response.
        - content: A dictionary containing the service information.
            - service: The name of the service.
            - version: The version of the service.
            - environment: The environment the service is running in.
            - docs: The URL of the documentation.
    """

    logger.info("GET / - Root endpoint called")
    logger.info("GET / - Response: 200 OK - Root endpoint completed successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Root200Response(
            service=settings.app_name,
            version=settings.app_version,
            docs=f"{settings.base_url}/docs",
        ).model_dump(),
    )


@router.get(
    path="/healthz",
    summary="Health check endpoint",
    description="Health check endpoint for the Trellix Backend.",
    status_code=status.HTTP_200_OK,
    response_model=Health200Response,
)
async def health(request: Request) -> JSONResponse:
    """
    Health check endpoint.

    # Args:
    - request: Request - The request object.

    # Returns:
    - JSONResponse: A JSON response containing the health status.
        - status_code: The status code of the response.
        - content: A dictionary containing the health status.
            - status: The health status of the application.
            - service: The name of the service.
            - version: The version of the service.
            - dependencies: The dependencies of the service.
    """

    logger.info("GET /healthz - Health check endpoint called")

    # Check Redis connection (handles uninitialized Redis in test/startup scenarios)
    redis_healthy = False
    try:
        redis_healthy = await redis_manager.ping()
    except RuntimeError as e:
        logger.warning(f"Redis not initialized: {str(e)}")
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")

    # Check database connection (simple query)
    db_healthy = False
    try:
        db_healthy = await db_manager.ping()
    except RuntimeError as e:
        logger.warning(f"Database not initialized: {str(e)}")
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")

    overall_healthy = redis_healthy and db_healthy

    logger.info(
        "GET /healthz - Response: 200 OK - Health check endpoint completed successfully"
    )

    return JSONResponse(
        status_code=200 if overall_healthy else 503,
        content=Health200Response(
            status="healthy" if overall_healthy else "unhealthy",
            service=settings.app_name,
            version=settings.app_version,
            dependencies={
                "redis": "healthy" if redis_healthy else "unhealthy",
                "database": "healthy" if db_healthy else "unhealthy",
            },
        ).model_dump(),
    )


@router.post(
    path="/swagger-ui-auth",
    include_in_schema=False,
    status_code=status.HTTP_200_OK,
    response_model=Login200Response,
)
async def swagger_ui_auth(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db_session: AsyncSession = Depends(get_db_session),
    session_store: SessionStoreType = Depends(get_session_store),
) -> JSONResponse:
    """
    Token endpoint for Swagger UI.
    """
    logger.info("POST /swagger-ui-auth - Swagger UI auth endpoint called")

    user = await get_user_by_email(form_data.username, db_session)

    if not user:
        raise HTTPException(
            status_code=404, detail="User with this email does not exists."
        )

    if not verify_password(SecretStr(form_data.password), user.hashed_password):
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

    logger.info(
        "POST /swagger-ui-auth - Response: 200 OK - Swagger UI auth endpoint completed successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=Login200Response(
            message="Swagger UI auth completed successfully",
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=session_id,
        ).model_dump(mode="json"),
    )
