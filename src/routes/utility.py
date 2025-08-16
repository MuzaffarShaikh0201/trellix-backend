from sqlalchemy.orm import Session
from typing import Annotated, Union
from fastapi.requests import Request
from fastapi import APIRouter, Depends, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from ..database.connect import get_db
from ..middleware.logging import logger
from ..schemas.auth_schemas import TokenData
from ..schemas.responses import CustomJSONResponse
from ..schemas.default_schemas import HOME_RESPONSE_MODEL
from ..controllers.utility_services import token_handler, health_check_handler


router = APIRouter(tags=["Utility APIs"])


@router.get(
    "/",
    description="<b>Default endpoint that serves as the entry point for the APIs.<b>",
    responses=HOME_RESPONSE_MODEL,
)
async def default(request: Request) -> CustomJSONResponse:
    """
    Default entry point for the Trellix Backend APIs.

    This is a public health check or informational endpoint to confirm that the
    Project microservice is running and accessible.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        CustomJSONResponse: A simple success response indicating that the service is live.
    """
    logger.info(
        "%s - %s - %s",
        request.method,
        "public",
        "Default API is being called",
    )
    return CustomJSONResponse(
        success=True,
        status_code=status.HTTP_200_OK,
        message="This is initial route of TRELLIX-BACKEND APIs!",
    )


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """
    This endpoint is used to serve the favicon.ico file.
    """
    logger.info("Favicon API is being called")

    return RedirectResponse(url="https://fastapi.tiangolo.com/img/favicon.png")


@router.post(
    path="/token",
    description=(
        "<b>This endpoint handles the token generation functionality for Swagger UI.<b><br>"
        "`Note: This is not a part of the actual API. Use /auth/login in actual usecases.`"
    ),
    include_in_schema=False,
)
async def token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    Generate access token for Swagger UI testing (not for production use).

    This endpoint acts as a proxy to the actual `/auth/login` endpoint,
    primarily intended for integration with Swagger UI. It facilitates token-based
    authentication for API testing within the Swagger interface.

    Args:
        form_data (OAuth2PasswordRequestForm): Form data containing `username`,
        `password`, and `grant_type`.

    Returns:
        TokenData: A response object containing the access and refresh tokens, or
        the raw response from the `/auth/login` endpoint in case of failure.

    Notes:
        - This endpoint is hidden from the OpenAPI schema (`include_in_schema=False`).
        - For actual application authentication, use the `/auth/login` endpoint
    """
    logger.info("Token API is being called")

    return await token_handler(
        email=form_data.username, password=form_data.password, db=db
    )


@router.get(path="/healthz", include_in_schema=False)
async def healthz() -> CustomJSONResponse:
    """
    Health check endpoint to verify the service is running.

    Returns:
        CustomJSONResponse: A response indicating the service is healthy.
    """
    logger.info("Healthz API is being called")

    return await health_check_handler()
