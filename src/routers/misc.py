"""
Miscellaneous routes for the Trellix Backend.
"""

from sqlalchemy import text
from fastapi.responses import JSONResponse
from fastapi import APIRouter, Request, status

from ..config import settings
from ..utils import get_logger
from ..db import redis_manager, db_manager
from ..models import Root200Response, Health200Response


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
        content={
            "service": settings.app_name,
            "version": settings.app_version,
            "docs": f"{settings.base_url}/docs",
        },
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
        logger.warning(f"Redis not initialized: {e}")
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")

    # Check database connection (simple query)
    db_healthy = False
    try:
        db_healthy = await db_manager.ping()
    except RuntimeError as e:
        logger.warning(f"Database not initialized: {e}")
    except Exception as e:
        logger.error(f"Database health check failed: {e}")

    overall_healthy = redis_healthy and db_healthy

    logger.info(
        "GET /healthz - Response: 200 OK - Health check endpoint completed successfully"
    )

    return JSONResponse(
        status_code=200 if overall_healthy else 503,
        content={
            "status": "healthy" if overall_healthy else "unhealthy",
            "service": settings.app_name,
            "version": settings.app_version,
            "dependencies": {
                "redis": "healthy" if redis_healthy else "unhealthy",
                "database": "healthy" if db_healthy else "unhealthy",
            },
        },
    )
