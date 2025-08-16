import json
from typing import Union
from fastapi import status
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core.config import settings
from ..middleware.logging import logger
from ..database.connect import SessionLocal
from ..schemas.auth_schemas import TokenData
from ..controllers.auth_services import login_handler
from ..schemas.responses import CustomBackendError, CustomJSONResponse


async def default_handler() -> CustomJSONResponse:
    """
    Returns a JSON response for the initial route.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    return CustomJSONResponse(
        success=True,
        status_code=status.HTTP_200_OK,
        message="This is initial route of TRELLIX-BACKEND APIs!",
    )


async def token_handler(
    email: str, password: str, db: Session
) -> Union[CustomJSONResponse, TokenData]:
    """
    Generate access token for Swagger UI testing (not for production use).

    Args:
        email (str): The email address of the user.
        password (str): The password of the user.
        db (Session): The database session for performing database operations.

    Returns:
        Union[CustomJSONResponse, TokenData]: A JSON response with a dict and HTTP status code 200.
    """
    logger.info(f"{email} - Execution started")

    try:
        if email not in settings.DEVELOPERS_EMAIL:
            return CustomJSONResponse(
                success=False,
                status_code=403,
                message="Forbidden Access",
                error={
                    "code": "FORBIDDEN",
                    "details": "You are not authorized to access this resource. Please contact support if needed.",
                },
            )

        token_response = await login_handler(email=email, password=password, db=db)

        token_data = json.loads(token_response.body.decode("utf-8"))

        if token_response.status_code == 200:
            reponse = TokenData(**token_data["data"])
        else:
            reponse = reponse = CustomJSONResponse(**token_data)

        return reponse

    except Exception as e:
        logger.error(f"{email} - Error: {str(e)}")
        return CustomBackendError(
            message="Token generation failed",
            details=(
                "Something went wrong while generating the token. Please try again later or contact support if the issue persists."
            ),
        )

    finally:
        logger.info(f"{email} - Execution completed")


async def health_check_handler() -> CustomJSONResponse:
    """
    Returns a JSON response for the health check route.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info(f"Execution started")

    status_report = {
        "PostgreSQL DB": False,
    }

    try:
        # Check PostgreSQL DB
        try:
            db_session = SessionLocal()
            db_session.execute(text("SELECT 1"))
            status_report["PostgreSQL DB"] = True
        except Exception as e:
            logger.error(f"PostgreSQL DB check failed: {e}")
            status_report["PostgreSQL DB"] = False

        return CustomJSONResponse(
            success=True,
            status_code=status.HTTP_200_OK,
            message="Health check successful",
            meta=status_report,
        )

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return CustomBackendError(
            message="Health check failed",
            details=(
                "Something went wrong while checking the health of the service. Please try again later or contact support if the issue persists."
            ),
            kwargs={"data": status_report},
        )

    finally:
        logger.info(f"Execution completed")
