"""
Authentication routes.
"""

from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, HTTPException, status

from ..db import get_db
from ..utils import get_logger
from ..services import create_user, user_exists
from ..models import RegisterRequest, Register201Response


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
    request: RegisterRequest, db_session: AsyncSession = Depends(get_db)
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
        content=Register201Response(
            message="User registered successfully"
        ).model_dump(),
    )
