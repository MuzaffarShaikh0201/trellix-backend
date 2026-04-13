"""
User routes.
These routes are used for user-related operations.
"""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..utils import get_logger
from ..db import get_db_session
from ..auth import bearer_header_auth
from ..services import get_user_by_id, hash_password, verify_password
from ..models import (
    UpdateUserPassword200Response,
    UpdateUserPasswordParams,
    UserCreds,
    GetUser200Response,
    UpdateUserParams,
    UpdateUser200Response,
)


logger = get_logger(__name__)
router = APIRouter(tags=["User APIs"], prefix="/user")


@router.get(
    path="",
    summary="Get user by ID",
    description="Get user by ID for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=GetUser200Response,
)
async def get_user(
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Get user by ID for the current user.

    # Args:
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the user.
    """

    logger.info("GET /user - Get user by ID endpoint called")

    user = await get_user_by_id(user_creds.user_id, db_session)

    logger.info("GET /user - Response: 200 OK - User fetched successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GetUser200Response.model_validate(user).model_dump(mode="json"),
    )


@router.put(
    path="",
    summary="Update user",
    description="Update user for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=UpdateUser200Response,
)
async def update_user(
    params: UpdateUserParams = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Update user for the current user.

    # Args:
    - params: UpdateUserParams - The request object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the user.
    """

    logger.info("PUT /user - Update user endpoint called")

    user = await get_user_by_id(user_creds.user_id, db_session)

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if params.first_name:
        user.first_name = params.first_name

    if params.last_name:
        user.last_name = params.last_name

    await db_session.commit()

    logger.info("PUT /user - Response: 200 OK - User updated successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=UpdateUser200Response(message="User updated successfully").model_dump(
            mode="json"
        ),
    )


@router.patch(
    path="",
    summary="Update user password",
    description="Update user password for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=UpdateUserPassword200Response,
)
async def update_user_password(
    params: UpdateUserPasswordParams = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Update user password for the current user.

    # Args:
    - params: UpdateUserPasswordParams - The request object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the user.
    """

    logger.info("PATCH /user - Update user password endpoint called")

    user = await get_user_by_id(user_creds.user_id, db_session)

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not verify_password(params.current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid current password.")

    user.hashed_password = hash_password(params.new_password.get_secret_value())

    await db_session.commit()

    logger.info("PATCH /user - Response: 200 OK - User password updated successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=UpdateUserPassword200Response(
            message="User password updated successfully",
        ).model_dump(mode="json"),
    )
