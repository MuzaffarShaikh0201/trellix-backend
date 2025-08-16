from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends

from ..database.connect import get_db
from ..middleware.logging import logger
from ..schemas.auth_schemas import SessionData
from ..schemas.responses import CustomJSONResponse
from ..middleware.authorization import oauth2_scheme
from ..controllers.user_services import user_profile_handler
from ..schemas.user_schemas import GET_USER_RESPONSE_MODEL


router = APIRouter(tags=["User APIs"], prefix="/user")


@router.get(
    path="",
    description="<b>This endpoint retrieves the user profile.<b>",
    responses=GET_USER_RESPONSE_MODEL,
)
async def user_profile(
    session_data: SessionData = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> CustomJSONResponse:
    """
    This endpoint retrieves the user profile.

    Args:
        session_data (SessionData): The session data containing the user ID and session ID.
        db (Session): The database session for performing database operations.

    Returns:
        CustomJSONResponse: A JSON response with a dict and HTTP status code 200.
    """
    logger.info("User Profile API is being called")

    return await user_profile_handler(
        user_id=session_data["user_id"], email=session_data["email"], db=db
    )
