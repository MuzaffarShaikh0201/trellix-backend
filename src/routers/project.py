"""
Project routes.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import JSONResponse

from ..utils import get_logger
from ..db import get_db_session
from ..auth import bearer_header_auth
from ..services import create_project
from ..models import CreateProjectRequest, CreateProject201Response, UserCreds

logger = get_logger(__name__)
router = APIRouter(tags=["Project APIs"], prefix="/project")


@router.post(
    path="/create",
    summary="Create new project",
    description="Create new project for the current user.",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateProject201Response,
)
async def create_new_project(
    request: CreateProjectRequest,
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Create new project for the current user.

    # Args:
    - request: CreateProjectRequest - The request object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the project information.
        - status_code: The status code of the response.
        - content: A dictionary containing the project information.
            - message: The message of the response.
    """

    logger.info("POST /project/create - Create new project endpoint called")

    project = await create_project(
        db_session=db_session,
        user_creds=user_creds,
        title=request.title,
        description=request.description,
        category=request.category,
        priority=request.priority,
        start_date=request.start_date,
        due_date=request.due_date,
        color=request.color,
    )

    logger.info(
        "POST /project/create - Response: 201 Created - Project created successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=CreateProject201Response(
            message="Project created successfully",
            project_id=project.id,
        ).model_dump(mode="json"),
    )
