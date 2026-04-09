"""
Project routes.
"""

from pydantic import UUID4
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, Path, status

from ..utils import get_logger
from ..db import get_db_session
from ..auth import bearer_header_auth
from ..services import create_project, get_all_projects_by_user_id, get_project_by_id
from ..models import (
    CreateProjectRequest,
    CreateProject201Response,
    GetAllProjectsRequest,
    UserCreds,
    GetAllProjects200Response,
    GetProject200Response,
)

logger = get_logger(__name__)
router = APIRouter(tags=["Project APIs"], prefix="/project")


@router.get(
    path="",
    summary="Get all projects",
    description=(
        "Get all projects for the current user (not deleted and not archived).\n"
        "Pagination and sorting are supported."
    ),
    status_code=status.HTTP_200_OK,
    response_model=GetAllProjects200Response,
)
async def get_all_projects(
    request_data: GetAllProjectsRequest = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Get all projects for the current user (not deleted and not archived).

    # Args:
    - request_data: GetAllProjectsRequest - The request data object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the list of projects.
    """

    logger.info("GET /project - Get all projects endpoint called")

    projects, total_pages, total_items = await get_all_projects_by_user_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        page=request_data.page,
        limit=request_data.limit,
        sort_by=request_data.sort_by,
        sort_order=request_data.sort_order,
        status=request_data.status,
        category=request_data.category,
        priority=request_data.priority,
    )

    logger.info("GET /project - Response: 200 OK - Projects fetched successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GetAllProjects200Response(
            projects=projects,
            total_pages=total_pages,
            total_items=total_items,
            current_page=request_data.page,
            items_per_page=request_data.limit,
        ).model_dump(mode="json"),
    )


@router.get(
    path="/{project_id}",
    summary="Get project by ID",
    description="Get project by ID for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=GetProject200Response,
)
async def get_project(
    project_id: UUID4 = Path(..., description="The ID of the project."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Get project by ID for the current user.

    # Args:
    - project_id: UUID4 - The ID of the project.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the project.
    """

    logger.info("GET /project/{project_id} - Get a project by ID endpoint called")

    project = await get_project_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        project_id=project_id,
    )

    logger.info(
        "GET /project/{project_id} - Response: 200 OK - Project fetched successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GetProject200Response(**project.__dict__).model_dump(mode="json"),
    )


@router.post(
    path="",
    summary="Create new project",
    description="Create new project for the current user.",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateProject201Response,
)
async def create_new_project(
    request_data: CreateProjectRequest = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Create new project for the current user with the given request data.

    # Args:
    - request_data: CreateProjectRequest - The request data object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the project ID.
    """

    logger.info("POST /project/create - Create new project endpoint called")

    project = await create_project(
        db_session=db_session,
        user_creds=user_creds,
        title=request_data.title,
        description=request_data.description,
        category=request_data.category,
        priority=request_data.priority,
        start_date=request_data.start_date,
        due_date=request_data.due_date,
        color=request_data.color,
    )

    logger.info(
        "POST /project/create - Response: 201 Created - Project created successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=CreateProject201Response(
            project_id=project.id,
        ).model_dump(mode="json"),
    )
