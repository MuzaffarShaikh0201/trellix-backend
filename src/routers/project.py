"""
Project routes.
"""

from pydantic import UUID4
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Body, Depends, Path, status

from ..utils import get_logger
from ..db import get_db_session
from ..auth import bearer_header_auth
from ..services import (
    create_project,
    get_all_projects_by_user_id,
    get_project_by_id,
    toggle_project_favorite_status_by_id,
    update_project_by_id,
    delete_project_by_id,
)
from ..models import (
    CreateProjectRequest,
    CreateProject201Response,
    DeleteProject200Response,
    GetAllProjectsRequest,
    UserCreds,
    GetAllProjects200Response,
    GetProject200Response,
    ToggleProjectFavorite200Response,
    UpdateProjectRequest,
    UpdateProject200Response,
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
        is_favorite=request_data.is_favorite,
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
        content=GetProject200Response.model_validate(project).model_dump(mode="json"),
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


@router.put(
    path="/{project_id}",
    summary="Update project",
    description="Update project for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=UpdateProject200Response,
)
async def update_project(
    project_id: UUID4 = Path(..., description="The ID of the project."),
    request_data: UpdateProjectRequest = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Update project for the current user.

    # Args:
    - project_id: UUID4 - The ID of the project.
    - request_data: UpdateProjectRequest - The request data object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the project.
    """

    logger.info("PUT /project/{project_id} - Update project endpoint called")

    await update_project_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        project_id=project_id,
        title=request_data.title,
        description=request_data.description,
        status=request_data.status,
        category=request_data.category,
        priority=request_data.priority,
        start_date=request_data.start_date,
        due_date=request_data.due_date,
        color=request_data.color,
    )

    logger.info(
        "PUT /project/{project_id} - Response: 200 OK - Project updated successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=UpdateProject200Response(
            message="Project updated successfully",
        ).model_dump(mode="json"),
    )


@router.patch(
    path="/{project_id}/toggle-favorite",
    summary="Toggle project favorite status",
    description="Toggle project favorite status for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=ToggleProjectFavorite200Response,
)
async def toggle_project_favorite_status(
    project_id: UUID4 = Path(..., description="The ID of the project."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Toggle project favorite status for the current user.

    # Args:
    - project_id: UUID4 - The ID of the project.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the project.
    """

    logger.info(
        "PATCH /project/{project_id}/toggle-favorite - Toggle project favorite status endpoint called"
    )

    await toggle_project_favorite_status_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        project_id=project_id,
    )

    logger.info(
        "PATCH /project/{project_id}/toggle-favorite - Response: 200 OK - Project favorite status toggled successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ToggleProjectFavorite200Response(
            message="Project favorite status toggled successfully",
        ).model_dump(mode="json"),
    )


@router.delete(
    path="/{project_id}",
    summary="Delete project",
    description="Delete project for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=DeleteProject200Response,
)
async def delete_project(
    project_id: UUID4 = Path(..., description="The ID of the project."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Delete project for the current user.

    # Args:
    - project_id: UUID4 - The ID of the project.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the message.
    """
    logger.info("DELETE /project/{project_id} - Delete project endpoint called")

    await delete_project_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        project_id=project_id,
    )

    logger.info(
        "DELETE /project/{project_id} - Response: 200 OK - Project deleted successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=DeleteProject200Response(
            message="Project deleted successfully",
        ).model_dump(mode="json"),
    )
