"""
Project services.
These services are used for project-related operations.
"""

from datetime import date
import math
from pydantic import UUID4
from sqlalchemy import func, select
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..utils import get_logger
from ..models import (
    Project,
    ProjectStatusEnum,
    UserCreds,
)


logger = get_logger(__name__)

_RECENT_PROJECTS_LIMIT = 5


async def get_recent_projects_by_user_id(
    db_session: AsyncSession,
    user_id: UUID4,
) -> list[Project]:
    """
    Get up to 5 most recently updated projects for a user (not deleted, not archived).

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.

    # Returns:
    - list[Project]: Projects ordered by updated_at descending.

    # Raises:
    - HTTPException: If the project retrieval fails.
    """

    try:
        projects_stmt = (
            select(Project)
            .where(
                Project.user_id == user_id,
                Project.is_deleted == False,
                Project.is_archived == False,
            )
            .order_by(Project.updated_at.desc())
            .limit(_RECENT_PROJECTS_LIMIT)
        )
        projects_result = await db_session.execute(projects_stmt)
        projects = list(projects_result.scalars().all())

        logger.info(
            f"Recent projects fetched for user ID: {user_id} - {len(projects)} projects"
        )
        return projects
    except Exception as e:
        logger.error(f"Error getting recent projects by user ID: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get recent projects. Please try again.",
        )


async def get_all_projects_by_user_id(
    db_session: AsyncSession,
    user_id: UUID4,
    page: int,
    limit: int,
    sort_by: str,
    sort_order: str,
    status: ProjectStatusEnum | None,
    is_favorite: bool | None,
    is_archived: bool | None,
) -> tuple[list[Project], int, int]:
    """
    Get all projects by user ID (not deleted; excludes archived by default).
    Filters, sorting, and pagination are supported.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - page: int - The page number.
    - limit: int - The number of projects per page.
    - sort_by: str - The field to sort by.
    - sort_order: str - The order to sort by.
    - status: ProjectStatusEnum | None - The status of the projects.
    - is_favorite: bool | None - Whether the projects are marked as favorite.
    - is_archived: bool | None - When set, filter by archive flag; when None, exclude archived.

    # Returns:
    - tuple[list[Project], int, int]: Projects, total pages, total item count.

    # Raises:
    - HTTPException: If the project retrieval fails.
    """

    try:
        # Base query
        projects_stmt = select(Project).where(
            Project.user_id == user_id,
            Project.is_deleted == False,
        )

        # Apply filters
        if is_archived is not None:
            projects_stmt = projects_stmt.where(Project.is_archived == is_archived)
        else:
            projects_stmt = projects_stmt.where(Project.is_archived == False)
        if status is not None:
            projects_stmt = projects_stmt.where(Project.status == status)
        if is_favorite is not None:
            projects_stmt = projects_stmt.where(Project.is_favorite == is_favorite)

        # Total items
        count_stmt = select(func.count()).select_from(projects_stmt)
        total_items_result = await db_session.execute(count_stmt)
        total_items = total_items_result.scalar_one()
        total_pages = math.ceil(total_items / limit)

        # Sorting
        projects_stmt = projects_stmt.order_by(
            getattr(Project, sort_by).asc()
            if sort_order == "asc"
            else getattr(Project, sort_by).desc()
        )

        # Pagination
        projects_stmt = projects_stmt.offset((page - 1) * limit).limit(limit)

        # Execute query
        projects_result = await db_session.execute(projects_stmt)
        projects = projects_result.scalars().all()

        logger.info(
            f"Projects fetched successfully for user ID: {user_id} - {total_items} projects - {total_pages} pages - {page} page - {limit} limit"
        )
        return projects, total_pages, total_items
    except Exception as e:
        logger.error(f"Error getting projects by user ID: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get projects by user ID. Please try again.",
        )


async def get_project_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    project_id: UUID4,
) -> Project:
    """
    Get a project by ID for the current user

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - project_id: UUID4 - The ID of the project.

    # Returns:
    - Project: The project object.

    # Raises:
    - HTTPException: If the project retrieval fails or if the project is not found.
    """
    try:
        project_stmt = select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
            Project.is_deleted == False,
        )
        project_result = await db_session.execute(project_stmt)
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found.",
            )

        logger.info(
            f"Project fetched successfully by ID: {project_id} for user ID: {user_id}"
        )
        return project
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error getting project by ID: {str(e)} for user ID: {user_id}")
        raise HTTPException(
            status_code=500,
            detail="Could not get project by ID. Please try again.",
            headers={"X-Error": str(e)},
        )


async def create_project(
    db_session: AsyncSession,
    user_creds: UserCreds,
    title: str,
    description: str | None,
    start_date: date | None,
    end_date: date | None,
    color: str | None,
    repo_url: str | None,
) -> Project:
    """
    Create a new project for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - payload: CreateProjectRequest - The request object.

    # Returns:
    - Project: The created project.

    # Raises:
    - HTTPException: If the project creation fails.
    """

    try:
        if start_date and start_date == date.today():
            status = ProjectStatusEnum.IN_PROGRESS
        else:
            status = ProjectStatusEnum.PLANNING

        project = Project(
            user_id=user_creds.user_id,
            title=title,
            description=description,
            status=status,
            repo_url=repo_url,
            start_date=start_date,
            end_date=end_date,
            color=color,
        )
        db_session.add(project)
        await db_session.commit()

        logger.info(f"Project created successfully: {project.id}")
        return project
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create project. Please try again.",
        )


async def toggle_project_favorite_status_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    project_id: UUID4,
) -> None:
    """
    Toggle project favorite status for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - project_id: UUID4 - The ID of the project.

    # Returns:
    - None: The project favorite status is toggled successfully.
    """
    try:
        project_stmt = select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
            Project.is_deleted == False,
            Project.is_archived == False,
        )
        project_result = await db_session.execute(project_stmt)
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found.",
            )

        project.is_favorite = not project.is_favorite
        await db_session.commit()

        logger.info(
            f"Project favorite status toggled successfully for project ID: {project_id}"
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error toggling project favorite status by ID: {str(e)} for project ID: {project_id}"
        )
        raise HTTPException(
            status_code=500,
            detail="Could not toggle project favorite status. Please try again.",
        )


async def toggle_project_archived_status_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    project_id: UUID4,
) -> None:
    """
    Toggle project archived status for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - project_id: UUID4 - The ID of the project.

    # Returns:
    - None: The project archived status is toggled successfully.
    """
    try:
        project_stmt = select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
            Project.is_deleted == False,
        )

        project_result = await db_session.execute(project_stmt)
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found.",
            )

        project.is_archived = not project.is_archived
        await db_session.commit()

        logger.info(
            f"Project archived status toggled successfully for project ID: {project_id}"
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error toggling project archived status by ID: {str(e)} for project ID: {project_id}"
        )
        raise HTTPException(
            status_code=500,
            detail="Could not toggle project archived status. Please try again.",
        )


async def update_project_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    project_id: UUID4,
    title: str | None,
    description: str | None,
    status: ProjectStatusEnum | None,
    start_date: date | None,
    end_date: date | None,
    color: str | None,
    repo_url: str | None,
    is_archived: bool | None,
) -> None:
    """
    Update a project by ID for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - project_id: UUID4 - The ID of the project.
    - title: str | None - The title of the project.
    - description: str | None - The description of the project.
    - status: ProjectStatusEnum | None - The status of the project.
    - is_archived: bool | None - Whether the project is archived.
    - start_date: date | None - The start date of the project.
    - end_date: date | None - The end date of the project.
    - color: str | None - The color of the project.
    - repo_url: str | None - When not None, set repository URL (strip; empty clears).

    # Returns:
    - None: The project is updated successfully.

    # Raises:
    - HTTPException: If the project update fails.
    """
    try:
        project_stmt = select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
            Project.is_deleted == False,
            Project.is_archived == False,
        )
        project_result = await db_session.execute(project_stmt)
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found.",
            )

        if title:
            project.title = title
        if description:
            project.description = description
        if status is not None:
            project.status = status
        if is_archived is not None:
            project.is_archived = is_archived
        if start_date:
            project.start_date = start_date
        if end_date:
            project.end_date = end_date
        if color:
            project.color = color
        if repo_url is not None:
            project.repo_url = repo_url.strip() or None

        await db_session.commit()

        logger.info(f"Project updated successfully by ID: {project_id}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error updating project by ID: {str(e)} for project ID: {project_id}"
        )
        raise HTTPException(
            status_code=500,
            detail="Could not update project. Please try again.",
        )


async def delete_project_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    project_id: UUID4,
) -> None:
    """
    Delete a project by ID for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - project_id: UUID4 - The ID of the project.

    # Returns:
    - None: The project is deleted successfully.

    # Raises:
    - HTTPException: If the project deletion fails.
    """
    try:
        project_stmt = select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
            Project.is_deleted == False,
            Project.is_archived == False,
        )
        project_result = await db_session.execute(project_stmt)
        project = project_result.scalar_one_or_none()

        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found.",
            )

        project.is_deleted = True
        await db_session.commit()

        logger.info(f"Project deleted successfully by ID: {project_id}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error deleting project by ID: {str(e)} for project ID: {project_id}"
        )
        raise HTTPException(
            status_code=500,
            detail="Could not delete project. Please try again.",
        )
