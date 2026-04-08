"""
Project services.
These services are used for project-related operations.
"""

from datetime import date
from sqlalchemy import select
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..utils import get_logger
from ..models import (
    ProjectStatusEnum,
    UserCreds,
    ProjectCategoryEnum,
    ProjectPriorityEnum,
    Project,
)


logger = get_logger(__name__)


async def create_project(
    db_session: AsyncSession,
    user_creds: UserCreds,
    title: str,
    description: str | None,
    category: ProjectCategoryEnum,
    priority: ProjectPriorityEnum,
    start_date: date | None,
    due_date: date | None,
    color: str | None,
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
            status = ProjectStatusEnum.ACTIVE
        else:
            status = ProjectStatusEnum.PENDING

        project = Project(
            user_id=user_creds.user_id,
            title=title,
            description=description,
            status=status,
            category=category,
            priority=priority,
            start_date=start_date,
            due_date=due_date,
            color=color,
        )
        db_session.add(project)
        await db_session.commit()
        await db_session.flush()

        logger.info(f"Project created successfully: {project.id}")
        return project
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create project. Please try again.",
        )
