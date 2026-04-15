"""
Pydantic models for project routes.
These models are used for API request/response validation.
"""

from copy import deepcopy
from typing import Literal, Optional
from datetime import date, datetime
from fastapi import Body, Query, Path
from fastapi.exceptions import RequestValidationError
from pydantic import UUID4, BaseModel, Field, ConfigDict, field_validator

from .enums import ProjectCategoryEnum, ProjectStatusEnum


class CreateProjectParams:
    """Parameters for creating a new project."""

    def __init__(
        self,
        title: str = Body(
            ...,
            description=(
                "The title of the project.\n"
                "Title must contain only letters, numbers, spaces, hyphens (-), "
                "underscores (_), periods (.), and apostrophes ('). "
                "No special characters like @, #, $, %, &, *, etc."
            ),
            min_length=1,
            max_length=255,
            pattern=r"^[a-zA-Z0-9\s\-_\.\']+$",
        ),
        description: Optional[str] = Body(
            None,
            description="The description of the project.",
            min_length=1,
            max_length=2000,
        ),
        category: ProjectCategoryEnum = Body(
            ...,
            description="The category of the project.",
        ),
        start_date: Optional[date] = Body(
            None,
            description="The start date of the project.",
            ge=date.today(),
        ),
        due_date: Optional[date] = Body(
            None,
            description="The due date of the project.",
            ge=date.today(),
        ),
        color: Optional[str] = Body(
            None,
            description=(
                "The color of the project.\n"
                "Color must be a valid hex color code like #000000, #FFFFFF, etc."
            ),
            pattern=r"^#[0-9a-fA-F]{6}$",
        ),
    ) -> None:
        self.title = title.strip()
        self.description = description.strip() if description else None
        self.category = category
        self.start_date = start_date
        self.due_date = due_date
        self.color = color.strip() if color else None


class CreateProject201Response(BaseModel):
    """Response model for creating a new project."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "project_id": "12345678-9012-3456-7890-123456789012",
            }
        },
    )

    project_id: UUID4 = Field(..., description="The ID of the created project.")


class GetAllProjectsParams:
    """Parameters for getting all projects."""

    def __init__(
        self,
        status: Optional[ProjectStatusEnum] = Query(
            None,
            description="The status of the projects.",
        ),
        category: Optional[ProjectCategoryEnum] = Query(
            None,
            description="The category of the projects.",
        ),
        is_favorite: Optional[bool] = Query(
            None,
            description="Whether the projects are marked as favorite.",
        ),
        page: int = Query(default=1, description="The page number."),
        limit: int = Query(
            default=10, description="The number of projects per page.", ge=1, le=100
        ),
        sort_by: Literal["title", "created_at", "updated_at"] = Query(
            default="updated_at",
            description="The field to sort by.",
            enum=["title", "created_at", "updated_at"],
        ),
        sort_order: Literal["asc", "desc"] = Query(
            default="desc",
            description="The order to sort by.",
            enum=["asc", "desc"],
        ),
    ) -> None:
        self.status = status.value if status else None
        self.category = category.value if category else None
        self.is_favorite = is_favorite
        self.page = page
        self.limit = limit
        self.sort_by = sort_by
        self.sort_order = sort_order


class ProjectResponse(BaseModel):
    """Project response DTO for API payloads."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "12345678-9012-3456-7890-123456789012",
                "user_id": "12345678-9012-3456-7890-123456789012",
                "title": "Project Title",
                "description": "Project Description",
                "status": ProjectStatusEnum.ACTIVE.value,
                "category": ProjectCategoryEnum.WORK.value,
                "start_date": "2026-01-01",
                "due_date": "2026-01-01",
                "completed_at": "2026-01-01T00:00:00Z",
                "color": "#000000",
                "is_favorite": False,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        },
    )

    id: UUID4 = Field(..., description="The project ID.")
    user_id: UUID4 = Field(..., description="The owner user ID.")
    title: str = Field(..., description="The title of the project.")
    description: Optional[str] = Field(
        None, description="The description of the project."
    )
    status: ProjectStatusEnum = Field(..., description="The status of the project.")
    category: ProjectCategoryEnum = Field(
        ..., description="The category of the project."
    )
    start_date: Optional[date] = Field(
        None, description="The start date of the project."
    )
    due_date: Optional[date] = Field(None, description="The due date of the project.")
    completed_at: Optional[datetime] = Field(
        None, description="When the project was completed."
    )
    color: Optional[str] = Field(None, description="The color of the project.")
    is_favorite: bool = Field(..., description="Whether project is marked favorite.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class GetAllProjects200Response(BaseModel):
    """Response model for getting all projects."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "projects": [
                    {
                        "id": "12345678-9012-3456-7890-123456789012",
                        "user_id": "12345678-9012-3456-7890-123456789012",
                        "title": "Project Title",
                        "description": "Project Description",
                        "status": ProjectStatusEnum.ACTIVE,
                        "category": ProjectCategoryEnum.WORK.value,
                        "start_date": "2026-01-01",
                        "due_date": "2026-01-01",
                        "completed_at": "2026-01-01T00:00:00Z",
                        "color": "#000000",
                        "is_favorite": False,
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
                "total_pages": 1,
                "total_items": 1,
                "current_page": 1,
                "items_per_page": 1,
            }
        },
    )

    projects: list["ProjectResponse"] = Field(..., description="The list of projects.")
    total_pages: int = Field(..., description="The total number of pages.")
    total_items: int = Field(..., description="The total number of items.")
    current_page: int = Field(..., description="The current page number.")
    items_per_page: int = Field(..., description="The number of items per page.")


class GetProject200Response(ProjectResponse):
    """Response model for getting a project by ID."""

    _parent_json_schema_extra = deepcopy(
        ProjectResponse.model_config.get("json_schema_extra", {})
    )
    _parent_example = deepcopy(_parent_json_schema_extra.get("example", {}))
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            **_parent_json_schema_extra,
            "example": {
                **_parent_example,
            },
        },
    )


class ToggleProjectFavorite200Response(BaseModel):
    """Response model for toggling project favorite status."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Project favorite status toggled successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class UpdateProjectParams:
    """Parameters for updating a project."""

    def __init__(
        self,
        project_id: UUID4 = Path(..., description="The ID of the project."),
        title: Optional[str] = Body(
            None,
            description=(
                "The title of the project.\n"
                "Title must contain only letters, numbers, spaces, hyphens (-), "
                "underscores (_), periods (.), and apostrophes ('). "
                "No special characters like @, #, $, %, &, *, etc."
            ),
            min_length=1,
            max_length=255,
            pattern=r"^[a-zA-Z0-9\s\-_\.\']+$",
        ),
        description: Optional[str] = Body(
            None,
            description="The description of the project.",
            min_length=1,
            max_length=2000,
        ),
        status: Optional[ProjectStatusEnum] = Body(
            None, description="The status of the project."
        ),
        category: Optional[ProjectCategoryEnum] = Body(
            None, description="The category of the project."
        ),
        start_date: Optional[date] = Body(
            None,
            description="The start date of the project.",
            ge=date.today(),
        ),
        due_date: Optional[date] = Body(
            None,
            description="The due date of the project.",
            ge=date.today(),
        ),
        color: Optional[str] = Body(
            None,
            description=(
                "The color of the project.\n"
                "Color must be a valid hex color code like #000000, #FFFFFF, etc."
            ),
            pattern=r"^#[0-9a-fA-F]{6}$",
        ),
    ) -> None:
        self.project_id = project_id
        self.title = title.strip() if title else None
        self.description = description.strip() if description else None
        self.status = status.value if status else None
        self.category = category.value if category else None
        self.start_date = start_date if start_date else None
        self.due_date = due_date if due_date else None
        self.color = color.strip() if color else None


class UpdateProject200Response(BaseModel):
    """Response model for updating a project."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Project updated successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class DeleteProject200Response(BaseModel):
    """Response model for deleting a project."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Project deleted successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")
