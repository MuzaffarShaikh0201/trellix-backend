"""
Pydantic models for project routes.
These models are used for API request/response validation.
"""

from copy import deepcopy
from datetime import date, datetime
from typing import Literal, Optional
from fastapi import Body, Query, Path
from pydantic import UUID4, BaseModel, Field, ConfigDict

from .enums import ProjectStatusEnum


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
        start_date: Optional[date] = Body(
            None,
            description="The start date of the project.",
            ge=date.today(),
        ),
        end_date: Optional[date] = Body(
            None,
            description="The end date of the project.",
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
        repo_url: Optional[str] = Body(
            None,
            description="Repository URL (e.g. Git remote).",
            max_length=500,
        ),
    ) -> None:
        self.title = title.strip()
        self.description = description.strip() if description else None
        self.start_date = start_date
        self.end_date = end_date
        self.color = color.strip() if color else None
        self.repo_url = repo_url.strip() if repo_url else None


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
        is_favorite: Optional[bool] = Query(
            None,
            description="Whether the projects are marked as favorite.",
        ),
        is_archived: Optional[bool] = Query(
            None,
            description=(
                "Filter by archive flag. When omitted, archived projects are excluded."
            ),
        ),
        page: int = Query(default=1, description="The page number."),
        limit: int = Query(
            default=10, description="The number of projects per page.", ge=1, le=100
        ),
        sort_by: Literal[
            "title",
            "created_at",
            "updated_at",
            "start_date",
            "end_date",
        ] = Query(
            default="updated_at",
            description="The field to sort by.",
            enum=[
                "title",
                "created_at",
                "updated_at",
                "start_date",
                "end_date",
            ],
        ),
        sort_order: Literal["asc", "desc"] = Query(
            default="desc",
            description="The order to sort by.",
            enum=["asc", "desc"],
        ),
    ) -> None:
        self.status = status
        self.is_favorite = is_favorite
        self.is_archived = is_archived
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
                "title": "Auth Service Revamp",
                "description": "Refactor login flow, improve token refresh, and add audit logs.",
                "status": ProjectStatusEnum.IN_PROGRESS.value,
                "repo_url": "https://github.com/org/repo",
                "start_date": "2026-01-01",
                "end_date": "2026-06-01",
                "color": "#000000",
                "is_favorite": False,
                "is_archived": False,
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
    repo_url: Optional[str] = Field(None, description="Source repository URL, if any.")
    start_date: Optional[date] = Field(
        None, description="The start date of the project."
    )
    end_date: Optional[date] = Field(None, description="The end date of the project.")
    color: Optional[str] = Field(None, description="The color of the project.")
    is_favorite: bool = Field(..., description="Whether project is marked favorite.")
    is_archived: bool = Field(..., description="Whether the project is archived.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class RecentProjectItem(BaseModel):
    """Summary of a recently updated project."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "title": "Auth Service Revamp",
                "is_favorite": True,
                "status": ProjectStatusEnum.IN_PROGRESS.value,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        },
    )

    title: str = Field(..., description="The title of the project.")
    is_favorite: bool = Field(..., description="Whether the project is marked favorite.")
    status: ProjectStatusEnum = Field(..., description="The status of the project.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class GetRecentProjects200Response(BaseModel):
    """Response model for recently updated projects (up to 5)."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "projects": [
                    {
                        "title": "Auth Service Revamp",
                        "is_favorite": True,
                        "status": ProjectStatusEnum.IN_PROGRESS.value,
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        },
    )

    projects: list[RecentProjectItem] = Field(
        ..., description="Up to 5 projects, newest by updated_at first."
    )


class GetAllProjects200Response(BaseModel):
    """Response model for getting all projects."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "projects": [
                    {
                        "id": "12345678-9012-3456-7890-123456789012",
                        "user_id": "12345678-9012-3456-7890-123456789012",
                        "title": "Auth Service Revamp",
                        "description": "Refactor login flow, improve token refresh, and add audit logs.",
                        "status": ProjectStatusEnum.IN_PROGRESS.value,
                        "repo_url": None,
                        "start_date": "2026-01-01",
                        "end_date": "2026-06-01",
                        "color": "#000000",
                        "is_favorite": False,
                        "is_archived": False,
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


class ToggleProjectArchived200Response(BaseModel):
    """Response model for toggling project archived status."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Project archived status toggled successfully",
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
        start_date: Optional[date] = Body(
            None,
            description="The start date of the project.",
            ge=date.today(),
        ),
        end_date: Optional[date] = Body(
            None,
            description="The end date of the project.",
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
        repo_url: Optional[str] = Body(
            None,
            description="Repository URL (e.g. Git remote).",
            max_length=500,
        ),
        is_archived: Optional[bool] = Body(
            None,
            description="Whether the project is archived.",
        ),
    ) -> None:
        self.project_id = project_id
        self.title = title.strip() if title else None
        self.description = description.strip() if description else None
        self.status = status
        self.start_date = start_date if start_date else None
        self.end_date = end_date if end_date else None
        self.color = color.strip() if color else None
        self.repo_url = repo_url
        self.is_archived = is_archived


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
