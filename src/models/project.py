"""
Pydantic models for project routes.
These models are used for API request/response validation.
"""

from datetime import date
from typing import Optional
from fastapi.exceptions import RequestValidationError
from pydantic import UUID4, BaseModel, Field, ConfigDict, field_validator

from .enums import ProjectCategoryEnum, ProjectPriorityEnum


class CreateProjectRequest(BaseModel):
    """Request model for creating a new project."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "Project Title",
                "description": "Project Description",
                "category": ProjectCategoryEnum.WORK,
                "priority": ProjectPriorityEnum.MEDIUM,
                "start_date": "2026-01-01",
                "due_date": "2026-01-01",
                "color": "#000000",
            }
        },
    )

    title: str = Field(
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
    )
    description: Optional[str] = Field(
        None,
        description="The description of the project.",
        min_length=1,
        max_length=2000,
    )
    category: ProjectCategoryEnum = Field(
        ..., description="The category of the project."
    )
    priority: ProjectPriorityEnum = Field(
        ..., description="The priority of the project."
    )
    start_date: Optional[date] = Field(
        None, description="The start date of the project."
    )
    due_date: Optional[date] = Field(None, description="The due date of the project.")
    color: Optional[str] = Field(
        None,
        description=(
            "The color of the project.\n"
            "Color must be a valid hex color code like #000000, #FFFFFF, etc."
        ),
        pattern=r"^#[0-9a-fA-F]{6}$",
    )

    @field_validator("title", mode="before")
    @classmethod
    def clean_title(cls, v: str) -> str:
        return v.strip()

    @field_validator("description", mode="before")
    @classmethod
    def clean_description(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return v.strip()
        return v

    @field_validator("start_date")
    def validate_start_date(cls, v: Optional[date]) -> Optional[date]:
        if v and v < date.today():
            raise RequestValidationError(
                [
                    {
                        "type": "past_date",
                        "loc": ("body", "start_date"),
                        "msg": "Start date cannot be in the past",
                    }
                ],
                body=cls.model_json_schema(),
            )
        return v

    @field_validator("due_date")
    def validate_due_date(cls, v: Optional[date]) -> Optional[date]:
        if v and v < date.today():
            raise RequestValidationError(
                [
                    {
                        "type": "past_date",
                        "loc": ("body", "due_date"),
                        "msg": "Due date cannot be in the past",
                    }
                ],
                body=cls.model_json_schema(),
            )
        return v


class CreateProject201Response(BaseModel):
    """Response model for creating a new project."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Project created successfully",
                "project_id": "12345678-9012-3456-7890-123456789012",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")
    project_id: UUID4 = Field(..., description="The ID of the created project.")
