"""
Pydantic models for note routes.
These models are used for API request/response validation.
"""

from copy import deepcopy
from datetime import datetime
from typing import Literal, Optional

from fastapi import Body, Query, Path
from pydantic import UUID4, BaseModel, ConfigDict, Field


class CreateNoteParams:
    """Parameters for creating a new note."""

    def __init__(
        self,
        title: str = Body(
            ...,
            description=(
                "The title of the note.\n"
                "Title must contain only letters, numbers, spaces, hyphens (-), "
                "underscores (_), periods (.), and apostrophes ('). "
                "No special characters like @, #, $, %, &, *, etc."
            ),
            min_length=1,
            max_length=255,
            pattern=r"^[a-zA-Z0-9\s\-_\.\']+$",
        ),
        content: Optional[str] = Body(
            None,
            description="Markdown content of the note.",
        ),
        project_id: Optional[UUID4] = Body(
            None,
            description=(
                "Optional project ID. When omitted, creates a personal note "
                "not linked to any project."
            ),
        ),
    ) -> None:
        self.title = title.strip()
        self.content = content.strip() if content else None
        self.project_id = project_id


class CreateNote201Response(BaseModel):
    """Response model for creating a new note."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "note_id": "12345678-9012-3456-7890-123456789012",
            }
        },
    )

    note_id: UUID4 = Field(..., description="The ID of the created note.")


class GetAllNotesParams:
    """Parameters for getting all notes."""

    def __init__(
        self,
        project_id: Optional[UUID4] = Query(
            None,
            description="Filter notes by project ID. Omit to include all notes.",
        ),
        personal: bool = Query(
            default=False,
            description="When true, return only personal notes (not linked to a project).",
        ),
        page: int = Query(default=1, description="The page number.", ge=1),
        limit: int = Query(
            default=10,
            description="The number of notes per page.",
            ge=1,
            le=100,
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
        self.project_id = project_id
        self.personal = personal
        self.page = page
        self.limit = limit
        self.sort_by = sort_by
        self.sort_order = sort_order


class NoteResponseProject(BaseModel):
    """Project response DTO for API payloads."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "12345678-9012-3456-7890-123456789012",
                "title": "Project 1",
            }
        },
    )

    id: UUID4 = Field(..., description="The project ID.")
    title: str = Field(..., description="The title of the project.")


class NoteResponse(BaseModel):
    """Note summary DTO for list API payloads."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "12345678-9012-3456-7890-123456789012",
                "title": "Meeting notes",
                "project": {
                    "id": "12345678-9012-3456-7890-123456789012",
                    "title": "Project 1",
                },
                "is_pinned": True,
                "updated_at": "2026-01-01T00:00:00Z",
            }
        },
    )

    id: UUID4 = Field(..., description="The note ID.")
    title: str = Field(..., description="The title of the note.")
    project: Optional[NoteResponseProject] = Field(
        None, description="Linked project, if any."
    )
    is_pinned: bool = Field(..., description="Whether the note is pinned.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class GetAllNotes200Response(BaseModel):
    """Response model for getting all notes."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "notes": [
                    {
                        "id": "12345678-9012-3456-7890-123456789012",
                        "title": "Personal note",
                        "project": {
                            "id": "12345678-9012-3456-7890-123456789012",
                            "title": "Project 1",
                        },
                        "is_pinned": True,
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ],
                "total_pages": 1,
                "total_items": 1,
                "current_page": 1,
                "items_per_page": 10,
            }
        },
    )

    notes: list[NoteResponse] = Field(..., description="The list of notes.")
    total_pages: int = Field(..., description="The total number of pages.")
    total_items: int = Field(..., description="The total number of items.")
    current_page: int = Field(..., description="The current page number.")
    items_per_page: int = Field(..., description="The number of items per page.")


class NoteDetailResponse(BaseModel):
    """Note detail DTO with all table fields except user_id."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "12345678-9012-3456-7890-123456789012",
                "project": {
                    "id": "12345678-9012-3456-7890-123456789012",
                    "title": "Project 1",
                },
                "title": "Meeting notes",
                "content": "## Agenda\n- Kickoff",
                "is_pinned": True,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        },
    )

    id: UUID4 = Field(..., description="The note ID.")
    project: Optional[NoteResponseProject] = Field(
        None, description="Linked project, if any."
    )
    title: str = Field(..., description="The title of the note.")
    content: Optional[str] = Field(None, description="Markdown content of the note.")
    is_pinned: bool = Field(..., description="Whether the note is pinned.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class GetNote200Response(NoteDetailResponse):
    """Response model for getting a note by ID."""

    _parent_json_schema_extra = deepcopy(
        NoteDetailResponse.model_config.get("json_schema_extra", {})
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


class ToggleNotePin200Response(BaseModel):
    """Response model for toggling note pinned status."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Note pinned status toggled successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class UpdateNoteParams:
    """Parameters for updating a note."""

    def __init__(
        self,
        note_id: UUID4 = Path(..., description="The ID of the note."),
        title: Optional[str] = Body(
            None,
            description=(
                "The title of the note.\n"
                "Title must contain only letters, numbers, spaces, hyphens (-), "
                "underscores (_), periods (.), and apostrophes ('). "
                "No special characters like @, #, $, %, &, *, etc."
            ),
            min_length=1,
            max_length=255,
            pattern=r"^[a-zA-Z0-9\s\-_\.\']+$",
        ),
        content: Optional[str] = Body(
            None,
            description="Markdown content of the note.",
        ),
        project_id: Optional[UUID4] = Body(
            None,
            description=(
                "Optional project ID to link the note to. "
                "When omitted, the current project link is kept."
            ),
        ),
    ) -> None:
        self.note_id = note_id
        self.title = title.strip() if title else None
        self.content = content.strip() if content else None
        self.project_id = project_id


class UpdateNote200Response(BaseModel):
    """Response model for updating a note."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Note updated successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class DeleteNote200Response(BaseModel):
    """Response model for deleting a note."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Note deleted successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")
