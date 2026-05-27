"""
Note routes.
"""

from pydantic import UUID4
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, Path, status

from ..utils import get_logger
from ..db import get_db_session
from ..auth import bearer_header_auth
from ..services import (
    create_note,
    delete_note_by_id,
    get_all_notes_by_user_id,
    get_note_by_id,
    toggle_note_pinned_status_by_id,
    update_note_by_id,
)
from ..models import (
    CreateNoteParams,
    CreateNote201Response,
    DeleteNote200Response,
    GetAllNotesParams,
    GetAllNotes200Response,
    GetNote200Response,
    ToggleNotePin200Response,
    UpdateNote200Response,
    UpdateNoteParams,
    UserCreds,
)

logger = get_logger(__name__)
router = APIRouter(tags=["Note APIs"], prefix="/note")


@router.get(
    path="",
    summary="Get all notes",
    description=(
        "Get all notes for the current user (excludes soft-deleted notes).\n"
        "Use personal=true to return only notes not linked to a project.\n"
        "Pinned notes appear first, then results are sorted by the requested field.\n"
        "Pagination is supported."
    ),
    status_code=status.HTTP_200_OK,
    response_model=GetAllNotes200Response,
)
async def get_all_notes(
    params: GetAllNotesParams = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Get all notes for the current user.

    # Args:
    - params: GetAllNotesParams - Query parameters.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the list of notes.
    """

    logger.info("GET /note - Get all notes endpoint called")

    notes, total_pages, total_items = await get_all_notes_by_user_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        page=params.page,
        limit=params.limit,
        sort_by=params.sort_by,
        sort_order=params.sort_order,
        project_id=params.project_id,
        personal=params.personal,
    )

    logger.info("GET /note - Response: 200 OK - Notes fetched successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GetAllNotes200Response(
            notes=notes,
            total_pages=total_pages,
            total_items=total_items,
            current_page=params.page,
            items_per_page=params.limit,
        ).model_dump(mode="json"),
    )


@router.get(
    path="/{note_id}",
    summary="Get note by ID",
    description="Get note by ID for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=GetNote200Response,
)
async def get_note(
    note_id: UUID4 = Path(..., description="The ID of the note."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Get note by ID for the current user.

    # Args:
    - note_id: UUID4 - The ID of the note.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the note.
    """

    logger.info("GET /note/{note_id} - Get note by ID endpoint called")

    note = await get_note_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        note_id=note_id,
    )

    logger.info("GET /note/{note_id} - Response: 200 OK - Note fetched successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=GetNote200Response.model_validate(note).model_dump(mode="json"),
    )


@router.post(
    path="",
    summary="Create new note",
    description=(
        "Create a new note for the current user. "
        "Omit project_id for a personal note, or provide a project_id "
        "to attach the note to one of your projects."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=CreateNote201Response,
)
async def create_new_note(
    params: CreateNoteParams = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Create a new note for the current user with the given request data.

    # Args:
    - params: CreateNoteParams - The request data object.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - db_session: AsyncSession - The database session.

    # Returns:
    - JSONResponse: A JSON response containing the note ID.
    """

    logger.info("POST /note - Create new note endpoint called")

    note = await create_note(
        db_session=db_session,
        user_creds=user_creds,
        title=params.title,
        content=params.content,
        project_id=params.project_id,
    )

    logger.info("POST /note - Response: 201 Created - Note created successfully")

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=CreateNote201Response(
            note_id=note.id,
        ).model_dump(mode="json"),
    )


@router.patch(
    path="/{note_id}/toggle-pinned",
    summary="Toggle note pinned status",
    description="Toggle note pinned status for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=ToggleNotePin200Response,
)
async def toggle_note_pinned_status(
    note_id: UUID4 = Path(..., description="The ID of the note."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Toggle note pinned status for the current user.
    """
    logger.info(
        "PATCH /note/{note_id}/toggle-pinned - Toggle note pinned status endpoint called"
    )

    await toggle_note_pinned_status_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        note_id=note_id,
    )

    logger.info(
        "PATCH /note/{note_id}/toggle-pinned - Response: 200 OK - Note pinned status toggled successfully"
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ToggleNotePin200Response(
            message="Note pinned status toggled successfully",
        ).model_dump(mode="json"),
    )


@router.put(
    path="/{note_id}",
    summary="Update note",
    description="Update note fields for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=UpdateNote200Response,
)
async def update_note(
    params: UpdateNoteParams = Depends(),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Update note for the current user.
    """
    logger.info("PUT /note/{note_id} - Update note endpoint called")

    await update_note_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        note_id=params.note_id,
        title=params.title,
        content=params.content,
        project_id=params.project_id,
    )

    logger.info("PUT /note/{note_id} - Response: 200 OK - Note updated successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=UpdateNote200Response(
            message="Note updated successfully",
        ).model_dump(mode="json"),
    )


@router.delete(
    path="/{note_id}",
    summary="Delete note",
    description="Soft-delete a note for the current user.",
    status_code=status.HTTP_200_OK,
    response_model=DeleteNote200Response,
)
async def delete_note(
    note_id: UUID4 = Path(..., description="The ID of the note."),
    user_creds: UserCreds = Depends(bearer_header_auth),
    db_session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Soft-delete note for the current user.
    """
    logger.info("DELETE /note/{note_id} - Delete note endpoint called")

    await delete_note_by_id(
        db_session=db_session,
        user_id=user_creds.user_id,
        note_id=note_id,
    )

    logger.info("DELETE /note/{note_id} - Response: 200 OK - Note deleted successfully")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=DeleteNote200Response(
            message="Note deleted successfully",
        ).model_dump(mode="json"),
    )
