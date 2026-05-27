"""
Note services.
These services are used for note-related operations.
"""

import math

from pydantic import UUID4
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..utils import get_logger
from ..models import Note, Project, UserCreds


logger = get_logger(__name__)


async def create_note(
    db_session: AsyncSession,
    user_creds: UserCreds,
    title: str,
    content: str | None,
    project_id: UUID4 | None,
) -> Note:
    """
    Create a new note for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_creds: UserCreds - The user credentials from the bearer header authentication.
    - title: str - The note title.
    - content: str | None - Markdown content.
    - project_id: UUID4 | None - Optional project to link the note to.

    # Returns:
    - Note: The created note.

    # Raises:
    - HTTPException: If project validation or note creation fails.
    """

    try:
        if project_id is not None:
            project_stmt = select(Project).where(
                Project.id == project_id,
                Project.user_id == user_creds.user_id,
            )
            project_result = await db_session.execute(project_stmt)
            project = project_result.scalar_one_or_none()

            if not project:
                raise HTTPException(
                    status_code=404,
                    detail="Project not found.",
                )

        note = Note(
            user_id=user_creds.user_id,
            project_id=project_id,
            title=title,
            content=content,
        )
        db_session.add(note)
        await db_session.commit()

        logger.info(f"Note created successfully: {note.id}")
        return note
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating note: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not create note. Please try again.",
        )


async def get_all_notes_by_user_id(
    db_session: AsyncSession,
    user_id: UUID4,
    page: int,
    limit: int,
    sort_by: str,
    sort_order: str,
    project_id: UUID4 | None,
    personal: bool,
) -> tuple[list[Note], int, int]:
    """
    Get all notes by user ID (excludes soft-deleted notes).
    Pinned notes are ordered first, then by the requested sort field.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - page: int - The page number.
    - limit: int - The number of notes per page.
    - sort_by: str - The field to sort by.
    - sort_order: str - The order to sort by.
    - project_id: UUID4 | None - Optional project filter.
    - personal: bool - When true, return only notes with no project link.

    # Returns:
    - tuple[list[Note], int, int]: Notes, total pages, total item count.

    # Raises:
    - HTTPException: If note retrieval or project validation fails.
    """

    try:
        if personal:
            notes_stmt = select(Note).where(
                Note.user_id == user_id,
                Note.is_deleted == False,
                Note.project_id.is_(None),
            )
        else:
            if project_id is not None:
                project_stmt = select(Project).where(
                    Project.id == project_id,
                    Project.user_id == user_id,
                )
                project_result = await db_session.execute(project_stmt)
                project = project_result.scalar_one_or_none()

                if not project:
                    raise HTTPException(
                        status_code=404,
                        detail="Project not found.",
                    )

            notes_stmt = select(Note).where(
                Note.user_id == user_id,
                Note.is_deleted == False,
            )

            if project_id is not None:
                notes_stmt = notes_stmt.where(Note.project_id == project_id)

        count_stmt = select(func.count()).select_from(notes_stmt)
        total_items_result = await db_session.execute(count_stmt)
        total_items = total_items_result.scalar_one()
        total_pages = math.ceil(total_items / limit)

        sort_column = getattr(Note, sort_by)
        sort_expr = sort_column.asc() if sort_order == "asc" else sort_column.desc()

        notes_stmt = notes_stmt.order_by(Note.is_pinned.desc(), sort_expr)
        notes_stmt = notes_stmt.offset((page - 1) * limit).limit(limit)

        notes_stmt = notes_stmt.options(selectinload(Note.project))

        notes_result = await db_session.execute(notes_stmt)
        notes = list(notes_result.scalars().all())

        logger.info(
            f"Notes fetched successfully for user ID: {user_id} - "
            f"{total_items} notes - {total_pages} pages - page {page} - limit {limit}"
        )
        return notes, total_pages, total_items
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting notes by user ID: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not get notes. Please try again.",
        )


async def get_note_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    note_id: UUID4,
) -> Note:
    """
    Get a note by ID for the current user.

    # Args:
    - db_session: AsyncSession - The database session.
    - user_id: UUID4 - The user ID.
    - note_id: UUID4 - The ID of the note.

    # Returns:
    - Note: The note object.

    # Raises:
    - HTTPException: If the note is not found or retrieval fails.
    """

    try:
        note_stmt = select(Note).where(
            Note.id == note_id,
            Note.user_id == user_id,
            Note.is_deleted == False,
        )
        note_stmt = note_stmt.options(selectinload(Note.project))
        note_result = await db_session.execute(note_stmt)
        note = note_result.scalar_one_or_none()

        if not note:
            raise HTTPException(
                status_code=404,
                detail="Note not found.",
            )

        logger.info(
            f"Note fetched successfully by ID: {note_id} for user ID: {user_id}"
        )
        return note
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting note by ID: {str(e)} for user ID: {user_id}")
        raise HTTPException(
            status_code=500,
            detail="Could not get note by ID. Please try again.",
        )


async def toggle_note_pinned_status_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    note_id: UUID4,
) -> None:
    """
    Toggle note pinned status for the current user.
    """
    try:
        note_stmt = select(Note).where(
            Note.id == note_id,
            Note.user_id == user_id,
            Note.is_deleted == False,
        )
        note_result = await db_session.execute(note_stmt)
        note = note_result.scalar_one_or_none()

        if not note:
            raise HTTPException(
                status_code=404,
                detail="Note not found.",
            )

        note.is_pinned = not note.is_pinned
        await db_session.commit()

        logger.info(f"Note pinned status toggled successfully for note ID: {note_id}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Error toggling note pinned status by ID: {str(e)} for note ID: {note_id}"
        )
        raise HTTPException(
            status_code=500,
            detail="Could not toggle note pinned status. Please try again.",
        )


async def update_note_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    note_id: UUID4,
    title: str | None,
    content: str | None,
    project_id: UUID4 | None,
) -> None:
    """
    Update a note by ID for the current user.
    """
    try:
        note_stmt = select(Note).where(
            Note.id == note_id,
            Note.user_id == user_id,
            Note.is_deleted == False,
        )
        note_result = await db_session.execute(note_stmt)
        note = note_result.scalar_one_or_none()

        if not note:
            raise HTTPException(
                status_code=404,
                detail="Note not found.",
            )

        if title is not None:
            note.title = title.strip()
        if content is not None:
            note.content = content.strip() or None

        if project_id is not None:
            project_stmt = select(Project).where(
                Project.id == project_id,
                Project.user_id == user_id,
            )
            project_result = await db_session.execute(project_stmt)
            project = project_result.scalar_one_or_none()

            if not project:
                raise HTTPException(
                    status_code=404,
                    detail="Project not found.",
                )

            note.project_id = project_id

        await db_session.commit()
        logger.info(f"Note updated successfully by ID: {note_id}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error updating note by ID: {str(e)} for note ID: {note_id}")
        raise HTTPException(
            status_code=500,
            detail="Could not update note. Please try again.",
        )


async def delete_note_by_id(
    db_session: AsyncSession,
    user_id: UUID4,
    note_id: UUID4,
) -> None:
    """
    Soft-delete a note (set is_deleted=true) for the current user.
    """
    try:
        note_stmt = select(Note).where(
            Note.id == note_id,
            Note.user_id == user_id,
            Note.is_deleted == False,
        )
        note_result = await db_session.execute(note_stmt)
        note = note_result.scalar_one_or_none()

        if not note:
            raise HTTPException(
                status_code=404,
                detail="Note not found.",
            )

        note.is_deleted = True
        note.is_pinned = False
        await db_session.commit()

        logger.info(f"Note deleted successfully by ID: {note_id}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error deleting note by ID: {str(e)} for note ID: {note_id}")
        raise HTTPException(
            status_code=500,
            detail="Could not delete note. Please try again.",
        )
