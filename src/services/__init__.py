"""
Services initialization.
"""

from .auth import (
    hash_password,
    verify_password,
    generate_jwt_tokens,
    verify_refresh_token,
)
from .user import find_user_by_email, get_user_by_email, create_user, get_user_by_id
from .note import (
    create_note,
    delete_note_by_id,
    get_all_notes_by_user_id,
    get_note_by_id,
    toggle_note_pinned_status_by_id,
    update_note_by_id,
)
from .project import (
    create_project,
    get_all_projects_by_user_id,
    get_recent_projects_by_user_id,
    get_project_by_id,
    toggle_project_favorite_status_by_id,
    toggle_project_archived_status_by_id,
    update_project_by_id,
    delete_project_by_id,
)

__all__ = [
    "create_user",
    "find_user_by_email",
    "get_user_by_email",
    "get_user_by_id",
    "hash_password",
    "verify_password",
    "generate_jwt_tokens",
    "verify_refresh_token",
    "create_note",
    "get_all_notes_by_user_id",
    "get_note_by_id",
    "toggle_note_pinned_status_by_id",
    "update_note_by_id",
    "delete_note_by_id",
    "create_project",
    "get_all_projects_by_user_id",
    "get_recent_projects_by_user_id",
    "get_project_by_id",
    "toggle_project_favorite_status_by_id",
    "toggle_project_archived_status_by_id",
    "update_project_by_id",
    "delete_project_by_id",
]
