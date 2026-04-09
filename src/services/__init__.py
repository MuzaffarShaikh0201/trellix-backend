"""
Services initialization.
"""

from .auth import (
    hash_password,
    verify_password,
    generate_jwt_tokens,
    verify_refresh_token,
)
from .user import get_user_by_email, create_user, get_user_by_id
from .project import (
    create_project,
    get_all_projects_by_user_id,
    get_project_by_id,
    toggle_project_favorite_status_by_id,
    update_project_by_id,
    delete_project_by_id,
)

__all__ = [
    "create_user",
    "get_user_by_email",
    "get_user_by_id",
    "hash_password",
    "verify_password",
    "generate_jwt_tokens",
    "verify_refresh_token",
    "create_project",
    "get_all_projects_by_user_id",
    "get_project_by_id",
    "toggle_project_favorite_status_by_id",
    "update_project_by_id",
    "delete_project_by_id",
]
