"""
Routes initialization.
"""

from .misc import router as misc_router
from .auth import router as auth_router
from .project import router as project_router
from .user import router as user_router

__all__ = ["misc_router", "auth_router", "project_router", "user_router"]
