"""
Routes initialization.
"""

from .misc import router as misc_router
from .auth import router as auth_router

__all__ = ["misc_router", "auth_router"]
