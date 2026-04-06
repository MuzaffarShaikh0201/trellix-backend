"""
Services initialization.
"""

from .auth import create_user, user_exists

__all__ = ["create_user", "user_exists"]
