"""
Enums for the application.
These enums are used for database model validation.
"""

from enum import StrEnum


class AuthTypeEnum(StrEnum):
    """Authentication type used by the user to register or login."""

    EMAIL = "email"
    OAUTH = "oauth"


class ProjectStatusEnum(StrEnum):
    """Lifecycle status for a project."""

    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    ON_HOLD = "ON_HOLD"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    ARCHIVED = "ARCHIVED"


class ProjectPriorityEnum(StrEnum):
    """Priority level for project planning."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ProjectCategoryEnum(StrEnum):
    """Category classification for projects."""

    WORK = "WORK"
    PERSONAL = "PERSONAL"
    LEARNING = "LEARNING"
    HEALTH = "HEALTH"
    FINANCE = "FINANCE"
    SIDE_PROJECT = "SIDE_PROJECT"
    CREATIVE = "CREATIVE"
    TRAVEL = "TRAVEL"
    HOME = "HOME"
    OTHER = "OTHER"
