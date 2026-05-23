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

    PLANNING = "PLANNING"
    IN_PROGRESS = "IN_PROGRESS"
    ON_HOLD = "ON_HOLD"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"


class ProjectPriorityEnum(StrEnum):
    """Priority level for project planning."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TaskStatusEnum(StrEnum):
    """Task workflow status."""

    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    IN_REVIEW = "IN_REVIEW"
    DONE = "DONE"
    BLOCKED = "BLOCKED"


class TaskTypeEnum(StrEnum):
    """Task type."""

    FEATURE = "FEATURE"
    BUG = "BUG"
    REFACTOR = "REFACTOR"
    DOCS = "DOCS"
    TEST = "TEST"
    CHORE = "CHORE"


class TaskDomainEnum(StrEnum):
    """Task domain / area (replaces project-level category for tasks)."""

    BACKEND = "BACKEND"
    FRONTEND = "FRONTEND"
    DEVOPS = "DEVOPS"
    DATABASE = "DATABASE"
    TESTING = "TESTING"
    INFRA = "INFRA"
    OTHER = "OTHER"


class TaskPriorityEnum(StrEnum):
    """Task priority level."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"
