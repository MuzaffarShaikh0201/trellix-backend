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

    PLANNED = "PLANNED"
    ACTIVE = "ACTIVE"
    ON_HOLD = "ON_HOLD"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class ProjectPriorityEnum(StrEnum):
    """Priority level for project planning."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ProjectTypeEnum(StrEnum):
    """Project type classification."""

    WEB_APP = "WEB_APP"
    MOBILE_APP = "MOBILE_APP"
    API = "API"
    CLI = "CLI"
    LIBRARY = "LIBRARY"
    FULL_STACK = "FULL_STACK"


class ProjectStageEnum(StrEnum):
    """Current stage of project lifecycle."""

    IDEA = "IDEA"
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    PRODUCTION = "PRODUCTION"
    MAINTENANCE = "MAINTENANCE"
    DEPRECATED = "DEPRECATED"


class ProjectTechStackTypeEnum(StrEnum):
    """Project technology stack component type."""

    BACKEND = "BACKEND"
    FRONTEND = "FRONTEND"
    DATABASE = "DATABASE"
    DEVOPS = "DEVOPS"
    OTHER = "OTHER"


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
