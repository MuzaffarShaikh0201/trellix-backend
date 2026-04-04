from enum import StrEnum


class AuthTypeEnum(StrEnum):
    """Authentication type used by the user to register or login."""

    EMAIL = "EMAIL"
    OAUTH = "OAUTH"
