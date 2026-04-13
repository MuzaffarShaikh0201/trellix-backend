"""
Pydantic models for user routes.
These models are used for API request/response validation.
"""

from typing import Optional
from datetime import datetime
from fastapi import Body, Form
from pydantic import UUID4, SecretStr
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .enums import AuthTypeEnum
from .auth import validate_name, validate_password


class GetUser200Response(BaseModel):
    """Response model for getting a user by ID."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "12345678-9012-3456-7890-123456789012",
                "first_name": "John",
                "last_name": "Doe",
                "email": "john.doe@example.com",
                "auth_type": AuthTypeEnum.EMAIL,
                "is_active": True,
                "last_logged_in": "2026-04-07T12:00:00.000000",
                "created_at": "2026-04-07T12:00:00.000000",
                "updated_at": "2026-04-07T12:00:00.000000",
            }
        },
    )

    id: UUID4 = Field(..., description="The ID of the user.")
    first_name: str = Field(..., description="The first name of the user.")
    last_name: str = Field(..., description="The last name of the user.")
    email: EmailStr = Field(..., description="The email of the user.")
    auth_type: AuthTypeEnum = Field(
        ..., description="The authentication type of the user."
    )
    is_active: bool = Field(..., description="Whether the user is active.")
    last_logged_in: datetime = Field(
        ..., description="The last login date of the user."
    )
    created_at: datetime = Field(..., description="The creation date of the user.")
    updated_at: datetime = Field(..., description="The last update date of the user.")


class UpdateUserParams:
    """Parameters for updating a user."""

    def __init__(
        self,
        first_name: Optional[str] = Body(
            None, description="The first name of the user.", min_length=1, max_length=32
        ),
        last_name: Optional[str] = Body(
            None, description="The last name of the user.", min_length=1, max_length=32
        ),
    ) -> None:
        self.first_name = validate_name(first_name, "first_name")
        self.last_name = validate_name(last_name, "last_name")


class UpdateUser200Response(BaseModel):
    """Response model for updating a user."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "User updated successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class UpdateUserPasswordParams:
    """Parameters for updating a user password."""

    def __init__(
        self,
        current_password: SecretStr = Form(
            ...,
            description="The current password of the user.",
            min_length=8,
            max_length=20,
        ),
        new_password: SecretStr = Form(
            ...,
            description="The new password of the user.",
            min_length=8,
            max_length=20,
        ),
    ) -> None:
        self.current_password = validate_password(current_password)
        self.new_password = validate_password(new_password)


class UpdateUserPassword200Response(BaseModel):
    """Response model for updating a user password."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "User password updated successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")
