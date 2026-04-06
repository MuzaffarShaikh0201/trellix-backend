import re
from uuid import UUID
from fastapi import Form
from datetime import datetime, timezone
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator


def validate_password(password: SecretStr) -> SecretStr:
    """
    Validate password for the following conditions:
    - At least one number
    - At least one special character
    - At least one alphabet

    # Args:
    - password: SecretStr - Password to be validated

    # Returns:
    - SecretStr: Password if all conditions are met

    # Raises:
    - RequestValidationError: If any of the conditions are not met
    """
    password_value = password.get_secret_value()
    errors = []

    # At least one number
    if not re.search(r"\d", password_value):
        errors.append(
            {
                "type": "missing_number",
                "loc": ("body", "password"),
                "msg": "Value should have at least one number",
                "input": password_value,
            }
        )

    # At least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_value):
        errors.append(
            {
                "type": "missing_special_char",
                "loc": ("body", "password"),
                "msg": "Value should have at least one special character",
                "input": password_value,
            }
        )

    # At least one alphabet
    if not re.search(r"[a-zA-Z]", password_value):
        errors.append(
            {
                "type": "missing_alphabet",
                "loc": ("body", "password"),
                "msg": "Value should have at least one alphabet",
                "input": password_value,
            }
        )

    # Raise validation error if any of the conditions are not met
    if errors:
        raise RequestValidationError(errors)

    return password


def validate_name(name: str, field_name: str) -> str:
    """
    Validate name for the following conditions:
    - Should not contain spaces
    - Should only contain alphabets

    # Args:
    - name: str - Name to be validated
    - field_name: str - Field name to be used in the error message

    # Returns:
    - str - Name if all conditions are met

    # Raises:
    - RequestValidationError: If any of the conditions are not met
    """
    errors = []

    # Should not contain spaces
    if re.search(r"\s", name):
        errors.append(
            {
                "type": "invalid_name",
                "loc": ("body", field_name),
                "msg": "Name should not contain spaces",
                "input": name,
            }
        )

    # Should only contain alphabets
    if re.search(r"[^a-zA-Z]", name):
        errors.append(
            {
                "type": "invalid_name",
                "loc": ("body", field_name),
                "msg": "Name should only contain alphabets",
                "input": name,
            }
        )

    # Raise validation error if any of the conditions are not met
    if errors:
        raise RequestValidationError(errors)

    return name.strip()


class RegisterRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "test@example.com",
                "password": "********",
            }
        },
    )

    first_name: str = Form(..., description="The first name of the user.")
    last_name: str = Form(..., description="The last name of the user.")
    email: EmailStr = Form(..., description="The email of the user.")
    password: SecretStr = Form(
        ..., description="The password of the user.", min_length=8, max_length=20
    )

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: SecretStr) -> SecretStr:
        return validate_password(password)

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, first_name: str) -> str:
        return validate_name(first_name, "first_name")

    @field_validator("last_name")
    @classmethod
    def validate_last_name(cls, last_name: str) -> str:
        return validate_name(last_name, "last_name")


class Register201Response(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "User registered successfully",
            }
        },
    )

    message: str = Field(..., description="The message of the response.")


class SessionData(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "session_id": "12345678-9012-3456-7890-123456789012",
                "user_id": "12345678-9012-3456-7890-123456789012",
                "access_token": "12345678901234567890123456789012",
            }
        },
    )
    session_id: UUID = Field(..., description="The session ID.")
    user_id: UUID = Field(..., description="The user ID.")
    access_token: str = Field(..., description="The access token of the user.")


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "test@example.com",
                "password": "********",
            }
        },
    )
    email: EmailStr = Form(..., description="The email of the user.")
    password: SecretStr = Form(
        ..., description="The password of the user.", min_length=8, max_length=20
    )

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: SecretStr) -> SecretStr:
        return validate_password(password)


class Login200Response(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "User logged in successfully",
                "access_token": "12345678901234567890123456789012",
                "refresh_token": "12345678901234567890123456789012",
                "session_id": "12345678-9012-3456-7890-123456789012",
            }
        },
    )
    message: str = Field(..., description="The message of the response.")
    access_token: str = Field(..., description="The access token of the user.")
    refresh_token: str = Field(..., description="The refresh token of the user.")
    session_id: UUID = Field(..., description="The ID of the session.")


class RefreshRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "12345678901234567890123456789012",
            }
        },
    )
    refresh_token: str = Form(..., description="The refresh token of the user.")


class Refresh200Response(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Refresh token refreshed successfully",
                "access_token": "12345678901234567890123456789012",
                "refresh_token": "12345678901234567890123456789012",
                "session_id": "12345678-9012-3456-7890-123456789012",
            }
        },
    )
    message: str = Field(..., description="The message of the response.")
    access_token: str = Field(..., description="The access token of the user.")
    refresh_token: str = Field(..., description="The refresh token of the user.")
    session_id: UUID = Field(..., description="The ID of the session.")
