from uuid import UUID
from pydantic import BaseModel, Field
from typing import Literal, TypedDict, Union

from ..schemas.user_schemas import UserProfileData

from .default_schemas import (
    CreatedResponse,
    SuccessfulResponse,
    BackendErrorResponse,
    NotFoundErrorResponse,
    ConflictErrorResponse,
    ForbiddenErrorResponse,
    ValidationErrorResponse,
    UnauthorizedErrorResponse,
    TooManyRequestsErrorResponse,
)


class TokenData(BaseModel):
    session_id: UUID = Field(..., description="Session ID of the user")
    access_token: str = Field(..., description="Access token of the user")
    refresh_token: str = Field(..., description="Refresh token of the user")
    token_type: str = Field(..., description="Token type of the user")


class SessionData(TypedDict):
    session_id: UUID
    user_id: UUID
    email: str


class LoginSuccessfulMeta(BaseModel):
    user: UserProfileData = Field(..., description="User data of the user")


class LoginSuccessfulResponse(SuccessfulResponse):
    message: Literal["User logged in successfully"]
    data: TokenData
    meta: LoginSuccessfulMeta


class LoginUnauthorizedError(BaseModel):
    code: Literal["INVALID_CREDENTIALS"]
    details: Union[
        Literal[
            "The provided credentials are incorrect. Please check your email and password."
        ],
    ]


class LoginUnauthorizedErrorResponse(UnauthorizedErrorResponse):
    message: Literal["Invalid credentials"]
    error: LoginUnauthorizedError


class LoginNotFoundError(BaseModel):
    code: Literal["NOT_FOUND"]
    details: Literal[
        "User with the provided email does not exist. Please register or try with a different email."
    ]


class LoginNotFoundErrorResponse(NotFoundErrorResponse):
    message: Literal["User not found"]
    error: LoginNotFoundError


class LoginBackendError(BaseModel):
    code: Literal["INTERNAL_SERVER_ERROR"]
    details: Literal[
        "Something went wrong while trying to log in. Please try again later or contact support if the issue persists."
    ]


class LoginBackendErrorResponse(BackendErrorResponse):
    message: str = "User login failed"
    error: LoginBackendError


LOGIN_RESPONSE_MODEL = {
    200: {"model": LoginSuccessfulResponse},
    401: {"model": LoginUnauthorizedErrorResponse},
    404: {"model": LoginNotFoundErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsErrorResponse},
    500: {"model": LoginBackendErrorResponse},
}


class RegistrationSuccessfulResponse(CreatedResponse):
    message: Literal["User registered successfully"]


class RegistrationConflictError(BaseModel):
    code: Literal["CONFLICT"]
    details: Literal[
        "User with the provided email already exists. Please login or try with a different email."
    ]


class RegistrationConflictErrorResponse(ConflictErrorResponse):
    message: str = "User already exists"
    error: RegistrationConflictError


class RegistrationBackendError(BaseModel):
    code: Literal["INTERNAL_SERVER_ERROR"]
    details: Literal[
        "Something went wrong while trying to register the user. Please try again later or contact support if the issue persists."
    ]


class RegistrationBackendErrorResponse(BackendErrorResponse):
    message: str = "User registration failed"
    error: RegistrationBackendError


REGISTRATION_RESPONSE_MODEL = {
    201: {"model": RegistrationSuccessfulResponse},
    409: {"model": RegistrationConflictErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsErrorResponse},
    500: {"model": RegistrationBackendErrorResponse},
}


class LogoutSuccessResponse(SuccessfulResponse):
    message: str = "User logged out successfully"


class LogoutUnauthorizedError(BaseModel):
    code: Literal["UNAUTHORIZED"]
    details: Union[
        Literal["Missing Authorization header. Please provide a valid Bearer token."],
        Literal["Invalid Authorization header. Please provide a valid Bearer token."],
        Literal["Invalid token. Please provide a valid Bearer token."],
        Literal["Token expired. Please refresh the token or login again."],
        Literal["Invalid token structure. Please provide a valid Bearer token."],
        Literal["Invalid token data. Please provide a valid Bearer token."],
    ]


class LogoutUnauthorizedErrorResponse(UnauthorizedErrorResponse):
    message: Literal["Unauthorized access"]
    error: LogoutUnauthorizedError


class LogoutForbiddenError(BaseModel):
    code: Literal["FORBIDDEN"]
    details: Literal[
        "You are not authorized to access this resource. Please contact support if required."
    ]


class ForbiddenErrorResponse(ForbiddenErrorResponse):
    message: Literal["Forbidden access"]
    error: LogoutForbiddenError


class LogoutBackendError(BaseModel):
    code: Literal["INTERNAL_SERVER_ERROR"]
    details: Literal[
        "Something went wrong while trying to log out. Please try again later or contact support if the issue persists."
    ]


class LogoutBackendErrorResponse(BackendErrorResponse):
    message: str = "User logout failed"
    error: LogoutBackendError


LOGOUT_RESPONSE_MODEL = {
    200: {"model": LogoutSuccessResponse},
    401: {"model": LogoutUnauthorizedErrorResponse},
    403: {"model": ForbiddenErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsErrorResponse},
    500: {"model": LogoutBackendErrorResponse},
}


class RefreshSessionSuccessfulResponse(SuccessfulResponse):
    message: Literal["Session refreshed successfully"]
    data: TokenData
    meta: LoginSuccessfulMeta


class RefreshSessionUnauthorizedError(BaseModel):
    code: Literal["UNAUTHORIZED"]
    details: Union[
        Literal["The provided refresh token is invalid. Please log in again."],
        Literal["The provided refresh token has expired. Please log in again."],
        Literal["The provided session is invalid. Please log in again."],
    ]


class RefreshSessionUnauthorizedErrorResponse(UnauthorizedErrorResponse):
    message: Union[
        Literal["Invalid refresh token"],
        Literal["Refresh token expired"],
        Literal["Invalid session"],
    ]
    error: RefreshSessionUnauthorizedError


class RefreshSessionForbiddenError(BaseModel):
    code: Literal["FORBIDDEN"]
    details: Literal[
        "Access from this user is not allowed. Please contact support if required."
    ]


class RefreshSessionForbiddenErrorResponse(ForbiddenErrorResponse):
    message: Literal["Forbidden access"]
    error: RefreshSessionForbiddenError


class RefreshSessionBackendError(BaseModel):
    code: Literal["INTERNAL_SERVER_ERROR"]
    details: Literal[
        "Something went wrong while trying to refresh the session. Please try again later or contact support if the issue persists."
    ]


class RefreshSessionBackendErrorResponse(BackendErrorResponse):
    message: str = "Session refresh failed"
    error: RefreshSessionBackendError


REFRESH_SESSION_RESPONSE_MODEL = {
    200: {"model": RefreshSessionSuccessfulResponse},
    401: {"model": RefreshSessionUnauthorizedErrorResponse},
    403: {"model": RefreshSessionForbiddenErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsErrorResponse},
    500: {"model": RefreshSessionBackendErrorResponse},
}
