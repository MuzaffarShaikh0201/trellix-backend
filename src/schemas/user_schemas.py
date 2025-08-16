from typing import Literal, Union
from uuid import UUID
from pydantic import BaseModel, Field

from .default_schemas import (
    ForbiddenErrorResponse,
    SuccessfulResponse,
    BackendErrorResponse,
    NotFoundErrorResponse,
    TooManyRequestsError,
    UnauthorizedErrorResponse,
    ValidationErrorResponse,
)


class UserProfileData(BaseModel):
    id: UUID = Field(..., description="ID of the user")
    email: str = Field(..., description="Email of the user")
    first_name: str = Field(..., description="First Name of the user")
    last_name: str = Field(..., description="Last Name of the user")


class GetUserProfileSuccessfulResponse(SuccessfulResponse):
    message: Literal["User profile retrieved successfully"]
    data: UserProfileData


class GetUserProfileNotFoundError(BaseModel):
    code: Literal["NOT_FOUND"]
    details: Literal[
        "User with the provided email does not exist. Please register or try with a different email."
    ]


class GetUserProfileNotFoundErrorResponse(NotFoundErrorResponse):
    message: Literal["User not found"]
    error: GetUserProfileNotFoundError


class GetUserProfileBackendError(BaseModel):
    code: Literal["INTERNAL_SERVER_ERROR"]
    details: Union[
        Literal[
            "Something went wrong while retrieving the user profile. Please try again later or contact support if the issue persists."
        ],
        Literal[
            "Something went wrong while authorizing the user. Please try again later or contact support if the issue persists."
        ],
    ]


class GetUserProfileBackendErrorResponse(BackendErrorResponse):
    message: Union[
        Literal["Failed to retrieve user profile"], Literal["User authorization failed"]
    ]
    error: dict = {
        "code": "INTERNAL_SERVER_ERROR",
        "details": "Something went wrong while retrieving the user profile. Please try again later or contact support if the issue persists.",
    }


GET_USER_RESPONSE_MODEL = {
    200: {"model": GetUserProfileSuccessfulResponse},
    401: {"model": UnauthorizedErrorResponse},
    403: {"model": ForbiddenErrorResponse},
    404: {"model": GetUserProfileNotFoundErrorResponse},
    422: {"model": ValidationErrorResponse},
    429: {"model": TooManyRequestsError},
    500: {"model": GetUserProfileBackendErrorResponse},
}
