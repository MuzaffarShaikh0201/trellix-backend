"""
Pydantic models for miscellaneous routes.
These models are used for API request/response validation.
"""

from typing import Dict
from pydantic import BaseModel, ConfigDict, Field

from ..config import settings


class Root200Response(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "service": "Trellix Backend",
                "version": "0.1.0",
                "docs": f"{settings.base_url}/docs",
            }
        },
    )

    service: str = Field(description="The name of the service.")
    version: str = Field(description="The version of the service.")
    docs: str = Field(description="The URL of the documentation.")


class Health200Response(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "service": "Trellix Backend",
                "version": "0.1.0",
                "dependencies": {
                    "redis": "healthy",
                    "database": "healthy",
                },
            }
        }
    )

    status: str = Field(description="The health status of the application.")
    service: str = Field(description="The name of the service.")
    version: str = Field(description="The version of the service.")
    dependencies: Dict[str, str] = Field(description="The dependencies of the service.")
