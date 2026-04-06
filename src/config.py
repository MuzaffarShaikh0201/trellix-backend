"""
Configuration for Trellix Backend.
All settings are loaded from environment variables (no defaults).
"""

from pathlib import Path
from pydantic import Field
from functools import cached_property, lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings - all from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Application settings
    app_name: str = Field(..., description="Application name")
    app_version: str = Field(..., description="Application version")
    base_url: str = Field(..., description="Base URL")
    log_level: str = Field(..., description="Logging level")
    support_email: str = Field(..., description="Support email")

    # PostgreSQL settings
    postgres_user: str = Field(..., description="PostgreSQL user")
    postgres_password: str = Field(..., description="PostgreSQL password")
    postgres_host: str = Field(..., description="PostgreSQL host")
    postgres_port: int = Field(..., description="PostgreSQL port")
    postgres_db: str = Field(..., description="PostgreSQL database")
    postgres_schema: str = Field(
        default="public",
        description="PostgreSQL schema for ORM tables (use public unless you isolate app objects)",
    )
    postgres_pool_size: int = Field(..., description="PostgreSQL pool size")
    postgres_max_overflow: int = Field(..., description="PostgreSQL max overflow")

    # Redis settings
    redis_host: str = Field(..., description="Redis host")
    redis_port: int = Field(..., description="Redis port")
    redis_username: str = Field(..., description="Redis username")
    redis_password: str = Field(..., description="Redis password (empty if none)")
    redis_pool_size: int = Field(..., description="Redis pool size")

    # Supabase settings
    supabase_url: str = Field(..., description="Supabase URL")
    supabase_key: str = Field(..., description="Supabase key")
    bucket_name: str = Field(..., description="Supabase bucket name")

    # JWT settings
    jwt_secret_key: str = Field(..., description="JWT secret key")
    jwt_algorithm: str = Field(..., description="JWT algorithm")
    jwt_expiration_time: int = Field(..., description="JWT expiration time in minutes")
    jwt_refresh_time: int = Field(..., description="JWT refresh time in hours")

    @property
    def postgres_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_url_sync(self) -> str:
        """Generate synchronous PostgreSQL connection URL (for Alembic)."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Generate Redis connection URL."""
        return (
            f"redis://{self.redis_username}:{self.redis_password}"
            f"@{self.redis_host}:{self.redis_port}"
        )

    @cached_property
    def PRIVATE_KEY(self) -> str:
        """
        Reads and returns the private key from the file.
        """
        private_key_path = Path("keys/private.pem")
        if not private_key_path.is_file():
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        return private_key_path.read_text()

    @cached_property
    def PUBLIC_KEY(self) -> str:
        """
        Reads and returns the public key from the file.
        """
        public_key_path = Path("keys/public.pem")
        if not public_key_path.is_file():
            raise FileNotFoundError(f"Public key file not found: {public_key_path}")
        return public_key_path.read_text()


@lru_cache
def get_settings() -> Settings:
    """Get application settings - cached."""

    return Settings()


settings = get_settings()
