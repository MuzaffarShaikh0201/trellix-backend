"""
Trellix Backend - Main entry point.
"""

from typing import AsyncGenerator
from fastapi import FastAPI
from contextlib import asynccontextmanager

from .config import settings
from .routers import misc_router
from .db import db_manager, redis_manager
from .utils import setup_logging, get_logger
from .custom_openapi import create_custom_openapi_generator

# Setup logging
setup_logging()
logger = get_logger(settings.app_name)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan - setup and teardown."""

    # Startup
    logger.info("Starting Trellix Backend...")

    # Initialize database connection
    logger.info("Initializing PostgreSQL connection...")
    db_manager.init()

    # Initialize Redis connection
    logger.info("Initializing Redis connection...")
    await redis_manager.init()

    # Verify connections
    redis_connected = await redis_manager.ping()
    if redis_connected:
        logger.info("✓ Redis connection successful")
    else:
        logger.error("✗ Redis connection failed")

    db_connected = await db_manager.ping()
    if db_connected:
        logger.info("✓ PostgreSQL connection successful")
    else:
        logger.error("✗ PostgreSQL connection failed")

    logger.info(f"✓ Trellix Backend started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Trellix Backend...")

    # Close Redis connection
    await redis_manager.close()
    logger.info("✓ Redis connection closed")

    # Close database connection
    await db_manager.close()
    logger.info("✓ PostgreSQL connection closed")

    logger.info("✓ Trellix Backend shutdown complete")


app = FastAPI(
    title=settings.app_name,
    description="Backend services for Trellix Project Manager.",
    version=settings.app_version,
    lifespan=lifespan,
)

# Add custom OpenAPI generator
doc_tags_metadata = [
    {
        "name": "Miscellaneous APIs",
        "description": "Miscellaneous APIs like health check, root, etc. that are not related to any specific functionality.",
    },
]

app.openapi = create_custom_openapi_generator(
    app=app,
    env_config=settings,
    docs_summary="Trellix Backend API Documentation",
    docs_description=("Backend services for Trellix Project Manager."),
    docs_tags_metadata=doc_tags_metadata,
)


# Include routers
app.include_router(misc_router)
