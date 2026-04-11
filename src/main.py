"""
Trellix Backend - Main entry point.
"""

import os
from fastapi import FastAPI
from typing import AsyncGenerator
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import db_manager, redis_manager
from .utils import setup_logging, get_logger, download_keys
from .custom_openapi import create_custom_openapi_generator
from .routers import misc_router, auth_router, project_router, user_router


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

    # Download keys
    logger.info("Downloading keys from Supabase Storage...")
    if not os.path.exists("keys"):
        download_keys()
        logger.info("✓ Keys downloaded successfully")
    else:
        logger.info("✓ Keys already exists")

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
    {
        "name": "Authentication APIs",
        "description": "Authentication APIs like register, login, logout, etc. that are related to user authentication.",
    },
    {
        "name": "User APIs",
        "description": "User APIs like get, update, update password, etc. that are related to user management.",
    },
    {
        "name": "Project APIs",
        "description": "Project APIs like create, get, update, delete, etc. that are related to project management.",
    },
]

app.openapi = create_custom_openapi_generator(
    app=app,
    env_config=settings,
    docs_summary="Trellix Backend API Documentation",
    docs_description=(
        "Backend APIs for Trellix Project Manager.\n"
        f"Frontend URL: {settings.frontend_url}"
    ),
    docs_tags_metadata=doc_tags_metadata,
)


# Set up CORS (Cross-Origin Resource Sharing)
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    f"{settings.frontend_url}",
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Connection",
        "Connection-Length",
        "Connection-Type",
        "Keep-Alive",
        "Content-Length",
        "Content-Type",
        "Cookie",
        "Date",
        "Host",
        "Origin",
        "Referer",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "User-Agent",
        "Sec-Ch-Ua-Mobile",
        "Sec-Ch-Ua-Platform",
    ],
)


# Include routers
app.include_router(misc_router)
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(project_router)
