from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text

from .core.config import settings
from .middleware.logging import logger
from .routes import utility, auth, user
from .database.connect import temp_session
from .schemas.responses import CustomHttpException, CustomJSONResponse
from .middleware.rate_limitter import RateLimitMiddleware, rate_limiter
from .docs import (
    docs_summary,
    docs_description,
    docs_tags_metadata,
    generate_code_samples,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting application...")
    try:
        try:
            logger.info("Connecting to the database...")

            with temp_session() as session:
                session.execute(text("SELECT 1"))
                session.close()

            logger.info("Connected to the database successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to the database: {e}")
            raise e

        try:
            if not os.path.isdir("keys"):
                logger.info("Downloading keys...")
                os.makedirs("keys")

                settings.download_keys()
                logger.info("Keys downloaded successfully.")

            logger.info("Application started successfully.")
        except Exception as e:
            logger.error(f"Failed to download keys: {e}")
            raise e

        yield
    except Exception as e:
        logger.error(f"Failed to start the application: {e}")
        raise e
    finally:
        logger.info("Application stopped successfully.")


app = FastAPI(lifespan=lifespan)

# Set up CORS (Cross-Origin Resource Sharing)
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
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

# Global Rate Limiting Middleware
app.add_middleware(
    RateLimitMiddleware,
    rate_limiter=rate_limiter,
    limit=10,  # Maximum 10 requests
    window=60,  # Per 60 seconds
)


# Routes
app.include_router(utility.router)
app.include_router(auth.router)
app.include_router(user.router)


# Custom validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = [
        {"field": ".".join(e["loc"]), "error": e["msg"]} for e in exc.errors()
    ]
    response = {
        "success": False,
        "status_code": 422,
        "message": "Validation Error(s)",
        "data": None,
        "error": {"code": "VALIDATION_ERROR", "details": error_details},
        "meta": None,
    }
    return JSONResponse(status_code=422, content=response)


# Custom handler for internal server errors
@app.exception_handler(Exception)
async def internal_server_error_handler(request: Request, exc: Exception):
    # Log the error for debugging (optional)
    logger.error(f"Unexpected error: {exc}", exc_info=True)

    # Standardized response for 500 errors
    response = {
        "success": False,
        "status_code": 500,
        "message": "Internal Server Error",
        "data": None,
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "details": "Something went wrong. Please contact developers if the issue persists.",
        },
        "meta": None,
    }
    return JSONResponse(status_code=500, content=response)


# Custom handler for custom HTTP exceptions
@app.exception_handler(CustomHttpException)
async def custom_http_exception_handler(request: Request, exc: CustomHttpException):
    return CustomJSONResponse(**exc.detail, status_code=exc.status_code)


# Custom OpenAPI schema generator
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version=settings.INSTANCE.upper(),
        summary=docs_summary,
        description=docs_description,
        tags=docs_tags_metadata,
        routes=app.routes,
        contact={"name": "Muzaffar Shaikh", "email": settings.DEVELOPERS_EMAIL[0]},
        # servers=[
        #     {
        #         "url": "http://127.0.0.1:5000",
        #         "description": "Local development server",
        #     },
        #     {
        #         "url": settings.BASE_URL,
        #         "description": f"Deployed {settings.INSTANCE} server",
        #     },
        # ],
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png",
    }

    components = openapi_schema.get("components", {})
    for path, path_item in openapi_schema.get("paths", {}).items():
        for method, operation in path_item.items():
            if operation["summary"] in ["Register"]:
                operation["responses"].pop("200", None)
            if method in {"get", "post", "put", "delete", "patch"}:
                generate_code_samples(path, method, operation, components)

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Seting the custom OpenAPI function
app.openapi = custom_openapi
