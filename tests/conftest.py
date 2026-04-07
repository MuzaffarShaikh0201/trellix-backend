"""
Pytest configuration and fixtures.

**Database isolation**

Tests that create users must use email addresses starting with ``pytest-`` (see
``tests/test_auth.py``). At session start and session end, rows with
``email LIKE 'pytest-%'`` are deleted from ``users``,
so normal app data is unaffected as long as real accounts do not use that prefix.

Set ``SKIP_PYTEST_DB_CLEANUP=1`` to disable (not recommended).
"""

from __future__ import annotations

import os
from urllib.parse import quote_plus

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from src.config import settings
from src.main import app


def _delete_pytest_users_sync() -> None:
    """One-off sync connection; avoids competing with the app's asyncpg pool."""
    user = quote_plus(settings.postgres_user)
    password = quote_plus(settings.postgres_password)
    url = (
        f"postgresql+psycopg://{user}:{password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
    )
    schema = settings.postgres_schema
    if schema and schema != "public":
        table = f'"{schema}"."users"'
    else:
        table = "users"

    eng = create_engine(url)
    with eng.connect() as conn:
        conn.execute(text(f"DELETE FROM {table} WHERE email LIKE 'pytest-%'"))
        conn.commit()
    eng.dispose()


@pytest.fixture(scope="session", autouse=True)
def _cleanup_pytest_users_session(client: TestClient) -> None:
    """Depends on ``client`` so teardown runs before the app/engine is disposed."""
    if os.environ.get("SKIP_PYTEST_DB_CLEANUP") != "1":
        _delete_pytest_users_sync()
    yield
    if os.environ.get("SKIP_PYTEST_DB_CLEANUP") != "1":
        try:
            _delete_pytest_users_sync()
        except Exception:
            # Engine may already be torn down; best-effort cleanup.
            pass


@pytest.fixture(scope="session")
def client() -> TestClient:
    """FastAPI TestClient for testing the application."""
    with TestClient(app) as test_client:
        yield test_client
