"""
Tests for misc routes (root, health endpoints).
"""

from fastapi.testclient import TestClient

from src.config import settings
from src.models import Health200Response, Root200Response


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_returns_200(self, client: TestClient) -> None:
        """Test health check returns 200 status."""
        response = client.get("/healthz")
        assert response.status_code == 200

    def test_health_returns_healthy_status(self, client: TestClient) -> None:
        """Test health check returns healthy status and matches schema."""
        response = client.get("/healthz")
        data = response.json()
        Health200Response.model_validate(data)
        assert data["status"] == "healthy"
        assert data["service"] == settings.app_name
        assert "version" in data
        assert data["dependencies"] == {
            "redis": "healthy",
            "database": "healthy",
        }


class TestRootEndpoint:
    """Tests for / root endpoint."""

    def test_root_returns_200(self, client: TestClient) -> None:
        """Test root endpoint returns 200 status."""
        response = client.get("/")
        assert response.status_code == 200

    def test_root_returns_service_info(self, client: TestClient) -> None:
        """Test root endpoint returns service information and matches schema."""
        response = client.get("/")
        data = response.json()
        Root200Response.model_validate(data)
        assert data["service"] == settings.app_name
        assert "version" in data
        assert "docs" in data
