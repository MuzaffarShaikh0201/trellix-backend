"""
Tests for authentication routes (register).
"""

import uuid

from fastapi.testclient import TestClient

from src.models import Register201Response


def _register_payload(email: str) -> dict[str, str]:
    """Minimal valid registration body (matches RegisterRequest rules)."""

    return {
        "first_name": "John",
        "last_name": "Doe",
        "email": email,
        "password": "Valid1!ab",
    }


class TestRegisterValidation:
    """Request body validation (422) — fails before hitting the database."""

    def test_password_missing_digit(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("missing-digit@example.com"),
                "password": "NoDigit!!",
            },
        )
        assert response.status_code == 422

    def test_password_missing_special_character(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("missing-special@example.com"),
                "password": "NoSpecial1",
            },
        )
        assert response.status_code == 422

    def test_password_too_short(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("short-pw@example.com"),
                "password": "Ab1!",
            },
        )
        assert response.status_code == 422

    def test_first_name_invalid_characters(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("bad-name@example.com"),
                "first_name": "John3",
            },
        )
        assert response.status_code == 422

    def test_invalid_email(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={**_register_payload("x@example.com"), "email": "not-an-email"},
        )
        assert response.status_code == 422


class TestRegisterEndpoint:
    """Registration flow (PostgreSQL required — same as other app tests using ``client``)."""

    def test_register_returns_201_and_body(self, client: TestClient) -> None:
        email = f"register-{uuid.uuid4()}@example.com"
        response = client.post("/register", json=_register_payload(email))
        assert response.status_code == 201
        data = response.json()
        Register201Response.model_validate(data)
        assert data["message"] == "User registered successfully"

    def test_register_duplicate_email_returns_409(self, client: TestClient) -> None:
        email = f"dup-{uuid.uuid4()}@example.com"
        payload = _register_payload(email)

        first = client.post("/register", json=payload)
        assert first.status_code == 201

        second = client.post("/register", json=payload)
        assert second.status_code == 409
        assert second.json()["detail"] == "An account with this email already exists."
