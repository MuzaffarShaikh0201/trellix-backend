"""
Tests for authentication routes (register, login, refresh).
"""

import uuid

from fastapi.testclient import TestClient

from src.models import Login200Response, Refresh200Response, Register201Response


def _register_payload(email: str) -> dict[str, str]:
    """Minimal valid registration body (matches RegisterRequest rules)."""

    return {
        "first_name": "John",
        "last_name": "Doe",
        "email": email,
        "password": "Valid1!ab",
    }


def _login_payload(email: str, password: str = "Valid1!ab") -> dict[str, str]:
    """Minimal valid login body (matches LoginRequest rules)."""

    return {
        "email": email,
        "password": password,
    }


def _register_user(client: TestClient, email: str | None = None) -> str:
    """Register a user and return their email."""

    email = email or f"pytest-user-{uuid.uuid4()}@example.com"
    response = client.post("/register", json=_register_payload(email))
    assert response.status_code == 201, response.text
    return email


class TestRegisterValidation:
    """Request body validation (422) — fails before hitting the database."""

    def test_password_missing_digit(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("pytest-missing-digit@example.com"),
                "password": "NoDigit!!",
            },
        )
        assert response.status_code == 422

    def test_password_missing_special_character(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("pytest-missing-special@example.com"),
                "password": "NoSpecial1",
            },
        )
        assert response.status_code == 422

    def test_password_too_short(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("pytest-short-pw@example.com"),
                "password": "Ab1!",
            },
        )
        assert response.status_code == 422

    def test_first_name_invalid_characters(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={
                **_register_payload("pytest-bad-name@example.com"),
                "first_name": "John3",
            },
        )
        assert response.status_code == 422

    def test_invalid_email(self, client: TestClient) -> None:
        response = client.post(
            "/register",
            json={**_register_payload("pytest-x@example.com"), "email": "not-an-email"},
        )
        assert response.status_code == 422


class TestRegisterEndpoint:
    """Registration flow (PostgreSQL required — same as other app tests using ``client``)."""

    def test_register_returns_201_and_body(self, client: TestClient) -> None:
        email = f"pytest-register-{uuid.uuid4()}@example.com"
        response = client.post("/register", json=_register_payload(email))
        assert response.status_code == 201
        data = response.json()
        Register201Response.model_validate(data)
        assert data["message"] == "User registered successfully"

    def test_register_duplicate_email_returns_409(self, client: TestClient) -> None:
        email = f"pytest-dup-{uuid.uuid4()}@example.com"
        payload = _register_payload(email)

        first = client.post("/register", json=payload)
        assert first.status_code == 201

        second = client.post("/register", json=payload)
        assert second.status_code == 409
        assert second.json()["detail"] == "An account with this email already exists."


class TestLoginEndpoint:
    """Login flow (PostgreSQL required)."""

    def test_login_returns_200_after_register(self, client: TestClient) -> None:
        email = _register_user(client)
        response = client.post("/login", json=_login_payload(email))
        assert response.status_code == 200
        data = response.json()
        Login200Response.model_validate(data)
        assert data["message"] == "User logged in successfully"
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["session_id"]

    def test_login_unknown_email_returns_404(self, client: TestClient) -> None:
        response = client.post(
            "/login",
            json=_login_payload(f"pytest-nobody-{uuid.uuid4()}@example.com"),
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "User with this email does not exists."

    def test_login_wrong_password_returns_401(self, client: TestClient) -> None:
        email = _register_user(client)
        response = client.post(
            "/login",
            json=_login_payload(email, password="Wrong1!zz"),
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid email or password."


class TestLoginValidation:
    """Login body validation (422)."""

    def test_password_missing_digit(self, client: TestClient) -> None:
        response = client.post(
            "/login",
            json={
                "email": f"pytest-login-val-{uuid.uuid4()}@example.com",
                "password": "NoDigit!!",
            },
        )
        assert response.status_code == 422


class TestRefreshEndpoint:
    """Refresh token flow (PostgreSQL + JWT required)."""

    def test_refresh_returns_200_with_valid_tokens(self, client: TestClient) -> None:
        email = _register_user(client)
        login = client.post("/login", json=_login_payload(email))
        assert login.status_code == 200
        tokens = login.json()

        response = client.post(
            "/refresh",
            json={"refresh_token": tokens["refresh_token"]},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.status_code == 200
        data = response.json()
        Refresh200Response.model_validate(data)
        assert data["message"] == "Access token refreshed successfully"
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["session_id"] == tokens["session_id"]

    def test_refresh_missing_authorization_returns_401(self, client: TestClient) -> None:
        email = _register_user(client)
        login = client.post("/login", json=_login_payload(email))
        assert login.status_code == 200
        tokens = login.json()

        response = client.post(
            "/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "No authorization header provided"

    def test_refresh_invalid_refresh_token_returns_401(self, client: TestClient) -> None:
        email = _register_user(client)
        login = client.post("/login", json=_login_payload(email))
        assert login.status_code == 200
        tokens = login.json()

        response = client.post(
            "/refresh",
            json={"refresh_token": "invalid.jwt.token"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid refresh token."
