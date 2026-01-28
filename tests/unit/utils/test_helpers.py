"""Shared test utilities for Keycloak admin client tests.

This module provides reusable test helpers that can be imported by test files.
Unlike conftest.py fixtures, classes defined here must be explicitly imported.
"""

from typing import Any


class MockResponse:
    """Mock HTTP response object for testing async HTTP calls.

    Simulates aiohttp.ClientResponse with the minimal interface needed
    for testing KeycloakAdminClient methods.
    """

    def __init__(
        self,
        status_code: int,
        json_data: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
        text: str = "",
    ):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self) -> dict[str, Any] | list[Any]:
        """Return the JSON data."""
        return self._json_data
