import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "vulnerable_flask_app"
sys.path.insert(0, str(APP_DIR))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_homepage(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Welcome to our fixed Flask App" in response.data


def test_hello_default_name(client):
    response = client.get("/hello")
    assert response.status_code == 200
    assert b"Hello, Guest!" in response.data


def test_hello_custom_name(client):
    response = client.get("/hello?name=Aya")
    assert response.status_code == 200
    assert b"Hello, Aya!" in response.data


def test_hello_escapes_html(client):
    response = client.get("/hello?name=<script>")
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>" not in response.data


@patch("app.subprocess.run")
def test_execute_date(mock_run, client):
    mock_run.return_value.stdout = "Tue Oct 20 00:00:00 UTC 2026\n"
    response = client.get("/execute?cmd=date")
    assert response.status_code == 200
    assert b"Execute Command Page" in response.data
    assert b"Tue Oct 20" in response.data
    mock_run.assert_called_once_with(
        ["date"], capture_output=True, text=True
    )


def test_execute_rejects_unknown_command(client):
    response = client.get("/execute?cmd=invalid")
    assert response.status_code == 400
    assert b"Commande non autorisee" in response.data


def test_security_headers(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
