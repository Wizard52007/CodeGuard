import pytest
from fastapi.testclient import TestClient

from app import app, get_evaluator


def mock_detector(code: str) -> dict:
    """Test-only mock. This is not a real security detector."""
    return {
        "verdict": "allow",
        "risk_score": 0.05,
        "categories": [],
        "code_language": "python",
        "reason": "Mock response used for API testing.",
        "vulnerable_lines": [],
    }


@pytest.fixture(autouse=True)
def install_mock_detector():
    """Use a mock detector only during these tests."""
    app.dependency_overrides[get_evaluator] = lambda: mock_detector
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_evaluate_accepts_code(client):
    response = client.post(
        "/evaluate",
        json={"code": "print('Hello world')"},
    )

    assert response.status_code == 200

    result = response.json()
    assert result["verdict"] == "allow"
    assert result["risk_score"] == 0.05
    assert result["categories"] == []
    assert result["code_language"] == "python"
    assert result["vulnerable_lines"] == []


def test_response_contains_only_agreed_fields(client):
    response = client.post(
        "/evaluate",
        json={"code": "print('Hello world')"},
    )

    assert response.status_code == 200

    assert set(response.json()) == {
        "verdict",
        "risk_score",
        "categories",
        "code_language",
        "reason",
        "vulnerable_lines",
    }


def test_missing_code_is_rejected(client):
    response = client.post("/evaluate", json={})
    assert response.status_code == 422


def test_empty_code_is_rejected(client):
    response = client.post("/evaluate", json={"code": ""})
    assert response.status_code == 422


def test_extra_request_fields_are_rejected(client):
    response = client.post(
        "/evaluate",
        json={
            "code": "print('Hello world')",
            "language": "python",
        },
    )

    assert response.status_code == 422


def test_invalid_detector_result_fails_closed(client):
    def invalid_detector(code: str) -> dict:
        return {
            "verdict": "allow",
            "risk_score": 0.05,
            "categories": [],
            "code_language": "python",
            "reason": "Invalid result",
            "vulnerable_lines": [0],
        }

    app.dependency_overrides[get_evaluator] = lambda: invalid_detector

    response = client.post(
        "/evaluate",
        json={"code": "print('Hello world')"},
    )

    assert response.status_code == 503