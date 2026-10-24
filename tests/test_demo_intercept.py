"""Tests for the controlled execution-gate demonstration endpoint."""

from fastapi.testclient import TestClient

from app import app, get_evaluator

client = TestClient(app)


def test_blocked_code_never_invokes_the_approved_operation():
    response = client.post(
        "/demo/intercept",
        json={"code": "rm -rf /tmp/codeguard-demo"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["assessment"]["verdict"] == "block"
    assert result["interception"]["decision"] == "block"
    assert result["interception"]["analysis_complete"] is True
    assert result["interception"]["operation_called"] is False
    assert result["approved_operation_calls"] == 0


def test_allowed_code_invokes_only_the_approved_operation():
    response = client.post(
        "/demo/intercept",
        json={"code": "print('Hello CodeGuard')"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["assessment"]["verdict"] == "allow"
    assert result["interception"]["decision"] == "allow"
    assert result["interception"]["operation_called"] is True
    assert result["approved_operation_calls"] == 1


def test_counter_is_not_shared_between_requests():
    for _ in range(2):
        response = client.post(
            "/demo/intercept",
            json={"code": "print('Hello CodeGuard')"},
        )

        assert response.json()["approved_operation_calls"] == 1


def test_submitted_code_is_not_executed_even_when_allowed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open({str(marker)!r}, 'w').write('executed')"

    response = client.post("/demo/intercept", json={"code": code})

    assert response.status_code == 200
    assert not marker.exists()


def test_detector_failure_fails_closed():
    def failing_evaluator(code):
        raise RuntimeError("Simulated detector failure")

    app.dependency_overrides[get_evaluator] = lambda: failing_evaluator

    try:
        response = client.post(
            "/demo/intercept",
            json={"code": "print('hello')"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200

    result = response.json()

    assert result["assessment"] is None
    assert result["interception"]["decision"] == "block"
    assert result["interception"]["analysis_complete"] is False
    assert result["interception"]["operation_called"] is False
    assert result["approved_operation_calls"] == 0


def test_invalid_assessment_fails_closed():
    def invalid_evaluator(code):
        return {"verdict": "allow"}

    app.dependency_overrides[get_evaluator] = lambda: invalid_evaluator

    try:
        response = client.post(
            "/demo/intercept",
            json={"code": "print('hello')"},
        )
    finally:
        app.dependency_overrides.clear()

    result = response.json()

    assert result["interception"]["decision"] == "block"
    assert result["interception"]["operation_called"] is False
    assert result["approved_operation_calls"] == 0


def test_request_contract_matches_evaluate():
    assert client.post("/demo/intercept", json={}).status_code == 422
    assert client.post("/demo/intercept", json={"code": ""}).status_code == 422
    assert (
        client.post(
            "/demo/intercept",
            json={"code": "print(1)", "language": "python"},
        ).status_code
        == 422
    )


def test_evaluate_response_schema_is_unchanged():
    response = client.post("/evaluate", json={"code": "print('hi')"})

    assert set(response.json()) == {
        "verdict",
        "risk_score",
        "categories",
        "code_language",
        "reason",
        "vulnerable_lines",
    }
