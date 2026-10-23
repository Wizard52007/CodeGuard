"""Integration tests for the real FastAPI endpoint and detector."""

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_real_api_allows_benign_python():
    response = client.post(
        "/evaluate",
        json={"code": "print('Hello CodeGuard')"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["verdict"] == "allow"
    assert result["code_language"] == "python"
    assert result["categories"] == []


def test_real_api_blocks_destructive_sql():
    response = client.post(
        "/evaluate",
        json={"code": "DROP TABLE users;"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["verdict"] == "block"
    assert result["code_language"] == "sql"
    assert "destructive_command" in result["categories"]
    assert result["vulnerable_lines"] == [1]


def test_real_api_blocks_destructive_bash():
    response = client.post(
        "/evaluate",
        json={"code": "rm -rf /tmp/codeguard-demo"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["verdict"] == "block"
    assert result["code_language"] == "bash"
    assert "destructive_command" in result["categories"]
    assert result["vulnerable_lines"] == [1]


def test_real_api_blocks_hardcoded_yaml_secret():
    response = client.post(
        "/evaluate",
        json={"code": "api_key: hardcoded-secret-value"},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["verdict"] == "block"
    assert result["code_language"] == "yaml"
    assert "secret_access" in result["categories"]
    assert result["vulnerable_lines"] == [1]