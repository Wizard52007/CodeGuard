import pytest

from src.interceptor import guarded_operation


def valid_allow_assessment():
    return {
        "verdict": "allow",
        "risk_score": 0.01,
        "categories": [],
        "code_language": "python",
        "reason": "Test-only allow fixture.",
        "vulnerable_lines": [],
    }


def valid_block_assessment():
    return {
        "verdict": "block",
        "risk_score": 0.99,
        "categories": ["destructive_command"],
        "code_language": "bash",
        "reason": "Test-only block fixture.",
        "vulnerable_lines": [1],
    }


def test_allow_calls_only_the_approved_operation():
    calls = []

    result = guarded_operation(
        'print("hello")',
        lambda code: valid_allow_assessment(),
        lambda: calls.append("approved-operation"),
    )

    assert result["decision"] == "allow"
    assert result["analysis_complete"] is True
    assert result["operation_called"] is True
    assert calls == ["approved-operation"]


def test_block_never_calls_the_operation():
    calls = []

    result = guarded_operation(
        "unsafe example",
        lambda code: valid_block_assessment(),
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is True
    assert result["operation_called"] is False
    assert calls == []


def test_detector_exception_fails_closed():
    calls = []

    def failing_detector(code):
        raise RuntimeError("Simulated detector failure")

    result = guarded_operation(
        "some code",
        failing_detector,
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert result["operation_called"] is False
    assert calls == []


def test_missing_response_field_fails_closed():
    calls = []
    assessment = valid_allow_assessment()
    assessment.pop("reason")

    result = guarded_operation(
        "some code",
        lambda code: assessment,
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert result["operation_called"] is False
    assert calls == []


def test_invalid_verdict_fails_closed():
    calls = []
    assessment = valid_allow_assessment()
    assessment["verdict"] = "maybe"

    result = guarded_operation(
        "some code",
        lambda code: assessment,
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert calls == []


def test_invalid_line_number_fails_closed():
    calls = []
    assessment = valid_allow_assessment()
    assessment["vulnerable_lines"] = [0]

    result = guarded_operation(
        "some code",
        lambda code: assessment,
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert calls == []


def test_invalid_risk_score_fails_closed():
    calls = []
    assessment = valid_allow_assessment()
    assessment["risk_score"] = float("nan")

    result = guarded_operation(
        "some code",
        lambda code: assessment,
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert calls == []


def test_empty_input_fails_closed():
    calls = []

    result = guarded_operation(
        "",
        lambda code: valid_allow_assessment(),
        lambda: calls.append("should-not-run"),
    )

    assert result["decision"] == "block"
    assert result["analysis_complete"] is False
    assert result["operation_called"] is False
    assert calls == []