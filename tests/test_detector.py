import pytest

from src.detector import evaluate_code
from src.language_detector import detect_language


def test_empty_input_is_allowed():
    result = evaluate_code("")

    assert result["verdict"] == "allow"
    assert result["risk_score"] == 0.0
    assert result["categories"] == []
    assert result["vulnerable_lines"] == []


def test_whitespace_input_is_allowed():
    result = evaluate_code("   \n\t")

    assert result["verdict"] == "allow"


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        evaluate_code(None)


def test_response_has_required_fields():
    result = evaluate_code("print('hello')")

    required_fields = {
        "verdict",
        "risk_score",
        "categories",
        "code_language",
        "reason",
        "vulnerable_lines",
    }

    assert required_fields.issubset(result)
    assert result["verdict"] in {"allow", "block"}
    assert 0.0 <= result["risk_score"] <= 1.0


def test_python_language_detection():
    assert detect_language("print('hello')") == "python"


def test_destructive_call_is_detected():
    code = "import os\nos.remove('example.txt')"
    result = evaluate_code(code, language="python")

    assert result["verdict"] == "block"
    assert "destructive_command" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_comment_mentioning_destructive_call_is_not_flagged():
    code = "# os.remove('example.txt')\nprint('hello')"
    result = evaluate_code(code, language="python")

    assert result["categories"] == []
    assert result["verdict"] == "allow"


def test_invalid_python_syntax_does_not_crash():
    result = evaluate_code("def broken(" , language="python")

    assert result["verdict"] in {"allow", "block"}