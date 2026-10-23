"""Fail-closed execution gate for the CodeGuard demonstration.

This module never executes submitted source code.

It accepts a security assessment from the detector and calls only
a separately supplied, pre-approved operation after receiving a
valid allow decision.
"""

from collections.abc import Callable
from math import isfinite
from typing import Any


APPROVED_CATEGORIES = {
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
}

SUPPORTED_LANGUAGES = {
    "python",
    "bash",
    "javascript",
    "sql",
    "yaml",
    "markdown",
    "unknown",
}

REQUIRED_RESPONSE_FIELDS = {
    "verdict",
    "risk_score",
    "categories",
    "code_language",
    "reason",
    "vulnerable_lines",
}


class InvalidAssessmentError(ValueError):
    """Raised when the security assessment violates the shared contract."""


def validate_assessment(result: Any) -> dict:
    """Validate the complete public CodeGuard response."""

    if not isinstance(result, dict):
        raise InvalidAssessmentError("Assessment must be a dictionary.")

    if set(result) != REQUIRED_RESPONSE_FIELDS:
        raise InvalidAssessmentError(
            "Assessment does not match the agreed response schema."
        )

    verdict = result["verdict"]
    if verdict not in {"allow", "block"}:
        raise InvalidAssessmentError("Invalid security verdict.")

    score = result["risk_score"]
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not isfinite(score)
        or not 0.0 <= score <= 1.0
    ):
        raise InvalidAssessmentError("Invalid risk score.")

    categories = result["categories"]
    if (
        not isinstance(categories, list)
        or any(category not in APPROVED_CATEGORIES for category in categories)
        or len(categories) != len(set(categories))
    ):
        raise InvalidAssessmentError("Invalid or duplicated threat categories.")

    language = result["code_language"]
    if language not in SUPPORTED_LANGUAGES:
        raise InvalidAssessmentError("Invalid language label.")

    if not isinstance(result["reason"], str) or not result["reason"].strip():
        raise InvalidAssessmentError("A nonempty decision reason is required.")

    lines = result["vulnerable_lines"]
    if (
        not isinstance(lines, list)
        or any(
            isinstance(line, bool)
            or not isinstance(line, int)
            or line < 1
            for line in lines
        )
        or lines != sorted(set(lines))
    ):
        raise InvalidAssessmentError(
            "Vulnerable lines must be positive, sorted, and unique."
        )

    return result


def guarded_operation(
    code: str,
    evaluator: Callable[[str], dict],
    approved_operation: Callable[[], Any],
) -> dict:
    """Call an approved operation only after a valid allow assessment.

    The submitted source string is passed to the evaluator only.
    The approved operation receives no submitted code.
    """

    if not isinstance(code, str) or not code.strip():
        return {
            "decision": "block",
            "analysis_complete": False,
            "operation_called": False,
            "reason": "Empty or invalid input; no operation was performed.",
        }

    # Any exception or invalid assessment fails closed.
    try:
        assessment = validate_assessment(evaluator(code))
    except Exception:
        return {
            "decision": "block",
            "analysis_complete": False,
            "operation_called": False,
            "reason": "Security analysis failed or was incomplete.",
        }

    if assessment["verdict"] != "allow":
        return {
            "decision": "block",
            "analysis_complete": True,
            "operation_called": False,
            "reason": assessment["reason"],
        }

    # This callback must be a pre-approved operation, not eval/exec
    # or a general-purpose executor for submitted source code.
    try:
        approved_operation()
    except Exception:
        return {
            "decision": "error",
            "analysis_complete": True,
            "operation_called": True,
            "reason": "The pre-approved operation failed.",
        }

    return {
        "decision": "allow",
        "analysis_complete": True,
        "operation_called": True,
        "reason": "A valid allow assessment permitted the pre-approved operation.",
    }