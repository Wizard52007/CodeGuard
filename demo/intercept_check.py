"""Controlled demonstration of the CodeGuard interception gate.

This demonstration uses predetermined assessment fixtures.
It does not run the supplied source strings.
"""

from src.interceptor import guarded_operation


SAFE_CODE = 'print("Safe demonstration")'
BLOCKED_CODE = "rm -rf /tmp/codeguard-demo"


ASSESSMENTS = {
    SAFE_CODE: {
        "verdict": "allow",
        "risk_score": 0.01,
        "categories": [],
        "code_language": "python",
        "reason": "Predefined safe demonstration fixture.",
        "vulnerable_lines": [],
    },
    BLOCKED_CODE: {
        "verdict": "block",
        "risk_score": 0.99,
        "categories": ["destructive_command"],
        "code_language": "bash",
        "reason": "Predefined blocked demonstration fixture.",
        "vulnerable_lines": [1],
    },
}


def demo_evaluator(code: str) -> dict:
    """Return a predetermined fixture; this is not a real detector."""

    if code not in ASSESSMENTS:
        raise ValueError("No assessment fixture exists for this input.")

    return ASSESSMENTS[code]


def main() -> None:
    # The marker represents a harmless, approved operation.
    # It does not execute the supplied source string.
    safe_marker = {"called": False}

    safe_result = guarded_operation(
        SAFE_CODE,
        demo_evaluator,
        lambda: safe_marker.__setitem__("called", True),
    )

    print("SAFE CASE")
    print(f"Result: {safe_result}")
    print(f"Approved operation called: {safe_marker['called']}")

    # This marker must remain untouched because the assessment blocks.
    blocked_marker = {"called": False}

    blocked_result = guarded_operation(
        BLOCKED_CODE,
        demo_evaluator,
        lambda: blocked_marker.__setitem__("called", True),
    )

    print("\nBLOCKED CASE")
    print(f"Result: {blocked_result}")
    print(f"Approved operation called: {blocked_marker['called']}")

    assert safe_result["decision"] == "allow"
    assert safe_marker["called"] is True

    assert blocked_result["decision"] == "block"
    assert blocked_result["operation_called"] is False
    assert blocked_marker["called"] is False

    print("\nPASS: the interception gate behaved as expected.")


if __name__ == "__main__":
    main()