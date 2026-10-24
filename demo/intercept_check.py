"""CodeGuard execution-interception demo using the real detector.

Submitted code is analyzed as text and is NEVER executed.
Only a harmless, pre-approved callback can be invoked.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import evaluate_code
from src.interceptor import guarded_operation


SAFE_CODE = 'print("Safe demonstration")'
BLOCKED_CODE = "rm -rf /tmp/codeguard-demo"


def main() -> None:
    # Test 1: Safe input
    safe_marker = {"called": False}

    safe_result = guarded_operation(
        SAFE_CODE,
        evaluate_code,
        lambda: safe_marker.__setitem__("called", True),
    )

    print("=== SAFE CASE ===")
    print("Input:", SAFE_CODE)
    print("Assessment:", evaluate_code(SAFE_CODE))
    print("Interception:", safe_result)
    print("Approved operation called:", safe_marker["called"])

    # Test 2: Destructive command (analyzed only, never executed)
    blocked_marker = {"called": False}

    blocked_result = guarded_operation(
        BLOCKED_CODE,
        evaluate_code,
        lambda: blocked_marker.__setitem__("called", True),
    )

    print("\n=== BLOCKED CASE ===")
    print("Input:", BLOCKED_CODE)
    print("Assessment:", evaluate_code(BLOCKED_CODE))
    print("Interception:", blocked_result)
    print("Approved operation called:", blocked_marker["called"])

    # Verify the expected behavior.
    assert safe_result["decision"] == "allow", (
        f"Safe input was not allowed: {safe_result}"
    )
    assert safe_marker["called"] is True, (
        "The approved operation should have been called for safe input."
    )

    assert blocked_result["decision"] == "block", (
        f"Destructive input was not blocked: {blocked_result}"
    )
    assert blocked_result["operation_called"] is False
    assert blocked_marker["called"] is False, (
        "SECURITY FAILURE: operation was called for blocked input!"
    )

    print("\nPASS: Real-detector interception checks succeeded.")


if __name__ == "__main__":
    main()
