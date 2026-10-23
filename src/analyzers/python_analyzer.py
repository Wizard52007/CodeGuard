"""Initial AST-based Python security analyzer."""

import ast
from typing import Any


def _get_call_name(node: ast.Call) -> str:
    """Convert a function call into a dotted name."""

    parts = []
    current = node.func

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if isinstance(current, ast.Name):
        parts.append(current.id)

    return ".".join(reversed(parts))


def analyze(code: str) -> list[dict[str, Any]]:
    """
    Analyze Python source without executing it.

    Returns structured security findings.
    """

    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Parsing failure is not proof of malicious intent.
        return []

    findings = []

    # Initial rules: selected destructive filesystem operations.
    dangerous_calls = {
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _get_call_name(node)

        if call_name in dangerous_calls:
            findings.append({
                "category": "destructive_command",
                "severity": "high",
                "reason": (
                    f"The code calls {call_name}, which can delete "
                    "files or directories."
                ),
                "lines": [node.lineno],
                "evidence": call_name,
            })

    return findings