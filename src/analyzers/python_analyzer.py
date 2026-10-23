
"""AST-based Python security analyzer."""

import ast
from typing import Any


DANGEROUS_CALLS = {
    "os.remove": "Deletes a file.",
    "os.unlink": "Deletes a file.",
    "os.rmdir": "Deletes a directory.",
    "shutil.rmtree": "Recursively deletes a directory tree.",
}

DYNAMIC_EXECUTION_CALLS = {
    "exec",
    "eval",
}

PRIVILEGE_CALLS = {
    "os.setuid",
    "os.seteuid",
    "os.setgid",
    "os.setegid",
}

STARTUP_PATH_MARKERS = (
    ".config/autostart/",
    ".config/systemd/user/",
)

MAX_SAFE_LITERAL_EXPONENT = 10000

PACKAGE_INSTALL_COMMANDS = {
    "pip",
    "pip3",
    "pip.exe",
    "pip3.exe",
}

PACKAGE_INSTALL_SUBCOMMANDS = {
    "install",
    "download",
}


def _resolve_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a function name, accounting for imported aliases."""

    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)

    if isinstance(node, ast.Attribute):
        base = _resolve_name(node.value, aliases)
        return f"{base}.{node.attr}"

    return ""


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local import names to their fully qualified names."""

    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]

                if alias.asname:
                    aliases[local_name] = alias.name
                elif "." in alias.name:
                    aliases[local_name] = alias.name.split(".")[0]
                else:
                    aliases[local_name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""

            for alias in node.names:
                if alias.name == "*":
                    continue

                local_name = alias.asname or alias.name
                aliases[local_name] = f"{module}.{alias.name}"

    return aliases


def _string_value(node: ast.AST) -> str | None:
    """Return a literal string value when statically available."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return None


def _command_parts(node: ast.AST) -> list[str] | None:
    """Extract a literal command from a subprocess-style argument list."""

    if not isinstance(node, (ast.List, ast.Tuple)):
        return None

    parts: list[str] = []

    for element in node.elts:
        value = _string_value(element)

        if value is None:
            return None

        parts.append(value)

    return parts


def _is_package_install_command(parts: list[str]) -> bool:
    """Check whether literal command arguments invoke pip installation."""

    if not parts:
        return False

    executable = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    executable = executable.removesuffix(".exe")

    # Recognize pip install ... and pip download ...
    if executable in {"pip", "pip3"}:
        return (
            len(parts) >= 2
            and parts[1].lower() in PACKAGE_INSTALL_SUBCOMMANDS
        )

    # Recognize python -m pip install ... and python3 -m pip install ...
    if executable in {"python", "python3"}:
        return (
            len(parts) >= 4
            and parts[1:3] == ["-m", "pip"]
            and parts[3].lower() in PACKAGE_INSTALL_SUBCOMMANDS
        )

    return False


def _is_unbounded_loop_test(node: ast.AST) -> bool:
    """Check whether a while-loop condition is the literal True."""

    return isinstance(node, ast.Constant) and node.value is True


def _is_suspicious_exponent(node: ast.AST) -> bool:
    """Detect exponentiation with an unusually large literal exponent."""

    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Pow):
        return False

    exponent = node.right

    return (
        isinstance(exponent, ast.Constant)
        and isinstance(exponent.value, int)
        and not isinstance(exponent.value, bool)
        and exponent.value > MAX_SAFE_LITERAL_EXPONENT
    )


def analyze(code: str) -> list[dict[str, Any]]:
    """Analyze Python source without executing it."""

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases = _collect_import_aliases(tree)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

        # Detect potentially unbounded loops.
    for node in ast.walk(tree):
        if isinstance(node, ast.While) and _is_unbounded_loop_test(node.test):
            key = ("resource_exhaustion", node.lineno)

            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "resource_exhaustion",
                    "severity": "high",
                    "reason": (
                        "The code contains a while True loop that may "
                        "continue indefinitely without an exit condition."
                    ),
                    "lines": [node.lineno],
                    "evidence": "while True",
                })

    # Detect potentially excessive literal exponentiation.
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and _is_suspicious_exponent(node):
            key = ("resource_exhaustion", node.lineno)

            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "resource_exhaustion",
                    "severity": "high",
                    "reason": (
                        "The code uses an unusually large literal exponent, "
                        "which may cause excessive CPU or memory consumption."
                    ),
                    "lines": [node.lineno],
                    "evidence": "Exponentiation with a large literal exponent",
                })

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_name(node.func, aliases)
        line = node.lineno

                # Detect recognizable dynamic package installation.
        if call_name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        } and node.args:
            parts = _command_parts(node.args[0])

            if parts and _is_package_install_command(parts):
                key = ("dependency_risk", line)

                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "category": "dependency_risk",
                        "severity": "medium",
                        "reason": (
                            "The code invokes a package installation or "
                            "download command through a subprocess."
                        ),
                        "lines": [line],
                        "evidence": "Subprocess package-management command",
                    })

        if call_name in DANGEROUS_CALLS:
            key = ("destructive_command", line)

            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "destructive_command",
                    "severity": "high",
                    "reason": (
                        f"The code calls {call_name}, which can "
                        f"{DANGEROUS_CALLS[call_name].lower()}"
                    ),
                    "lines": [line],
                    "evidence": call_name,
                })

        if call_name in DYNAMIC_EXECUTION_CALLS:
            key = ("obfuscated_execution", line)

            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "obfuscated_execution",
                    "severity": "high",
                    "reason": (
                        f"The code uses {call_name}() to evaluate "
                        "a dynamically supplied expression."
                    ),
                    "lines": [line],
                    "evidence": f"{call_name}()",
                })

        if call_name in PRIVILEGE_CALLS:
            key = ("persistence_or_privesc", line)

            if key not in seen:
                seen.add(key)
                findings.append({
                    "category": "persistence_or_privesc",
                    "severity": "high",
                    "reason": (
                        f"The code calls {call_name}, which changes "
                        "process identity or group privileges."
                    ),
                    "lines": [line],
                    "evidence": call_name,
                })

    # Inspect literal paths used in file-opening calls.
    # This is only a narrow first-pass check, not full persistence analysis.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_name(node.func, aliases)

        if call_name not in {"open", "builtins.open"} or not node.args:
            continue

        path = _string_value(node.args[0])
        if path is None:
            continue

        normalized_path = path.replace("\\", "/")

        if not any(marker in normalized_path for marker in STARTUP_PATH_MARKERS):
            continue

        key = ("persistence_or_privesc", node.lineno)

        if key not in seen:
            seen.add(key)
            findings.append({
                "category": "persistence_or_privesc",
                "severity": "medium",
                "reason": (
                    "The code opens a file under a recognized "
                    "startup-related configuration path."
                ),
                "lines": [node.lineno],
                "evidence": "Startup-related path",
            })

    return findings
