"""Central entry point for CodeGuard security analysis."""

from typing import Any

from src.analyzers import (
    bash_analyzer,
    javascript_analyzer,
    markdown_analyzer,
    python_analyzer,
    sql_analyzer,
    yaml_analyzer,
)
from src.language_detector import detect_language
from src.risk_engine import calculate_risk


def evaluate_code(
    code: str,
    language: str | None = None,
) -> dict[str, Any]:
    """Analyze a snippet and return a structured security assessment."""

    if not isinstance(code, str):
        raise TypeError("code must be a string")

    if language is not None and not isinstance(language, str):
        raise TypeError("language must be a string or None")

    normalized_language = (
    language.strip().lower()
    if language and language.strip()
    else None
)

    if (
       normalized_language is not None
       and normalized_language not in {
           "python",
           "bash",
           "javascript",
           "sql",
           "yaml",
           "markdown",
       }
   ):
        raise ValueError(
           f"Unsupported language: {normalized_language}"
        )

    if not code.strip():
        return {
            "verdict": "allow",
            "risk_score": 0.0,
            "categories": [],
            "code_language": normalized_language or "unknown",
            "reason": "Empty input; nothing to analyze.",
            "vulnerable_lines": [],
        }

    detected_language = normalized_language or detect_language(code)

    findings = []

    if detected_language == "python":
        findings.extend(python_analyzer.analyze(code))
    elif detected_language == "bash":
        findings.extend(bash_analyzer.analyze(code))
    elif detected_language == "sql":
        findings.extend(sql_analyzer.analyze(code))
    elif detected_language == "javascript":
        findings.extend(javascript_analyzer.analyze(code))
    elif detected_language == "yaml":
        findings.extend(yaml_analyzer.analyze(code))
    elif detected_language == "markdown":
        findings.extend(markdown_analyzer.analyze(code))

    risk = calculate_risk(findings)

    return {
        **risk,
        "code_language": detected_language,
    }