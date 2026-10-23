"""Central entry point for CodeGuard security analysis."""

from typing import Any

from src.analyzers import python_analyzer
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

    if not code.strip():
        return {
            "verdict": "allow",
            "risk_score": 0.0,
            "categories": [],
            "code_language": language or "unknown",
            "reason": "Empty input; nothing to analyze.",
            "vulnerable_lines": [],
        }

    detected_language = (
        language.strip().lower()
        if language and language.strip()
        else detect_language(code)
    )

    findings = []

    if detected_language == "python":
        findings.extend(python_analyzer.analyze(code))

    risk = calculate_risk(findings)

    return {
        **risk,
        "code_language": detected_language,
    }