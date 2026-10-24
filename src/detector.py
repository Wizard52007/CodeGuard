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
from src.rules import (
    data_exfiltration,
    prompt_injection,
    secret_access,
    ssrf_network_exfil,
)


SUPPORTED_LANGUAGES = {
    "python",
    "bash",
    "javascript",
    "sql",
    "yaml",
    "markdown",
}


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove duplicate findings."""

    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for finding in findings:
        lines = tuple(sorted(set(finding.get("lines", []))))
        key = (
            finding.get("category"),
            lines,
            finding.get("reason"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


def evaluate_code(
    code: str,
    language: str | None = None,
) -> dict[str, Any]:
    """Analyze code and return a structured security assessment."""

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
        and normalized_language not in SUPPORTED_LANGUAGES
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

    analyzers = {
        "python": python_analyzer,
        "bash": bash_analyzer,
        "javascript": javascript_analyzer,
        "sql": sql_analyzer,
        "yaml": yaml_analyzer,
    }

    findings: list[dict[str, Any]] = []

    # Run the language-specific analyzer.
    if detected_language == "markdown":
        findings.extend(markdown_analyzer.analyze(code))

    elif detected_language in analyzers:
        findings.extend(
            analyzers[detected_language].analyze(code)
        )

    # Run reusable security rules on supported source languages.
    if detected_language in {"python", "bash", "javascript"}:
        findings.extend(secret_access.analyze(code))
        findings.extend(data_exfiltration.analyze(code))
        findings.extend(ssrf_network_exfil.analyze(code))

    # Instruction-override text can appear in any language. Findings that an
    # analyzer already reported for the same lines are removed below.
    findings.extend(prompt_injection.analyze(code))

    # Remove duplicates before calculating risk.
    findings = _deduplicate_findings(findings)

    risk = calculate_risk(findings)

    return {
        **risk,
        "code_language": detected_language,
    }