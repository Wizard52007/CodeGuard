"""Static security analyzer for Markdown documents.

Analyzes AI-targeted instructions and supported fenced code blocks.
All analysis is local; submitted code is never executed.
"""

from __future__ import annotations

import importlib
import re

class IncompleteAnalysisError(RuntimeError):
    """Raised when a required analyzer is unavailable or fails."""


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

APPROVED_SEVERITIES = {"low", "medium", "high", "critical"}

# Aliases are mapped to the analyzer module names used by CodeGuard.
LANGUAGE_MODULES = {
    "python": "python_analyzer",
    "py": "python_analyzer",
    "bash": "bash_analyzer",
    "sh": "bash_analyzer",
    "shell": "bash_analyzer",
    "javascript": "javascript_analyzer",
    "js": "javascript_analyzer",
    "node": "javascript_analyzer",
    "sql": "sql_analyzer",
    "yaml": "yaml_analyzer",
    "yml": "yaml_analyzer",
}

OPENING_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")

AI_TARGETED_INSTRUCTION = re.compile(
    r"\bignore\s+(?:all\s+)?(?:previous|prior|preceding)\s+instructions\b"
    r"|\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b"
    r"|\breveal\s+(?:the\s+)?(?:secrets|credentials|system prompt)\b"
    r"|\bbypass\s+(?:the\s+)?security\s+(?:checks|rules|review)\b"
    r"|\bdisable\s+(?:all\s+)?security\s+(?:checks|rules)\b"
    r"|\bhide\s+(?:this|the)\s+(?:vulnerability|malicious code|threat)\b"
    r"|\boverride\s+(?:your\s+)?(?:safety|security)\s+(?:rules|instructions)\b"
    r"|\bdo not report\s+(?:this|the)\s+(?:vulnerability|threat)\b",
    re.IGNORECASE,
)


def _extract_fenced_blocks(code: str) -> list[tuple[str, int, str]]:
    """Return (language, opening_fence_line, block_code) tuples.

    Lines are one-based in the original Markdown document.
    """
    lines = code.splitlines()
    blocks: list[tuple[str, int, str]] = []

    index = 0

    while index < len(lines):
        match = OPENING_FENCE.match(lines[index])

        if not match:
            index += 1
            continue

        fence = match.group(1)
        marker = fence[0]
        opening_line = index + 1

        info = match.group(2).strip()
        language = info.split(maxsplit=1)[0].strip("{}").lower() if info else ""

        # Find a valid closing fence using the same marker character.
        closing_pattern = re.compile(
            rf"^\s{{0,3}}{re.escape(marker)}{{{len(fence)},}}\s*$"
        )

        closing_index = index + 1

        while closing_index < len(lines):
            if closing_pattern.match(lines[closing_index]):
                break
            closing_index += 1

        # If there is no closing fence, analyze through end of document.
        block_lines = lines[index + 1:closing_index]
        block_code = "\n".join(block_lines)

        if language and block_code.strip():
            blocks.append((language, opening_line, block_code))

        if closing_index < len(lines):
            index = closing_index + 1
        else:
            index = len(lines)

    return blocks


def _load_analyzer(language: str):
    """Load the required analyzer or report incomplete coverage."""

    module_name = LANGUAGE_MODULES.get(language)

    if module_name is None:
        raise IncompleteAnalysisError(
            f"No analyzer is registered for fenced language: {language!r}"
        )

    try:
        module = importlib.import_module(
            f"src.analyzers.{module_name}"
        )
    except Exception as exc:
        raise IncompleteAnalysisError(
            f"The required analyzer for {language!r} is unavailable."
        ) from exc

    analyze_function = getattr(module, "analyze", None)

    if not callable(analyze_function):
        raise IncompleteAnalysisError(
            f"The required analyzer for {language!r} has no analyze() function."
        )

    return analyze_function


def analyze(code: str) -> list[dict]:
    """Analyze Markdown and return CodeGuard-compatible findings."""

    if not isinstance(code, str) or not code.strip():
        return []

    lines = code.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add_finding(finding: dict, line_offset: int = 0) -> None:
        """Validate, normalize, and optionally shift finding line numbers."""

        if not isinstance(finding, dict):
            return

        category = finding.get("category")
        severity = finding.get("severity")
        reason = finding.get("reason")
        evidence = finding.get("evidence")
        relative_lines = finding.get("lines")

        if category not in APPROVED_CATEGORIES:
            return

        if severity not in APPROVED_SEVERITIES:
            return

        if not isinstance(reason, str) or not isinstance(evidence, str):
            return

        if not isinstance(relative_lines, list):
            return

        absolute_lines = set()

        for line in relative_lines:
            if (
                isinstance(line, int)
                and not isinstance(line, bool)
                and line >= 1
            ):
                absolute_line = line + line_offset

                if absolute_line <= len(lines):
                    absolute_lines.add(absolute_line)

        sorted_lines = sorted(absolute_lines)

        if not sorted_lines:
            return

        key = (category, tuple(sorted_lines))

        if key in seen:
            return

        seen.add(key)

        findings.append({
            "category": category,
            "severity": severity,
            "reason": reason,
            "lines": sorted_lines,
            "evidence": evidence[:200],
        })

    # ---------------------------------------------------------
    # 1. Detect AI-targeted instructions in Markdown content.
    # ---------------------------------------------------------

    for line_number, line in enumerate(lines, start=1):
        if AI_TARGETED_INSTRUCTION.search(line):
            add_finding({
                "category": "ai_targeted_instructions",
                "severity": "high",
                "reason": (
                    "The document contains instruction-like text that may "
                    "attempt to override an AI agent's security behavior."
                ),
                "lines": [line_number],
                "evidence": "AI-targeted instruction pattern",
            })

        # ---------------------------------------------------------
    # 2. Analyze supported fenced code blocks.
    # ---------------------------------------------------------

    for language, opening_line, block_code in _extract_fenced_blocks(code):
        analyzer = _load_analyzer(language)

        try:
            block_findings = analyzer(block_code)
        except Exception as exc:
            raise IncompleteAnalysisError(
                f"Analysis failed for the {language!r} block "
                f"starting at line {opening_line}."
            ) from exc

        if not isinstance(block_findings, list):
            raise IncompleteAnalysisError(
                f"The analyzer for {language!r} returned an invalid result."
            )

        for finding in block_findings:
            if not isinstance(finding, dict):
                raise IncompleteAnalysisError(
                    f"The analyzer for {language!r} returned an invalid finding."
                )

            required_fields = {
                "category",
                "severity",
                "reason",
                "lines",
                "evidence",
            }

            if not required_fields.issubset(finding):
                raise IncompleteAnalysisError(
                    f"The analyzer for {language!r} returned an "
                    "incomplete finding."
                )

            add_finding(
                finding,
                line_offset=opening_line,
            )

    return sorted(
        findings,
        key=lambda finding: (
            finding["lines"][0],
            finding["category"],
        ),
    )