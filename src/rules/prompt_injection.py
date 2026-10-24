"""Reusable static checks for AI-targeted instructions.

The rule examines text only. It does not invoke an AI model or execute code.
"""

from __future__ import annotations

import re


_PATTERNS = [
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|preceding)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reveal|expose|print|send)\s+"
        r"(?:the\s+)?(?:secrets|credentials|system prompt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:bypass|disable|override)\s+(?:the\s+)?"
        r"(?:security checks|security rules|safety rules|"
        r"security instructions|safety instructions)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdo not report\s+(?:this|the)\s+"
        r"(?:vulnerability|security issue|threat)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bhide\s+(?:this|the)\s+(?:vulnerability|malicious code|threat)\b",
        re.IGNORECASE,
    ),
]


def analyze(code: str) -> list[dict]:
    """Return findings for instruction-like text that warrants review."""

    if not isinstance(code, str) or not code.strip():
        return []

    findings = []

    for line_number, line in enumerate(code.splitlines(), start=1):
        if not any(pattern.search(line) for pattern in _PATTERNS):
            continue

        findings.append({
            "category": "ai_targeted_instructions",
            "severity": "medium",
            "reason": (
                "The text contains an instruction-like pattern that may "
                "attempt to override an AI agent's security behavior."
            ),
            "lines": [line_number],
            # Do not copy potentially sensitive submitted text into evidence.
            "evidence": "AI-targeted instruction pattern",
        })

    return findings
