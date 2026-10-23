"""Language detection for CodeGuard."""

import re

SUPPORTED_LANGUAGES = {
    "python",
    "bash",
    "javascript",
    "sql",
    "yaml",
    "markdown",
}


def detect_language(code: str) -> str:
    """Infer the language from source-code syntax."""

    text = code.strip()

    if not text:
        return "unknown"

    # Markdown headings and fenced code blocks
    if re.search(r"(?m)^#{1,6}\s+\S", text):
        return "markdown"

    if re.search(r"(?m)^```", text):
        return "markdown"

    # SQL
    if re.search(
        r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|"
        r"DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE)\b",
        text,
    ):
        return "sql"

    # Bash
    if re.search(
        r"(?m)^\s*(#!/bin/(ba)?sh|sudo|curl|wget|chmod|export)\b",
        text,
    ):
        return "bash"

    # Python
    if re.search(
        r"(?m)^\s*(def |class |import |from .+ import |"
        r"if __name__ ==|print\()",
        text,
    ):
        return "python"

    # JavaScript
    if re.search(
        r"\b(const|let|var)\s+\w+\s*=|"
        r"\bfunction\s+\w+\s*\(|console\.log\(",
        text,
    ):
        return "javascript"

    # YAML
    if re.search(r"(?m)^[\w.-]+\s*:\s*(?:\S.*)?$", text):
        return "yaml"

    return "unknown"