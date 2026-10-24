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
        r"(?m)^\s*(#!/bin/(ba)?sh|sudo|curl|wget|chmod|rm|"
        r"mkfs|wipefs|dd|export|nc|ncat)\b",
        text,
    ):
        return "bash"

    # Python: imports, definitions, statements and common expressions
    if re.search(
        r"(?m)^\s*(async\s+def |def |class |import |from .+ import |"
        r"if __name__\s*==|print\s*\(|return\b|elif\b|"
        r"for\b.+\bin\b|while\b|try\s*:|except\b|with\b|"
        r"raise\b|assert\b|pass\s*$)",
        text,
    ):
        return "python"

    # Python module calls and common Python expression syntax.
    # Examples: requests.get(...), os.system(...), json.loads(...).
    if re.search(
        r"\b(?:requests|httpx|urllib|os|sys|subprocess|"
        r"pathlib|json|pickle|socket|shutil|builtins)\."
        r"[A-Za-z_]\w*\s*\(",
        text,
    ):
        return "python"

    # JavaScript
    if re.search(
        r"\b(const|let|var)\s+\w+\s*=|"
        r"\bfunction\s+\w+\s*\(|console\.log\(|"
        r"\b(?:fetch|require)\s*\(",
        text,
    ):
        return "javascript"

    # YAML: key-value configuration syntax
    if re.search(r"(?m)^[\w.-]+\s*:\s*(?:\S.*)?$", text):
        return "yaml"

    return "unknown"