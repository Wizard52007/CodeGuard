"""Static security analyzer for Bash and shell snippets.

This analyzer inspects source text only. It never executes submitted commands.
"""

import re
from typing import Any


# These patterns indicate potentially destructive file operations.
DESTRUCTIVE_PATTERNS = [
    (
        re.compile(r"(?<!\S)rm\s+(?:(?:-[a-zA-Z]*[rf][a-zA-Z]*|-[a-zA-Z]*[fr][a-zA-Z]*)\s+)+"),
        "A recursive or forced file-removal command may delete important data.",
    ),
    (
        re.compile(r"(?<!\S)(?:mkfs(?:\.\w+)?|wipefs)\b"),
        "A filesystem formatting or wiping command may destroy stored data.",
    ),
    (
        re.compile(r"(?<!\S)dd\b[^|\n]*\bof=/dev/(?:sd[a-z]\d*|nvme\d+n\d+p?\d*|vd[a-z]\d*)"),
        "A disk-writing command targets a device path.",
    ),
]

# Encoded content or downloaded content passed directly to a shell.
OBFUSCATED_EXECUTION_PATTERNS = [
    re.compile(
        r"\bbase64\b[^|\n]*\|\s*(?:ba)?sh\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\beval\s+[\"']?\$\(",
        re.IGNORECASE,
    ),
]

# Common, recognizable privilege-escalation or persistence indicators.
PERSISTENCE_PATTERNS = [
    # Detect setuid/setgid permissions, including chmod u+s and chmod g+s.
    re.compile(
        r"\bchmod\b[^\n]*\b(?:[ugoa]*\+[rwxXstugo]*s|[ugo]*s[ugo]*)\b",
        re.IGNORECASE,
    ),

    # Detect modifications to privileged startup/configuration files.
    re.compile(r">\s*/etc/(?:sudoers|profile|bash\.bashrc)\b"),
    re.compile(r">>\s*~?/\.bashrc\b"),
    re.compile(r">\s*~?/\.config/autostart/"),
]

# A recognizable fork bomb can cause rapid process exhaustion.
RESOURCE_EXHAUSTION_PATTERNS = [
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
]

# An endless data source written to a file fills the disk. Writing to
# /dev/null is excluded because it consumes no storage.
UNBOUNDED_WRITE_PATTERNS = [
    re.compile(
        r"(?<!\S)cat\s+/dev/(?:zero|u?random)\s*>{1,2}\s*"
        r"(?!/dev/null(?:\s|$))\S+"
    ),
    re.compile(
        r"(?<!\S)yes\b[^|;&\n>]*>{1,2}\s*(?!/dev/null(?:\s|$))[^\s&]+"
    ),
]

DD_COMMAND = re.compile(r"(?<!\S)dd\b(?P<arguments>[^|;&\n]*)")
DD_ENDLESS_INPUT = re.compile(r"\bif=/dev/(?:zero|u?random)\b")
DD_SIZE_LIMIT = re.compile(r"\bcount=\d|\biflag=\S*count_bytes")


def _is_unbounded_write(line: str) -> bool:
    """Detect endless input being written without a size limit."""

    if any(pattern.search(line) for pattern in UNBOUNDED_WRITE_PATTERNS):
        return True

    for match in DD_COMMAND.finditer(line):
        arguments = match.group("arguments")

        if (
            DD_ENDLESS_INPUT.search(arguments)
            and not DD_SIZE_LIMIT.search(arguments)
        ):
            return True

    return False


# Basic data-transfer patterns. These are signals, not proof of exfiltration.
NETWORK_TRANSFER_PATTERNS = [
    re.compile(r"\b(?:curl|wget)\b.*(?:https?://|ftp://)", re.IGNORECASE),
    re.compile(r"\bnc(?:at)?\b.*(?:\s-e\b|\s-c\b)", re.IGNORECASE),
]


def _strip_comments(line: str) -> str:
    """Remove a simple trailing shell comment without stripping quoted # signs.

    This is intentionally conservative and is not a full Bash parser.
    """

    quote: str | None = None
    escaped = False

    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue

        if char == "\\" and quote != "'":
            escaped = True
            continue

        if quote:
            if char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]

    return line


def _add_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, int]],
    *,
    category: str,
    severity: str,
    reason: str,
    line_number: int,
    evidence: str,
) -> None:
    """Append a finding once per category and source line."""

    key = (category, line_number)

    if key in seen:
        return

    seen.add(key)
    findings.append({
        "category": category,
        "severity": severity,
        "reason": reason,
        "lines": [line_number],
        "evidence": evidence[:100],
    })


def analyze(code: str) -> list[dict[str, Any]]:
    """Inspect Bash text and return findings using the shared schema."""

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for line_number, original_line in enumerate(code.splitlines(), start=1):
        line = _strip_comments(original_line).strip()

        if not line:
            continue

        for pattern, reason in DESTRUCTIVE_PATTERNS:
            match = pattern.search(line)

            if match:
                _add_finding(
                    findings,
                    seen,
                    category="destructive_command",
                    severity="high",
                    reason=reason,
                    line_number=line_number,
                    evidence=match.group(0).strip(),
                )

        for pattern in OBFUSCATED_EXECUTION_PATTERNS:
            match = pattern.search(line)

            if match:
                _add_finding(
                    findings,
                    seen,
                    category="obfuscated_execution",
                    severity="high",
                    reason=(
                        "The command appears to evaluate encoded or "
                        "downloaded content through a shell."
                    ),
                    line_number=line_number,
                    evidence=match.group(0).strip(),
                )

        for pattern in PERSISTENCE_PATTERNS:
            match = pattern.search(line)

            if match:
                _add_finding(
                    findings,
                    seen,
                    category="persistence_or_privesc",
                    severity="high",
                    reason=(
                        "The command matches a recognizable privilege or "
                        "startup-configuration modification pattern."
                    ),
                    line_number=line_number,
                    evidence=match.group(0).strip(),
                )

        for pattern in RESOURCE_EXHAUSTION_PATTERNS:
            match = pattern.search(line)

            if match:
                _add_finding(
                    findings,
                    seen,
                    category="resource_exhaustion",
                    severity="high",
                    reason=(
                        "The command resembles a shell fork bomb that can "
                        "exhaust available process resources."
                    ),
                    line_number=line_number,
                    evidence="Recognizable fork-bomb pattern",
                )

        if _is_unbounded_write(line):
            _add_finding(
                findings,
                seen,
                category="resource_exhaustion",
                severity="high",
                reason=(
                    "The command writes an endless data source without a "
                    "size limit, which can fill the available disk space."
                ),
                line_number=line_number,
                evidence="Unbounded write from an endless data source",
            )

        for pattern in NETWORK_TRANSFER_PATTERNS:
            match = pattern.search(line)

            if match:
                _add_finding(
                    findings,
                    seen,
                    category="data_exfiltration",
                    severity="medium",
                    reason=(
                        "The command performs network transfer activity; "
                        "review its destination and data source."
                    ),
                    line_number=line_number,
                    evidence=match.group(0).strip(),
                )

    return findings