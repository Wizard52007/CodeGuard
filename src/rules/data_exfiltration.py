"""Reusable static checks for potentially sensitive data exfiltration.

This module analyzes source text only. It never executes submitted code
or sends data to a network destination.
"""

from __future__ import annotations

import re


SENSITIVE_NAME = re.compile(
    r"API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"SECRET|TOKEN|PASSWORD|CREDENTIAL",
    re.IGNORECASE,
)

SOURCE_ACCESS = re.compile(
    r"process\s*\.\s*env\b"
    r"|os\s*\.\s*(?:getenv|environ)\b"
    r"|\bgetenv\s*\("
    r"|\bprintenv\b"
    r"|\bsecrets\s*\."
    r"|\$\{?\s*[A-Za-z_][A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)

ASSIGNMENT = re.compile(
    r"(?:\b(?:const|let|var)\s+)?"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
)

NETWORK_SINK = re.compile(
    r"\bfetch\s*\("
    r"|\baxios\s*\.\s*(?:post|put|patch|request)\s*\("
    r"|\bhttps?\s*\.\s*request\s*\("
    r"|\bXMLHttpRequest\b"
    r"|\bsendBeacon\s*\("
    r"|\bInvoke-WebRequest\b"
    r"|\bInvoke-RestMethod\b"
    r"|\bcurl\b"
    r"|\bwget\b"
    r"|\bnc\s+-",
    re.IGNORECASE,
)

PAYLOAD_MARKER = re.compile(
    r"\b(?:body|data|payload|headers)\s*:"
    r"|\b(?:body|data|payload|headers)\s*="
    r"|(?:^|\s)-d(?:\s|['\"]|$)"
    r"|--data(?:-raw)?\b"
    r"|\bAuthorization\s*:"
    r"|\bBearer\s+"
    r"|\bsetRequestHeader\s*\("
    r"|\.\s*send\s*\("
    r"|\.\s*write\s*\("
    r"|[?&](?:api[_-]?key|token|secret|password|credential)=",
    re.IGNORECASE,
)

IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _is_comment(line: str) -> bool:
    """Ignore simple, full-line comments to reduce false positives."""
    stripped = line.lstrip()

    return stripped.startswith(("#", "//", "--"))


def _mentions_symbol(line: str, symbol: str) -> bool:
    """Check for an identifier without matching it inside another name."""
    return re.search(
        rf"(?<!\w){re.escape(symbol)}(?!\w)",
        line,
    ) is not None


def analyze(code: str) -> list[dict]:
    """Return contract-compliant data-exfiltration findings."""

    if not isinstance(code, str) or not code.strip():
        return []

    lines = code.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    # Identify lines that appear to obtain sensitive values and the
    # variable names that may carry those values.
    source_lines: set[int] = set()
    sensitive_symbols: set[str] = set()

    for number, line in enumerate(lines, start=1):
        if _is_comment(line):
            continue

        has_sensitive_name = SENSITIVE_NAME.search(line) is not None
        has_source_access = SOURCE_ACCESS.search(line) is not None

        if not (has_sensitive_name and has_source_access):
            continue

        source_lines.add(number)

        assignment = ASSIGNMENT.search(line)
        if assignment:
            sensitive_symbols.add(assignment.group(1))

        # Retain sensitive identifiers such as API_TOKEN. These let us
        # track simple direct references and common variable assignments.
        for identifier in IDENTIFIER.findall(line):
            if SENSITIVE_NAME.search(identifier):
                sensitive_symbols.add(identifier)

    if not sensitive_symbols or not source_lines:
        return []

    # Locate possible network-request sinks.
    sink_lines = [
        number
        for number, line in enumerate(lines, start=1)
        if not _is_comment(line) and NETWORK_SINK.search(line)
    ]

    for sink in sink_lines:
        # Examine a bounded region around the sink to handle common
        # multiline request patterns without correlating the whole file.
        start = max(1, sink - 8)
        end = min(len(lines), sink + 10)
        context_numbers = list(range(start, end + 1))

        def has_sensitive_reference(line: str) -> bool:
            return any(
                _mentions_symbol(line, symbol)
                for symbol in sensitive_symbols
            )

        # A likely payload line must carry a sensitive reference. Merely
        # accessing a token and making an unrelated request isn't enough.
        payload_lines = [
            number
            for number in context_numbers
            if not _is_comment(lines[number - 1])
            and PAYLOAD_MARKER.search(lines[number - 1])
            and has_sensitive_reference(lines[number - 1])
        ]

        if not payload_lines:
            continue

        related_source_lines = [
            number
            for number in context_numbers
            if number in source_lines
            and has_sensitive_reference(lines[number - 1])
        ]

        # At least one sensitive source should be linked to a likely
        # payload and a network sink.
        if not related_source_lines:
            continue

        relevant_lines = sorted(
            set(related_source_lines + payload_lines + [sink])
        )

        key = ("data_exfiltration", tuple(relevant_lines))

        if key in seen:
            continue

        seen.add(key)

        findings.append({
            "category": "data_exfiltration",
            "severity": "high",
            "reason": (
                "A value associated with a sensitive credential appears "
                "to flow into a network request payload. Review the source, "
                "destination, and authorization context."
            ),
            "lines": relevant_lines,
            "evidence": (
                "Potential sensitive-value flow into a network payload"
            ),
        })

    return sorted(
        findings,
        key=lambda finding: (
            finding["lines"][0],
            finding["category"],
        ),
    )