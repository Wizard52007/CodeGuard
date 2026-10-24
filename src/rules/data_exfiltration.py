
"""Reusable static checks for potentially sensitive data exfiltration.

This module analyzes source text only. It never executes submitted code
or sends data to a network destination.
"""

from __future__ import annotations

import re


SENSITIVE_NAME = re.compile(
    r"API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"SECRET|TOKEN|PASSWORD|CREDENTIAL|"
    r"PRIVATE[_-]?(?:RECORDS?|DATA|INFORMATION)|"
    r"SENSITIVE[_-]?(?:DATA|RECORDS?|INFORMATION)|"
    r"PERSONAL[_-]?(?:DATA|RECORDS?|INFORMATION)|"
    r"USER[_-]?(?:DATA|RECORDS?|INFORMATION)",
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
    r"|\brequests\s*\.\s*(?:post|put|patch|request)\s*\("
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
    r"\b(?:body|data|payload|headers|json)\s*[:=]"
    r"|\bjson\s*="
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
    """Ignore simple, full-line comments."""
    return line.lstrip().startswith(("#", "//", "--"))


def _mentions_symbol(line: str, symbol: str) -> bool:
    """Check whether a line references an identifier."""
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

    source_lines: set[int] = set()
    sensitive_symbols: set[str] = set()

    # Find sensitive sources and track simple assigned identifiers.
    for number, line in enumerate(lines, start=1):
        if _is_comment(line):
            continue

        identifiers = IDENTIFIER.findall(line)
        has_sensitive_name = any(
            SENSITIVE_NAME.search(identifier)
            for identifier in identifiers
        )
        has_source_access = SOURCE_ACCESS.search(line) is not None

        # Sensitive environment/secret access, e.g. os.getenv("API_TOKEN").
        if has_sensitive_name and has_source_access:
            source_lines.add(number)

            assignment = ASSIGNMENT.search(line)
            if assignment:
                sensitive_symbols.add(assignment.group(1))

            for identifier in identifiers:
                if SENSITIVE_NAME.search(identifier):
                    sensitive_symbols.add(identifier)

        # Explicitly sensitive variable names, e.g. private_records.
        # This is a heuristic, not proof that the value contains private data.
        for identifier in identifiers:
            if SENSITIVE_NAME.search(identifier):
                sensitive_symbols.add(identifier)
                if not has_source_access:
                    source_lines.add(number)

    if not sensitive_symbols or not source_lines:
        return []

    sink_lines = [
        number
        for number, line in enumerate(lines, start=1)
        if not _is_comment(line) and NETWORK_SINK.search(line)
    ]

    for sink in sink_lines:
        start = max(1, sink - 8)
        end = min(len(lines), sink + 10)
        context_numbers = list(range(start, end + 1))

        def has_sensitive_reference(line: str) -> bool:
            return any(
                _mentions_symbol(line, symbol)
                for symbol in sensitive_symbols
            )

        payload_lines = [
            number
            for number in context_numbers
            if not _is_comment(lines[number - 1])
            and PAYLOAD_MARKER.search(lines[number - 1])
            and has_sensitive_reference(lines[number - 1])
        ]

        # Also recognize a sensitive identifier directly in a request
        # payload, such as requests.post(url, json={"records": private_records}).
        if not payload_lines:
            sink_line = lines[sink - 1]
            if (
                PAYLOAD_MARKER.search(sink_line)
                and has_sensitive_reference(sink_line)
            ):
                payload_lines = [sink]

        if not payload_lines:
            continue

        related_source_lines = [
            number
            for number in context_numbers
            if number in source_lines
            and has_sensitive_reference(lines[number - 1])
        ]

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
                "A value associated with a potentially sensitive identifier "
                "appears to flow into a network request payload. Review the "
                "source, destination, and authorization context."
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
