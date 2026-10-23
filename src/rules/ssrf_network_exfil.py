"""Reusable static checks for SSRF and suspicious network destinations.

This module analyzes source text only. It never makes network requests
or executes submitted code.
"""

from __future__ import annotations

import re


CATEGORY = "ssrf_network_exfil"

USER_INPUT_SOURCE = re.compile(
    r"\b(?:req|request|ctx)\s*\.\s*"
    r"(?:query|params|query_params|args|form)\b"
    r"|\brequest\s*\.\s*(?:args|query_params|form)\s*\.\s*get\s*\("
    r"|\breq\s*\.\s*query\s*\.\s*get\s*\(",
    re.IGNORECASE,
)

# Recognize explicit names indicating potentially untrusted destinations.
UNTRUSTED_URL_NAME = re.compile(
    r"\b(?:user|user_supplied|user_provided|untrusted|external|"
    r"request_supplied|request_provided)[_-]*"
    r"(?:url|uri|endpoint|host|destination)\b"
    r"|\b(?:url|uri|endpoint|host|destination)[_-]*"
    r"(?:from_user|from_request|untrusted)\b",
    re.IGNORECASE,
)

ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r".+",
)

NETWORK_SINK = re.compile(
    r"\bfetch\s*\("
    r"|\baxios(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)?\s*\("
    r"|\brequests\s*\.\s*(?:get|post|put|patch|delete|request)\s*\("
    r"|\bhttp\s*\.\s*(?:get|request)\s*\("
    r"|\bhttps\s*\.\s*(?:get|request)\s*\("
    r"|\burlopen\s*\("
    r"|\bInvoke-WebRequest\b"
    r"|\bInvoke-RestMethod\b"
    r"|\bcurl\b"
    r"|\bwget\b",
    re.IGNORECASE,
)

CLOUD_METADATA_DESTINATION = re.compile(
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|100\.100\.100\.200",
    re.IGNORECASE,
)

COMMENT_PREFIXES = ("#", "//", "--")

UNTRUSTED_REASON = (
    "A network request appears to use a destination derived from potentially "
    "untrusted input. Verify that the destination is validated and restricted "
    "to approved hosts."
)

METADATA_REASON = (
    "A network request appears to target a cloud metadata endpoint. Verify "
    "that the destination is expected and that access cannot be influenced "
    "by untrusted input."
)


def _is_comment(line: str) -> bool:
    """Ignore simple full-line comments."""
    return line.lstrip().startswith(COMMENT_PREFIXES)


def _contains_identifier(line: str, identifier: str) -> bool:
    """Check whether a line references a variable by its identifier."""
    return (
        re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}"
            rf"(?![A-Za-z0-9_$])",
            line,
        )
        is not None
    )


def analyze(code: str) -> list[dict]:
    """Return structured SSRF/network-destination findings."""
    if not isinstance(code, str) or not code.strip():
        return []

    lines = code.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    active_lines = {
        number: line
        for number, line in enumerate(lines, start=1)
        if not _is_comment(line)
    }

    def add_finding(
        severity: str,
        reason: str,
        line_numbers: list[int],
        evidence: str,
    ) -> None:
        """Add a deduplicated finding using the shared schema."""
        valid_lines = sorted(
            {
                number
                for number in line_numbers
                if isinstance(number, int)
                and not isinstance(number, bool)
                and 1 <= number <= len(lines)
            }
        )

        if not valid_lines:
            return

        key = (CATEGORY, tuple(valid_lines))
        if key in seen:
            return

        seen.add(key)
        findings.append(
            {
                "category": CATEGORY,
                "severity": severity,
                "reason": reason,
                "lines": valid_lines,
                "evidence": evidence,
            }
        )

    # Track variables assigned from request input or explicitly named
    # as untrusted destinations.
    user_controlled_variables: dict[str, tuple[int, bool]] = {}

    for number, line in active_lines.items():
        has_request_source = bool(USER_INPUT_SOURCE.search(line))
        has_explicit_untrusted_name = bool(UNTRUSTED_URL_NAME.search(line))

        if not (has_request_source or has_explicit_untrusted_name):
            continue

        assignment = ASSIGNMENT.search(line)
        if assignment:
            variable = assignment.group(1)
            user_controlled_variables[variable] = (
                number,
                has_explicit_untrusted_name,
            )

    # Find network-request operations.
    sink_lines = [
        number
        for number, line in active_lines.items()
        if NETWORK_SINK.search(line)
    ]

    # Detect request-controlled destinations reaching network sinks.
    for sink_number in sink_lines:
        sink_line = active_lines[sink_number]
        related_source_lines: list[int] = []
        explicitly_untrusted = bool(
            UNTRUSTED_URL_NAME.search(sink_line)
        )

        for variable, (source_number, explicit_name) in (
            user_controlled_variables.items()
        ):
            if _contains_identifier(sink_line, variable):
                related_source_lines.append(source_number)
                explicitly_untrusted = (
                    explicitly_untrusted or explicit_name
                )

        # Also recognize direct request input or an explicitly named
        # untrusted destination passed directly into a network operation.
        direct_request_input = bool(USER_INPUT_SOURCE.search(sink_line))

        if explicitly_untrusted or direct_request_input:
            related_source_lines.append(sink_number)

        if not related_source_lines:
            continue

        # An explicitly untrusted destination passed to a network sink
        # is high severity. A less certain request-input flow is medium.
        severity = "high" if explicitly_untrusted else "medium"

        add_finding(
            severity,
            UNTRUSTED_REASON,
            [*related_source_lines, sink_number],
            "Potentially untrusted destination reaches a network request",
        )

    # Detect network requests targeting cloud metadata endpoints.
    metadata_lines = [
        number
        for number, line in active_lines.items()
        if CLOUD_METADATA_DESTINATION.search(line)
    ]

    for metadata_number in metadata_lines:
        nearby_sinks = [
            sink
            for sink in sink_lines
            if abs(sink - metadata_number) <= 4
        ]

        if not nearby_sinks:
            continue

        add_finding(
            "high",
            METADATA_REASON,
            [metadata_number, *nearby_sinks],
            "Cloud metadata destination near a network-request operation",
        )

    return sorted(
        findings,
        key=lambda finding: (
            finding["lines"][0],
            finding["category"],
        ),
    )