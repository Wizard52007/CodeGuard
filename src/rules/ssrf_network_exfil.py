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

ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r".+",
)

# A deliberately conservative list of common network-request sinks.
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
    r"|metadata\.azure\.com"
    r"|100\.100\.100\.200",
    re.IGNORECASE,
)

COMMENT_PREFIXES = ("#", "//", "--")


def _is_comment(line: str) -> bool:
    """Ignore simple full-line comments."""
    return line.lstrip().startswith(COMMENT_PREFIXES)


def _contains_identifier(line: str, identifier: str) -> bool:
    """Check whether a line references a variable by its identifier."""
    return re.search(
        rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}"
        rf"(?![A-Za-z0-9_$])",
        line,
    ) is not None


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

        findings.append({
            "category": CATEGORY,
            "severity": severity,
            "reason": reason,
            "lines": valid_lines,
            "evidence": evidence,
        })

    # ---------------------------------------------------------
    # 1. Track simple request-derived URL variables.
    # ---------------------------------------------------------

    user_controlled_variables: dict[str, int] = {}
    direct_input_lines: set[int] = set()

    for number, line in active_lines.items():
        if not USER_INPUT_SOURCE.search(line):
            continue

        direct_input_lines.add(number)

        assignment = ASSIGNMENT.search(line)

        if assignment:
            user_controlled_variables[assignment.group(1)] = number

    # ---------------------------------------------------------
    # 2. Find network-request operations.
    # ---------------------------------------------------------

    sink_lines = [
        number
        for number, line in active_lines.items()
        if NETWORK_SINK.search(line)
    ]

    # A request-controlled URL used by a network sink is a candidate
    # SSRF pattern. The rule does not attempt to execute or resolve URLs.
    for sink_number in sink_lines:
        sink_line = active_lines[sink_number]

        related_source_lines: list[int] = []

        for variable, source_number in user_controlled_variables.items():
            if _contains_identifier(sink_line, variable):
                related_source_lines.append(source_number)

        # Also support a direct request-parameter expression in the sink.
        if USER_INPUT_SOURCE.search(sink_line):
            related_source_lines.append(sink_number)

        if related_source_lines:
            add_finding(
                "medium",
                (
                    "A network request appears to use a URL derived from "
                    "request-controlled input. Verify that the destination "
                    "is validated and restricted to approved hosts."
                ),
                [*related_source_lines, sink_number],
                "Request-controlled input reaches a network-request operation",
            )

    # ---------------------------------------------------------
    # 3. Detect requests to cloud metadata destinations.
    # ---------------------------------------------------------

    metadata_lines = [
        number
        for number, line in active_lines.items()
        if CLOUD_METADATA_DESTINATION.search(line)
    ]

    for metadata_number in metadata_lines:
        # Require a network sink on the same line or within a small
        # surrounding region. A comment or documentation-only mention
        # is not sufficient because comments were excluded above.
        nearby_sinks = [
            sink
            for sink in sink_lines
            if abs(sink - metadata_number) <= 4
        ]

        if not nearby_sinks:
            continue

        add_finding(
            "high",
            (
                "A network request appears to target a cloud metadata "
                "endpoint. Verify that the destination is expected and "
                "that access cannot be influenced by untrusted input."
            ),
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