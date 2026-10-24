"""Reusable static checks for SSRF and suspicious network destinations.

This module analyzes source text only. It never makes network requests
or executes submitted code.
"""

from __future__ import annotations

import ipaddress
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
    r"|\brequests\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\("
    r"|\bhttpx\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\("
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

LITERAL_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*"
    r"(?::\s*[A-Za-z_][\w\[\], .|]*)?"
    r"=(?!=)\s*[rRbBuUfF]{0,2}"
    r"([\"'`])(?P<value>.*?)\2"
)

URL_PATTERN = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://"
    r"(?P<authority>[^/\s'\"`)>?#\\]*)"
)

IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# Schemes that are rarely needed for ordinary web requests and are commonly
# abused to reach internal services. Plain http(s) is judged by host instead.
SUSPICIOUS_SCHEMES = {
    "gopher",
    "dict",
    "file",
    "tftp",
    "ldap",
    "ldaps",
    "jar",
    "netdoc",
}

INTERNAL_HOST_SUFFIXES = (".localhost", ".internal", ".local")

MAX_CALL_CONTINUATION_LINES = 8

COMMENT_PREFIXES = ("#", "//", "--")

SCHEME_REASON = (
    "A network request uses a non-HTTP URL scheme that is commonly used to "
    "reach internal services. Verify that the destination is expected."
)

INTERNAL_HOST_REASON = (
    "A network request targets a loopback, private, or internal host. "
    "Verify that the destination is expected and cannot be influenced by "
    "untrusted input."
)

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


def _split_arguments(text: str) -> tuple[list[str], bool]:
    """Split call arguments at top-level commas.

    Returns the arguments and whether the closing parenthesis was found.
    """

    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False

    for char in text:
        if escaped:
            escaped = False
            current.append(char)
            continue

        if quote:
            current.append(char)

            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None

            continue

        if char in {"'", '"', "`"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                arguments.append("".join(current).strip())
                return arguments, True

            depth -= 1
        elif char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
            continue

        current.append(char)

    arguments.append("".join(current).strip())

    return arguments, False


def _destination_candidates(
    active_lines: dict[int, str],
    number: int,
    match: re.Match[str],
) -> list[str]:
    """Return the expressions that select a request's destination."""

    line = active_lines[number]

    if not match.group(0).rstrip().endswith("("):
        # Command-line tools such as curl and wget: use the rest of the line.
        return [line[match.end():]]

    text = line[match.end():]
    arguments, closed = _split_arguments(text)
    following = number + 1

    while (
        not closed
        and following <= number + MAX_CALL_CONTINUATION_LINES
        and following <= max(active_lines, default=0)
    ):
        if following in active_lines:
            text += "\n" + active_lines[following]
            arguments, closed = _split_arguments(text)

        following += 1

    candidates = arguments[:1]

    if re.search(r"\brequest\s*\($", match.group(0)):
        # The first argument of a generic request call is the HTTP method.
        candidates = arguments[:2]

    candidates.extend(
        argument
        for argument in arguments[1:]
        if re.match(r"url\s*=", argument)
    )

    return [candidate for candidate in candidates if candidate]


def _host_of(authority: str) -> str:
    """Extract a lowercase host from a URL authority component."""

    authority = authority.rsplit("@", 1)[-1]

    if authority.startswith("["):
        return authority[1:].split("]", 1)[0].lower()

    return authority.split(":", 1)[0].rstrip(".").lower()


def _is_internal_host(host: str) -> bool:
    """Check for loopback, private, link-local, or internal hostnames."""

    if not host or "{" in host or "$" in host:
        return False

    if host == "localhost" or host.endswith(INTERNAL_HOST_SUFFIXES):
        return True

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    return not address.is_global


def _resolve_literals(
    candidate: str,
    number: int,
    literal_values: dict[str, list[tuple[int, str]]],
) -> tuple[list[str], list[int]]:
    """Resolve identifiers in a destination to earlier literal values.

    Returns texts to inspect and the source lines of resolved values.
    """

    texts = [candidate]
    source_lines: list[int] = []
    substituted = candidate

    for name in dict.fromkeys(IDENTIFIER_PATTERN.findall(candidate)):
        entries = literal_values.get(name)

        if not entries:
            continue

        before = [entry for entry in entries if entry[0] <= number]
        source_number, value = before[-1] if before else entries[0]

        texts.append(value)
        source_lines.append(source_number)
        substituted = re.sub(
            rf"\$?\{{\s*{re.escape(name)}\s*\}}",
            lambda _match, value=value: value,
            substituted,
        )

    if substituted != candidate:
        texts.append(substituted)

    return texts, source_lines


def _assess_destination(texts: list[str]) -> list[tuple[str, str, str]]:
    """Return (severity, reason, evidence) for risky destinations."""

    assessments: list[tuple[str, str, str]] = []

    for text in texts:
        if CLOUD_METADATA_DESTINATION.search(text):
            assessments.append(
                (
                    "high",
                    METADATA_REASON,
                    "Cloud metadata destination used by a network request",
                )
            )
            continue

        for url in URL_PATTERN.finditer(text):
            scheme = url.group("scheme").lower()
            host = _host_of(url.group("authority"))

            if scheme in SUSPICIOUS_SCHEMES:
                assessments.append(
                    (
                        "high",
                        SCHEME_REASON,
                        "Non-HTTP URL scheme used by a network request",
                    )
                )
            elif _is_internal_host(host):
                assessments.append(
                    (
                        "medium",
                        INTERNAL_HOST_REASON,
                        "Internal destination used by a network request",
                    )
                )

    return list(dict.fromkeys(assessments))


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

    # Record simple string-literal assignments so that destinations held in
    # constants can be resolved.
    literal_values: dict[str, list[tuple[int, str]]] = {}

    for number, line in active_lines.items():
        assignment = LITERAL_ASSIGNMENT.search(line)

        if assignment:
            literal_values.setdefault(assignment.group(1), []).append(
                (number, assignment.group("value"))
            )

    # Validate the destination that each network request actually uses.
    for number, line in active_lines.items():
        for sink_match in NETWORK_SINK.finditer(line):
            for candidate in _destination_candidates(
                active_lines,
                number,
                sink_match,
            ):
                texts, source_numbers = _resolve_literals(
                    candidate,
                    number,
                    literal_values,
                )

                for severity, reason, evidence in _assess_destination(texts):
                    add_finding(
                        severity,
                        reason,
                        [*source_numbers, number],
                        evidence,
                    )

    return sorted(
        findings,
        key=lambda finding: (
            finding["lines"][0],
            finding["category"],
        ),
    )