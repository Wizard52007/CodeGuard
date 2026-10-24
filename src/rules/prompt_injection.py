"""Reusable static checks for AI-targeted instructions.

The rule examines text only. It does not invoke an AI model or execute code.
"""

from __future__ import annotations

import re
from bisect import bisect_right


CATEGORY = "ai_targeted_instructions"

# Explicit attempts to override an AI agent's behavior are high severity so
# that the risk engine blocks them consistently across every language.
SEVERITY = "high"

REASON = (
    "The text contains an instruction-like pattern that may "
    "attempt to override an AI agent's security behavior."
)

# Do not copy potentially sensitive submitted text into evidence.
EVIDENCE = "AI-targeted instruction pattern"

_PATTERNS = [
    re.compile(
        r"\bignore\s+(?:all\s+|any\s+)?"
        r"(?:previous|prior|preceding|above)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard\s+(?:all\s+|any\s+)?"
        r"(?:previous|prior|preceding|above)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reveal|expose|print|send)\s+(?:the\s+|your\s+)?"
        r"(?:(?:full|entire|complete)\s+)?"
        r"(?:secrets|credentials|system\s+prompt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:bypass|disable|override)\s+(?:the\s+|your\s+|all\s+)?"
        r"(?:security|safety)\s+(?:checks|rules|instructions|review)\b",
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
    # Instructions aimed at an automated reviewer. The "regardless" clause
    # keeps ordinary descriptions of tool behavior from matching.
    re.compile(
        r"\bapprove\s+(?:the\s+)?"
        r"(?:pull\s+request|merge\s+request|pr|changes?|commit|code)\b"
        r"[^.\n]{0,60}?\b(?:regardless|irrespective)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:report|mark|label|declare)\s+(?:the\s+)?"
        r"(?:code(?:base)?|repo(?:sitory)?|project|changes?|"
        r"pull\s+request|pr)\s+as\s+(?:fully\s+)?"
        r"(?:compliant|safe|secure|clean|approved|passing)\b"
        r"[^.\n]{0,40}?\b(?:regardless|irrespective|no matter)\b",
        re.IGNORECASE,
    ),
]


# Guidance such as "never reveal secrets" warns against the behavior rather
# than requesting it.
_NEGATION = re.compile(
    r"(?:\bnever|\bnot|n't|\bavoid|\bwithout)\s+(?:\w+\s+){0,2}$",
    re.IGNORECASE,
)


def find_spans(text: str) -> list[tuple[int, int]]:
    """Return (start, end) offsets of instruction-override phrases."""

    spans: list[tuple[int, int]] = []

    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            preceding = text[max(0, match.start() - 30):match.start()]

            if _NEGATION.search(preceding):
                continue

            spans.append((match.start(), match.end()))

    return sorted(spans)


def build_finding(lines: list[int]) -> dict:
    """Create a finding that follows the shared CodeGuard schema."""

    return {
        "category": CATEGORY,
        "severity": SEVERITY,
        "reason": REASON,
        "lines": sorted(set(lines)),
        "evidence": EVIDENCE,
    }


def _comment_content(
    line: str,
    state: str | None,
) -> tuple[str | None, str | None]:
    """Return (comment text, block-comment state) for a source line.

    The comment text is None when the line is not part of a comment.
    """

    stripped = line.strip()

    if state is None:
        if stripped.startswith("<!--"):
            body, closing, kind = stripped[4:], "-->", "html"
        elif stripped.startswith("/*"):
            body, closing, kind = stripped[2:], "*/", "block"
        elif stripped.startswith(("#", "//")):
            return stripped.lstrip("#/").strip(), None
        else:
            return None, None

        if closing in body:
            return body.split(closing, 1)[0].strip(), None

        return body.strip(), kind

    closing = "-->" if state == "html" else "*/"
    body = stripped

    if closing in body:
        body = body.split(closing, 1)[0]
        state = None

    if state == "block" or closing == "*/":
        body = body.lstrip("*")

    return body.strip(), state


def _blocks(lines: list[str]) -> list[tuple[str, list[tuple[int, int]]]]:
    """Group source lines into searchable text blocks.

    Consecutive comment lines are joined so that an instruction wrapped
    across comment lines is still recognized. Every other line is its own
    block. Each block records (offset, original line number) pairs.
    """

    blocks: list[tuple[str, list[tuple[int, int]]]] = []
    text = ""
    offsets: list[tuple[int, int]] = []
    state: str | None = None

    def flush() -> None:
        nonlocal text, offsets

        if text:
            blocks.append((text, offsets))

        text = ""
        offsets = []

    for number, line in enumerate(lines, start=1):
        content, state = _comment_content(line, state)

        if content is None:
            flush()
            blocks.append((line, [(0, number)]))
            continue

        if not content:
            flush()
            continue

        if text:
            text += " "

        offsets.append((len(text), number))
        text += content

    flush()

    return blocks


def analyze(code: str) -> list[dict]:
    """Return findings for instruction-like text that warrants review."""

    if not isinstance(code, str) or not code.strip():
        return []

    findings: list[dict] = []
    seen: set[tuple[int, ...]] = set()

    for text, offsets in _blocks(code.splitlines()):
        starts = [offset for offset, _ in offsets]

        for start, end in find_spans(text):
            first = max(bisect_right(starts, start) - 1, 0)
            last = max(bisect_right(starts, max(end - 1, start)) - 1, first)

            lines = tuple(
                sorted({number for _, number in offsets[first:last + 1]})
            )

            if lines in seen:
                continue

            seen.add(lines)
            findings.append(build_finding(list(lines)))

    return findings
