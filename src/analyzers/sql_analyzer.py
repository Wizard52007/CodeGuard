"""Static security analyzer for SQL snippets.

This analyzer inspects SQL text only. It never executes submitted queries.
"""

import re
from typing import Any


RULES = [
    {
        "category": "destructive_command",
        "severity": "high",
        "pattern": re.compile(
            r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b",
            re.IGNORECASE,
        ),
        "reason": (
            "The query contains a DROP statement that can remove "
            "database objects."
        ),
        "evidence": "DROP statement",
    },
    {
        "category": "destructive_command",
        "severity": "high",
        "pattern": re.compile(
            r"\bTRUNCATE\s+TABLE\b",
            re.IGNORECASE,
        ),
        "reason": (
            "The query contains a TRUNCATE TABLE statement that can "
            "remove all rows from a table."
        ),
        "evidence": "TRUNCATE TABLE statement",
    },
    {
        "category": "obfuscated_execution",
        "severity": "high",
        "pattern": re.compile(
            r"\bEXEC(?:UTE)?\s*\(",
            re.IGNORECASE,
        ),
        "reason": (
            "The query contains a function-style EXEC or EXECUTE call "
            "that may indicate dynamic SQL execution."
        ),
        "evidence": "EXEC/EXECUTE call",
    },
    {
        "category": "data_exfiltration",
        "severity": "medium",
        "pattern": re.compile(
            r"\bSELECT\s+\*\s+FROM\b",
            re.IGNORECASE,
        ),
        "reason": (
            "The query selects all columns from a table. Review the "
            "scope and authorization of the data access."
        ),
        "evidence": "SELECT * FROM",
    },
]


def _remove_comments(sql: str) -> str:
    """Remove basic SQL comments while preserving line numbering."""

    # Preserve newlines so findings continue to reference original lines.
    sql = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), sql, flags=re.DOTALL)
    sql = re.sub(r"--[^\r\n]*", "", sql)
    return sql


UNSCOPED_STATEMENT = re.compile(
    r"\bDELETE\s+FROM\s+[^\s;]+"
    r"|\bUPDATE\s+[^\s;(]+\s+SET\b",
    re.IGNORECASE,
)

WHERE_CLAUSE = re.compile(r"\bWHERE\b(?P<condition>[^;]*)", re.IGNORECASE)

# A condition that is always true does not limit the affected rows.
ALWAYS_TRUE_CONDITION = re.compile(
    r"^\s*\(*\s*(?:1\s*=\s*1|true)\s*\)*\s*$",
    re.IGNORECASE,
)


def _mask_string_literals(sql: str) -> str:
    """Blank out quoted text while keeping offsets and line numbers."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return re.sub(r"'(?:[^']|'')*'", blank, sql)


def _unscoped_statement_lines(sql: str) -> list[tuple[int, str]]:
    """Find DELETE and UPDATE statements that have no limiting WHERE."""

    masked = _mask_string_literals(sql)
    results: list[tuple[int, str]] = []

    for match in UNSCOPED_STATEMENT.finditer(masked):
        end = masked.find(";", match.end())
        statement = masked[match.start():] if end == -1 else masked[match.start():end]
        where = WHERE_CLAUSE.search(statement)

        if where and not ALWAYS_TRUE_CONDITION.match(where.group("condition")):
            continue

        kind = "DELETE" if match.group(0).upper().startswith("DELETE") else "UPDATE"
        results.append((masked.count("\n", 0, match.start()) + 1, kind))

    return results


def analyze(code: str) -> list[dict[str, Any]]:
    """Analyze SQL source and return findings using the shared schema."""

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    sql = _remove_comments(code)

    for line_number, kind in _unscoped_statement_lines(sql):
        key = ("destructive_command", line_number)

        if key in seen:
            continue

        seen.add(key)

        findings.append({
            "category": "destructive_command",
            "severity": "high",
            "reason": (
                f"The query contains a {kind} statement without a limiting "
                "WHERE clause, so it affects every row in the table."
            ),
            "lines": [line_number],
            "evidence": f"{kind} without WHERE",
        })

    for rule in RULES:
        for match in rule["pattern"].finditer(sql):
            line_number = sql.count("\n", 0, match.start()) + 1
            key = (rule["category"], line_number)

            if key in seen:
                continue

            seen.add(key)

            findings.append({
                "category": rule["category"],
                "severity": rule["severity"],
                "reason": rule["reason"],
                "lines": [line_number],
                "evidence": rule["evidence"],
            })

    return findings