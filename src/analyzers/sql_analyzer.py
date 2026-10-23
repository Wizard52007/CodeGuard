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


def analyze(code: str) -> list[dict[str, Any]]:
    """Analyze SQL source and return findings using the shared schema."""

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    sql = _remove_comments(code)

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