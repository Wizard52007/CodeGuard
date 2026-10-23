"""Aggregate findings into a risk score and verdict."""

from typing import Any


SEVERITY_WEIGHTS = {
    "low": 0.20,
    "medium": 0.45,
    "high": 0.75,
    "critical": 1.00,
}


def calculate_risk(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate an initial score from structured findings."""

    if not findings:
        return {
            "verdict": "allow",
            "risk_score": 0.0,
            "categories": [],
            "reason": "No configured security rules detected a threat.",
            "vulnerable_lines": [],
        }

    remaining_risk = 1.0

    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(
            finding.get("severity", "medium"),
            0.45,
        )
        remaining_risk *= 1.0 - weight

    risk_score = round(1.0 - remaining_risk, 4)

    categories = sorted({
        finding["category"]
        for finding in findings
        if finding.get("category")
    })

    vulnerable_lines = sorted({
        line
        for finding in findings
        for line in finding.get("lines", [])
        if isinstance(line, int) and line > 0
    })

    reasons = list(dict.fromkeys(
        finding["reason"]
        for finding in findings
        if finding.get("reason")
    ))

    # Provisional policy, to be calibrated against the public dataset.
    has_critical_finding = any(
        finding.get("severity") == "critical"
        for finding in findings
    )

    verdict = (
        "block"
        if has_critical_finding or risk_score >= 0.75
        else "allow"
    )

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "categories": categories,
        "reason": " ".join(reasons),
        "vulnerable_lines": vulnerable_lines,
    }