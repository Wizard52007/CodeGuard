# CodeGuard Integration Contract v1.0

## 1. Central Detector

Import:
from src.detector import evaluate_code

Signature:
evaluate_code(code: str, language: str | None = None) -> dict

The language argument is optional. If omitted, the detector attempts
automatic language detection.

## 2. Supported Languages

- python
- bash
- javascript
- sql
- yaml
- markdown

Use lowercase canonical labels. Use unknown when the language cannot
be determined reliably.

## 3. Analyzer Interface

Every analyzer exposes:

analyze(code: str) -> list[dict]

Each finding must contain:

- category: one of the nine approved category identifiers
- severity: low, medium, high, or critical
- reason: human-readable explanation
- lines: one-based line numbers in the original submitted input
- evidence: short, non-sensitive supporting evidence

## 4. Threat Categories

- secret_access
- data_exfiltration
- destructive_command
- persistence_or_privesc
- obfuscated_execution
- dependency_risk
- resource_exhaustion
- ssrf_network_exfil
- ai_targeted_instructions

## 5. Public Response

Required fields:

- verdict: allow or block
- risk_score: number between 0.0 and 1.0
- categories: list of detected category identifiers
- code_language: canonical language label

Additional agreed fields:

- reason: explanation of the decision
- vulnerable_lines: sorted, unique, one-based line numbers

## 6. Risk Engine

The risk engine consumes findings from all registered analyzers,
aggregates the evidence, calculates a risk score, and determines
whether the code should be allowed or blocked.

Severity weights and decision thresholds are provisional until
validated against the public development dataset.

## 7. Runtime Restrictions

- Security decisions must not depend on external LLM API calls.
- Submitted code must not be executed during static analysis.
- Blocked code must never reach the execution stage.
- Findings must not expose actual secrets.
- Malformed input must be handled predictably.

## 8. Ownership

Core detector, language detection, risk engine, and Python/Bash/SQL
analyzers: feature/core-detector.

FastAPI service, JavaScript/YAML/Markdown analyzers, API tests, and
execution-interception demo: feature/api-interception.

Changes to shared schemas or interfaces must be coordinated before
implementation.
