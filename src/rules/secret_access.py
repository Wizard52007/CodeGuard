"""Reusable static checks for potentially sensitive credential access.

Analysis is local and never reads the submitted code's runtime environment.
"""

from __future__ import annotations

import re


SENSITIVE_NAME = re.compile(
    r"API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"SECRET|TOKEN|PASSWORD|CREDENTIAL|"
    r"GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY",
    re.IGNORECASE,
)

ENVIRONMENT_ACCESS = re.compile(
    r"process\s*\.\s*env\b|"
    r"os\s*\.\s*(?:getenv|environ)\b|"
    r"\bgetenv\s*\(|"
    r"\bprintenv\b|"
    r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)

SENSITIVE_FILE_ACCESS = re.compile(
    r"(?:cat|head|tail|type|Get-Content|"
    r"readFileSync|readFile|createReadStream|open)\b"
    r".{0,160}"
    r"(?:\.env\b|"
    r"\.ssh[/\\](?:id_rsa|id_ed25519)\b|"
    r"\.aws[/\\]credentials\b|"
    r"credentials\.json\b|"
    r"private[_-]?key)",
    re.IGNORECASE,
)

HARDCODED_CREDENTIAL = re.compile(
    r"""(?:api[_-]?key|access[_-]?key|secret|token|"""
    r"""password|credential|private[_-]?key)"""
    r"""\s*[:=]\s*(['"])(?P<value>[^'"\r\n]{8,})\1""",
    re.IGNORECASE,
)

PLACEHOLDERS = {
    "changeme",
    "change_me",
    "placeholder",
    "redacted",
    "example",
    "your_token_here",
    "your_api_key_here",
    "your_password_here",
}


def analyze(code: str) -> list[dict]:
    """Return secret-access findings using the CodeGuard finding schema."""

    if not isinstance(code, str) or not code.strip():
        return []

    findings = []

    for line_number, line in enumerate(code.splitlines(), start=1):
        stripped = line.lstrip()

        # Ignore ordinary single-line comments.
        if stripped.startswith(("#", "//")):
            continue

        finding = None

        # Case 1: A potentially sensitive credential file is read.
        if SENSITIVE_FILE_ACCESS.search(line):
            finding = {
                "category": "secret_access",
                "severity": "high",
                "reason": (
                    "The source appears to read a sensitive credential "
                    "or private-key file."
                ),
                "evidence": "Sensitive credential-file access pattern",
            }

        # Case 2: A credential appears to be hardcoded.
        elif HARDCODED_CREDENTIAL.search(line):
            match = HARDCODED_CREDENTIAL.search(line)
            value = match.group("value").strip()

            if (
                value.lower() not in PLACEHOLDERS
                and not value.startswith(("$", "${", "<"))
                and "your_" not in value.lower()
                and "${{" not in value
            ):
                finding = {
                    "category": "secret_access",
                    "severity": "high",
                    "reason": (
                        "The source appears to contain a hardcoded "
                        "credential value."
                    ),
                    "evidence": "Hardcoded-credential assignment pattern",
                }

        # Case 3: A credential-like environment variable is accessed.
        elif (
            ENVIRONMENT_ACCESS.search(line)
            and SENSITIVE_NAME.search(line)
        ):
            finding = {
                "category": "secret_access",
                "severity": "medium",
                "reason": (
                    "The source accesses an environment variable whose "
                    "name suggests a sensitive credential."
                ),
                "evidence": "Sensitive environment-variable access pattern",
            }

        if finding is not None:
            findings.append({
                **finding,
                "lines": [line_number],
            })

    return findings
