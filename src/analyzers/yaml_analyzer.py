"""Static security analysis for YAML configurations and workflows.

Submitted content is never executed.
Every finding follows the CodeGuard integration contract.
"""

from __future__ import annotations

import re

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from src.rules import prompt_injection


APPROVED_CATEGORIES = {
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
}

APPROVED_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


# A potential hardcoded credential in a YAML key/value pair.
_HARDCODED_SECRET = re.compile(
    r"""(?:^|[\s,{])"""
    r"""(?:password|passwd|token|secret|"""
    r"""api[_-]?(?:key|token|secret)|"""
    r"""access[_-]?key|private[_-]?key)"""
    r"""\s*:\s*(?P<value>[^,#\r\n]+)""",
    re.IGNORECASE,
)

_SECRET_REFERENCE = re.compile(
    r"""\$\{\{\s*secrets\.[A-Za-z_][\w-]*\s*\}\}"""
    r"""|\$\{?[A-Za-z_][A-Za-z0-9_]*"""
    r"""(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|CREDENTIALS?)"""
    r"""[A-Za-z0-9_]*\}?""",
    re.IGNORECASE,
)

_SENSITIVE_FILE_READ = re.compile(
    r"""\b(?:cat|head|tail|type|Get-Content|readFile|readFileSync)\b"""
    r""".{0,120}"""
    r"""(?:\.env\b|\.ssh[/\\](?:id_rsa|id_ed25519)\b|"""
    r"""credentials\.json\b|\.aws[/\\]credentials\b)""",
    re.IGNORECASE,
)

_NETWORK_SINK = re.compile(
    r"""\bcurl\b"""
    r"""|\bwget\b"""
    r"""|\bInvoke-WebRequest\b"""
    r"""|\bInvoke-RestMethod\b"""
    r"""|\bfetch\s*\("""
    r"""|\baxios(?:\s*\.\s*\w+)?\s*\("""
    r"""|\bsendBeacon\s*\("""
    r"""|\bnc\s+-""",
    re.IGNORECASE,
)

_REQUEST_PAYLOAD = re.compile(
    r"""(?:^|\s)-d(?:\s|$)"""
    r"""|--data(?:-raw)?\b"""
    r"""|(?:^|\s)-H(?:\s|$)"""
    r"""|--header\b"""
    r"""|\bBearer\b"""
    r"""|\b(?:body|data|headers)\s*:""",
    re.IGNORECASE,
)

_METADATA_DESTINATION = re.compile(
    r"""169\.254\.169\.254"""
    r"""|metadata\.google\.internal"""
    r"""|metadata\.azure\.com"""
    r"""|100\.100\.100\.200""",
    re.IGNORECASE,
)

_DESTRUCTIVE_COMMAND = re.compile(
    r"""\brm\s+-(?:rf|fr)\b"""
    r"""|\brm\b.*--(?:recursive|force)\b"""
    r"""|\bRemove-Item\b.*(?:-Recurse|-Force)"""
    r"""|\bdel\s+/[fqs]\b"""
    r"""|\bmkfs(?:\.\w+)?\b"""
    r"""|\bDROP\s+(?:DATABASE|TABLE)\b"""
    r"""|\bTRUNCATE\s+TABLE\b"""
    r"""|\bformat\s+[A-Z]:""",
    re.IGNORECASE,
)

_OBFUSCATED_EXECUTION = re.compile(
    r"""\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:ba)?sh\b"""
    r"""|\b(?:pwsh|powershell)\b.*\b-encodedcommand\b"""
    r"""|\beval\s*\(\s*(?:atob|Buffer\s*\.\s*from)\b""",
    re.IGNORECASE,
)

_DEPENDENCY_RISK = re.compile(
    r"""\b(?:pip3?|npm|yarn|pnpm)\s+(?:install|add)\b"""
    r""".{0,200}(?:https?://|git\+https?://)"""
    r"""|\buses\s*:\s*[\w./-]+@(?:master|main|latest)\b"""
    r"""|\bcurl\b.{0,160}\|\s*(?:bash|sh)\b""",
    re.IGNORECASE,
)

_RESOURCE_EXHAUSTION = re.compile(
    r"""\bwhile\s+(?:true|:)\s*;?\s*do\b"""
    r"""|:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:"""
    r"""|\byes\s+>\s*/dev/null\b"""
    r"""|\bdd\s+if=/dev/zero\b""",
    re.IGNORECASE,
)

def analyze(code: str) -> list[dict]:
    """Analyze YAML for security risks without executing its contents."""

    if not isinstance(code, str) or not code.strip():
        return []

    lines = code.splitlines()
    findings: list[dict] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add_finding(
        category: str,
        severity: str,
        reason: str,
        line_numbers: list[int],
        evidence: str,
    ) -> None:
        """Add a contract-compliant finding without exposing secrets."""

        if category not in APPROVED_CATEGORIES:
            return

        if severity not in APPROVED_SEVERITIES:
            return

        valid_lines = sorted(
            {
                line
                for line in line_numbers
                if isinstance(line, int)
                and not isinstance(line, bool)
                and 1 <= line <= len(lines)
            }
        )

        if not valid_lines:
            return

        key = (category, tuple(valid_lines))

        if key in seen:
            return

        seen.add(key)

        findings.append(
            {
                "category": category,
                "severity": severity,
                "reason": reason,
                "lines": valid_lines,
                "evidence": evidence,
            }
        )

    def matching_lines(pattern: re.Pattern[str]) -> list[int]:
        """Return one-based line numbers, excluding YAML comments."""
        return [
            number
            for number, line in enumerate(lines, start=1)
            if not line.lstrip().startswith("#")
            and pattern.search(line)
        ]

    # ---------------------------------------------------------
    # 1. Inspect YAML structure for risky security settings.
    # ---------------------------------------------------------

    try:
        root = yaml.compose(code, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        # Continue with static text checks. Invalid YAML is never executed.
        root = None

    def inspect_node(node: object) -> None:
        """Inspect parsed YAML nodes and preserve their source positions."""

        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    inspect_node(value_node)
                    continue

                key_name = str(key_node.value).strip().lower()
                key_line = key_node.start_mark.line + 1

                if isinstance(value_node, ScalarNode):
                    value = str(value_node.value).strip().lower()
                    value_line = value_node.start_mark.line + 1

                    if (
                        key_name in {
                            "privileged",
                            "allowprivilegeescalation",
                            "allow_privilege_escalation",
                        }
                        and value in {"true", "yes", "on"}
                    ):
                        add_finding(
                            "persistence_or_privesc",
                            "high",
                            (
                                "The configuration enables a privileged "
                                "execution setting."
                            ),
                            [value_line],
                            "Privileged-execution configuration",
                        )

                    if (
                        key_name in {"runasuser", "run_as_user"}
                        and value == "0"
                    ):
                        add_finding(
                            "persistence_or_privesc",
                            "high",
                            (
                                "The configuration specifies execution "
                                "as the root user."
                            ),
                            [value_line],
                            "Root-user configuration",
                        )

                if key_name == "hostpath":
                    add_finding(
                        "persistence_or_privesc",
                        "medium",
                        (
                            "The configuration mounts a host filesystem "
                            "path. Check whether host access is necessary."
                        ),
                        [key_line],
                        "Host-path mount configuration",
                    )

                inspect_node(value_node)

        elif isinstance(node, SequenceNode):
            for item in node.value:
                inspect_node(item)

    if root is not None:
        inspect_node(root)

    # ---------------------------------------------------------
    # 2. Secret access.
    # ---------------------------------------------------------

    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue

        secret_read = _SENSITIVE_FILE_READ.search(line)

        secret_match = _HARDCODED_SECRET.search(line)
        hardcoded_secret = False

        if secret_match:
            value = secret_match.group("value").strip().strip("'\"")
            normalized = value.lower()

            placeholders = {
                "changeme",
                "change_me",
                "placeholder",
                "redacted",
                "your_secret",
                "your_token",
                "your_password",
                "example",
            }

            hardcoded_secret = (
                len(value) >= 8
                and not value.startswith(("$", "${{", "<"))
                and "${{" not in value
                and normalized not in placeholders
                and "your_" not in normalized
            )

        if secret_read:
            add_finding(
                "secret_access",
                "high",
                (
                    "A command or operation appears to read a sensitive "
                    "credential file."
                ),
                [number],
                "Sensitive credential-file access pattern",
            )

        elif hardcoded_secret:
            add_finding(
                "secret_access",
                "high",
                (
                    "A YAML key appears to contain a hardcoded credential. "
                    "Move the value into an appropriate secret store."
                ),
                [number],
                "Hardcoded-credential assignment pattern",
            )

    # ---------------------------------------------------------
    # 3. Network access, SSRF and potential data exfiltration.
    # ---------------------------------------------------------

    network_lines = matching_lines(_NETWORK_SINK)

    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue

        if _METADATA_DESTINATION.search(line):
            add_finding(
                "ssrf_network_exfil",
                "high",
                (
                    "The configuration references a sensitive cloud "
                    "metadata destination. Verify that access is intended."
                ),
                [number],
                "Cloud metadata endpoint pattern",
            )

        if (
            _NETWORK_SINK.search(line)
            and _SECRET_REFERENCE.search(line)
            and _REQUEST_PAYLOAD.search(line)
        ):
            add_finding(
                "secret_access",
                "high",
                (
                    "The network command directly references a sensitive "
                    "credential or secret variable."
                ),
                [number],
                "Secret reference in a network command",
            )

            add_finding(
                "data_exfiltration",
                "high",
                (
                    "A network command appears to transmit a sensitive "
                    "value in its request data or headers."
                ),
                [number],
                "Sensitive-value reference in a network payload",
            )

    # Correlate multiline command payloads conservatively.
    for sink in network_lines:
        start = max(1, sink - 2)
        end = min(len(lines), sink + 5)

        context_lines = list(range(start, end + 1))
        context = "\n".join(lines[number - 1] for number in context_lines)

        secret_lines = [
            number
            for number in context_lines
            if _SECRET_REFERENCE.search(lines[number - 1])
        ]

        payload_lines = [
            number
            for number in context_lines
            if _REQUEST_PAYLOAD.search(lines[number - 1])
        ]

        if (
            secret_lines
            and payload_lines
            and _NETWORK_SINK.search(lines[sink - 1])
        ):
            relevant_lines = sorted(
                set(secret_lines + payload_lines + [sink])
            )

            add_finding(
                "data_exfiltration",
                "high",
                (
                    "A sensitive value and network payload occur close "
                    "together in the configuration. Review their data flow."
                ),
                relevant_lines,
                "Potential secret-to-network data flow",
            )

    # ---------------------------------------------------------
    # 4. Destructive commands.
    # ---------------------------------------------------------

    for number in matching_lines(_DESTRUCTIVE_COMMAND):
        add_finding(
            "destructive_command",
            "high",
            (
                "The configuration contains a potentially destructive "
                "command. Review its target and execution context."
            ),
            [number],
            "Destructive-command pattern",
        )

    # ---------------------------------------------------------
    # 5. Obfuscated execution.
    # ---------------------------------------------------------

    for number in matching_lines(_OBFUSCATED_EXECUTION):
        add_finding(
            "obfuscated_execution",
            "high",
            (
                "An encoded or dynamically constructed payload appears "
                "to be passed to an execution mechanism."
            ),
            [number],
            "Encoded-payload execution pattern",
        )

    # ---------------------------------------------------------
    # 6. Dependency and supply-chain risks.
    # ---------------------------------------------------------

    for number in matching_lines(_DEPENDENCY_RISK):
        add_finding(
            "dependency_risk",
            "medium",
            (
                "The configuration contains a potentially unpinned or "
                "direct-URL dependency source. Verify its provenance."
            ),
            [number],
            "Dependency-source risk pattern",
        )

    # ---------------------------------------------------------
    # 7. Resource exhaustion.
    # ---------------------------------------------------------

    for number in matching_lines(_RESOURCE_EXHAUSTION):
        add_finding(
            "resource_exhaustion",
            "high",
            (
                "The command contains a loop or operation that may "
                "consume resources without a practical limit."
            ),
            [number],
            "Resource-exhaustion command pattern",
        )

    # ---------------------------------------------------------
    # 8. AI-targeted instructions.
    # Comments are included because instructions can be hidden there.
    # ---------------------------------------------------------

    for finding in prompt_injection.analyze(code):
        add_finding(
            finding["category"],
            finding["severity"],
            finding["reason"],
            finding["lines"],
            finding["evidence"],
        )

    return findings