"""Initial static security analyzer for JavaScript.

This module performs local analysis only. Submitted code is never executed.
Each finding follows the CodeGuard integration contract.
"""

from __future__ import annotations

import re


def analyze(code: str) -> list[dict]:
    """Analyze JavaScript and return structured security findings."""

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
        """Create a validated, deduplicated finding."""

        valid_lines = sorted({
            line
            for line in line_numbers
            if isinstance(line, int) and 1 <= line <= len(lines)
        })

        if not valid_lines:
            return

        key = (category, tuple(valid_lines))
        if key in seen:
            return

        seen.add(key)

        findings.append({
            "category": category,
            "severity": severity,
            "reason": reason,
            "lines": valid_lines,
            "evidence": evidence,
        })

    def matching_lines(pattern: str) -> list[int]:
        """Return one-based line numbers matching a pattern."""
        expression = re.compile(pattern, re.IGNORECASE)
        return [
            index
            for index, line in enumerate(lines, start=1)
            if expression.search(line)
        ]

    # ---------------------------------------------------------
    # 1. Secret access
    # ---------------------------------------------------------

    sensitive_vars: dict[str, int] = {}

    sensitive_name = re.compile(
        r"(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|API[_-]?KEY|"
        r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY)",
        re.IGNORECASE,
    )

    env_dot_pattern = re.compile(
        r"process\s*\.\s*env\s*\.\s*([A-Za-z_$][\w$]*)",
        re.IGNORECASE,
    )

    env_bracket_pattern = re.compile(
        r"""process\s*\.\s*env\s*\[\s*['"]([^'"]+)['"]\s*\]""",
        re.IGNORECASE,
    )

    sensitive_file_pattern = re.compile(
        r"""(?:\.aws[/\\]credentials|\.ssh[/\\](?:id_rsa|id_ed25519)|"""
        r"""(?:^|[/\\])\.env(?:['"]|\s|$)|"""
        r"""credentials\.json|private[_-]?key)""",
        re.IGNORECASE,
    )

    secret_assignment_pattern = re.compile(
        r"""(?:api[_-]?key|secret|token|password|access[_-]?key)"""
        r"""\s*[:=]\s*(['"])[^'"\r\n]{8,}\1""",
        re.IGNORECASE,
    )

    for number, line in enumerate(lines, start=1):
        env_names = env_dot_pattern.findall(line)
        env_names.extend(env_bracket_pattern.findall(line))

        sensitive_env_names = [
            name for name in env_names
            if sensitive_name.search(name)
        ]

        reads_sensitive_file = (
            sensitive_file_pattern.search(line) is not None
            and re.search(
                r"\b(?:readFileSync|readFile|createReadStream|open)\b",
                line,
                re.IGNORECASE,
            ) is not None
        )

        hardcoded_secret_assignment = (
            secret_assignment_pattern.search(line) is not None
        )

        is_secret_access = bool(
            sensitive_env_names
            or reads_sensitive_file
            or hardcoded_secret_assignment
        )

        if not is_secret_access:
            continue

        if reads_sensitive_file:
            severity = "high"
            reason = (
                "The code appears to read a sensitive credentials or "
                "private-key file."
            )
            evidence = "Sensitive credential-file access pattern"
        elif hardcoded_secret_assignment:
            severity = "high"
            reason = (
                "The code appears to contain a hardcoded credential "
                "or secret value."
            )
            evidence = "Hardcoded-secret assignment pattern"
        else:
            severity = "medium"
            reason = (
                "The code accesses an environment variable whose name "
                "suggests sensitive credentials."
            )
            evidence = "Sensitive environment-variable reference"

        add_finding(
            "secret_access",
            severity,
            reason,
            [number],
            evidence,
        )

        # Track variable assignments for contextual data-flow checks.
        assignment = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=",
            line,
        )

        if assignment:
            sensitive_vars[assignment.group(1)] = number

    # ---------------------------------------------------------
    # 2. Network sinks and potential SSRF
    # ---------------------------------------------------------

    network_pattern = (
        r"\bfetch\s*\("
        r"|\baxios(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*\("
        r"|\bhttps?\s*\.\s*request\s*\("
        r"|\bsendBeacon\s*\("
    )

    network_lines = matching_lines(network_pattern)

    metadata_pattern = re.compile(
        r"169\.254\.169\.254"
        r"|metadata\.google\.internal"
        r"|metadata\.azure\.com"
        r"|100\.100\.100\.200",
        re.IGNORECASE,
    )

    for number, line in enumerate(lines, start=1):
        if metadata_pattern.search(line):
            related_sinks = [
                sink for sink in network_lines
                if abs(sink - number) <= 8
            ]

            if re.search(network_pattern, line, re.IGNORECASE):
                related_sinks.append(number)

            if related_sinks:
                add_finding(
                    "ssrf_network_exfil",
                    "high",
                    (
                        "A network request appears to target a sensitive "
                        "cloud metadata endpoint."
                    ),
                    [number, *related_sinks],
                    "Cloud metadata destination pattern",
                )

    # Identify common request values originating from user input.
    user_controlled_vars: dict[str, int] = {}

    user_input_assignment = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
        r"(?:req|request)\s*\.\s*(?:query|params|body)\b",
        re.IGNORECASE,
    )

    for number, line in enumerate(lines, start=1):
        match = user_input_assignment.search(line)
        if match:
            user_controlled_vars[match.group(1)] = number

    for sink in network_lines:
        sink_text = lines[sink - 1]

        for variable, source_line in user_controlled_vars.items():
            if re.search(rf"\b{re.escape(variable)}\b", sink_text):
                add_finding(
                    "ssrf_network_exfil",
                    "medium",
                    (
                        "A network request uses a destination derived "
                        "from a common user-controlled request field."
                    ),
                    [source_line, sink],
                    "User-controlled URL candidate reaches a network sink",
                )

    # ---------------------------------------------------------
    # 3. Data exfiltration: correlate sensitive values with sinks
    # ---------------------------------------------------------

    request_data_pattern = re.compile(
        r"\b(?:body|data|headers|params)\s*:",
        re.IGNORECASE,
    )

    for sink in network_lines:
        # Inspect a bounded region to associate a request with data.
        end = min(len(lines), sink + 11)
        context = "\n".join(lines[sink - 1:end])

        for variable, source_line in sensitive_vars.items():
            if not re.search(rf"\b{re.escape(variable)}\b", context):
                continue

            if not request_data_pattern.search(context):
                continue

            related_lines = [source_line, sink]

            for offset, context_line in enumerate(
                lines[sink - 1:end],
                start=sink,
            ):
                if (
                    re.search(
                        rf"\b{re.escape(variable)}\b",
                        context_line,
                    )
                    and request_data_pattern.search(context_line)
                ):
                    related_lines.append(offset)

            add_finding(
                "data_exfiltration",
                "high",
                (
                    "A sensitive value appears to flow into data or "
                    "headers associated with a network request."
                ),
                related_lines,
                "Potential sensitive-data flow into a network request",
            )

    # ---------------------------------------------------------
    # 4. Destructive command execution
    # ---------------------------------------------------------

    command_execution_lines = matching_lines(
        r"\b(?:exec|execSync|spawn|spawnSync)\s*\("
    )

    destructive_command_pattern = re.compile(
        r"""rm\s+-rf\b"""
        r"""|(?:del|erase)\s+/[fq]\b"""
        r"""|mkfs(?:\.\w+)?\b"""
        r"""|format\s+[a-z]:"""
        r"""|shutdown\s+-(?:h|s|r)\b""",
        re.IGNORECASE,
    )

    if command_execution_lines:
        for number, line in enumerate(lines, start=1):
            if destructive_command_pattern.search(line):
                related = [
                    sink for sink in command_execution_lines
                    if abs(sink - number) <= 4
                ]

                if related or re.search(
                    r"\b(?:exec|execSync|spawn|spawnSync)\s*\(",
                    line,
                ):
                    add_finding(
                        "destructive_command",
                        "high",
                        (
                            "The code appears to pass a destructive "
                            "command to a process-execution operation."
                        ),
                        [number, *related],
                        "Destructive shell-command pattern",
                    )

    # ---------------------------------------------------------
    # 5. Obfuscated execution
    # ---------------------------------------------------------

    decoder_lines = matching_lines(
        r"\batob\s*\("
        r"|\bBuffer\s*\.\s*from\s*\("
        r"|\bString\s*\.\s*fromCharCode\s*\("
    )

    dynamic_execution_lines = matching_lines(
        r"\beval\s*\("
        r"|\bnew\s+Function\s*\("
    )

    if decoder_lines and dynamic_execution_lines:
        add_finding(
            "obfuscated_execution",
            "high",
            (
                "Dynamic code execution is combined with an encoding "
                "or decoding operation, which may conceal behavior."
            ),
            [*decoder_lines, *dynamic_execution_lines],
            "Decoder and dynamic-execution pattern combination",
        )

    # ---------------------------------------------------------
    # 6. Persistence or privilege escalation
    # ---------------------------------------------------------

    privileged_operation_lines = matching_lines(
        r"\bsudo\b"
        r"|\bchmod\s+777\b"
        r"|\bcrontab\b"
        r"|\blaunchctl\b"
        r"|\bschtasks\b"
        r"|\.bashrc\b"
        r"|/etc/rc\.local\b"
    )

    if command_execution_lines and privileged_operation_lines:
        add_finding(
            "persistence_or_privesc",
            "high",
            (
                "A process-execution operation appears alongside "
                "a privilege or persistence-related command."
            ),
            [*command_execution_lines, *privileged_operation_lines],
            "Process execution with a privilege or persistence pattern",
        )

    # ---------------------------------------------------------
    # 7. Resource exhaustion
    # ---------------------------------------------------------

    unbounded_loop_lines = matching_lines(
        r"\bwhile\s*\(\s*true\s*\)"
        r"|\bwhile\s*\(\s*1\s*\)"
        r"|for\s*\(\s*;\s*;\s*\)"
    )

    for number in unbounded_loop_lines:
        add_finding(
            "resource_exhaustion",
            "medium",
            (
                "The code contains an apparently unbounded loop. "
                "Inspect whether it has a safe termination mechanism."
            ),
            [number],
            "Unbounded-loop candidate",
        )

    # ---------------------------------------------------------
    # 8. Dependency risk
    # ---------------------------------------------------------

    suspicious_install_lines = matching_lines(
        r"\b(?:npm|yarn|pnpm)\s+(?:install|add)\b.*"
        r"(?:https?://|git\+https?://)",
    )

    if command_execution_lines and suspicious_install_lines:
        add_finding(
            "dependency_risk",
            "medium",
            (
                "A package-installation command references a direct "
                "URL or Git-based dependency source."
            ),
            [*command_execution_lines, *suspicious_install_lines],
            "Direct-URL dependency installation pattern",
        )

    # ---------------------------------------------------------
    # 9. AI-targeted instructions
    # ---------------------------------------------------------

    ai_instruction_pattern = (
        r"ignore\s+(?:all\s+)?(?:previous|prior|preceding)\s+instructions"
        r"|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions"
        r"|reveal\s+(?:the\s+)?(?:secrets|credentials|system prompt)"
        r"|bypass\s+(?:the\s+)?security"
        r"|disable\s+(?:all\s+)?security\s+(?:checks|rules)"
        r"|hide\s+(?:this|the)\s+(?:vulnerability|malicious|threat)"
        r"|override\s+(?:your\s+)?(?:safety|security)\s+(?:rules|instructions)"
    )

    for number in matching_lines(ai_instruction_pattern):
        add_finding(
            "ai_targeted_instructions",
            "medium",
            (
                "The source contains instruction-like text that may "
                "attempt to override an AI agent's security behavior."
            ),
            [number],
            "AI-targeted instruction pattern",
        )

    return findings