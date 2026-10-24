"""AST-based Python security analyzer."""

import ast
import re
import shlex
from collections import Counter
from typing import Any

from src.analyzers import bash_analyzer, sql_analyzer
from src.rules import prompt_injection


DANGEROUS_CALLS = {
    "os.remove": "Deletes a file.",
    "os.unlink": "Deletes a file.",
    "os.rmdir": "Deletes a directory.",
    "shutil.rmtree": "Recursively deletes a directory tree.",
}

DYNAMIC_EXECUTION_CALLS = {
    "exec",
    "eval",
}

PRIVILEGE_CALLS = {
    "os.setuid",
    "os.seteuid",
    "os.setgid",
    "os.setegid",
}

STARTUP_PATH_MARKERS = (
    ".config/autostart/",
    ".config/systemd/user/",
)

MAX_SAFE_LITERAL_EXPONENT = 10000

SECRET_NAME_PATTERN = re.compile(
    r"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|"
    r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)",
    re.IGNORECASE,
)

SECRET_PLACEHOLDERS = {
    "changeme",
    "change_me",
    "placeholder",
    "redacted",
    "example",
    "your_secret",
    "your_token",
    "your_password",
}

PACKAGE_INSTALL_COMMANDS = {
    "pip",
    "pip3",
    "pip.exe",
    "pip3.exe",
}

PACKAGE_INSTALL_SUBCOMMANDS = {
    "install",
    "download",
}

SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}

# Calls that always pass their command string to a shell.
SHELL_STRING_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}

COMMAND_KEYWORDS = {"args", "command", "cmd"}

# Stands in for values that cannot be resolved statically.
DYNAMIC_PLACEHOLDER = "__dynamic__"

# Command findings that are meaningful for a command executed from Python.
# Plain network transfer is covered by the dedicated network rules.
COMMAND_FINDING_CATEGORIES = {
    "destructive_command",
    "obfuscated_execution",
    "persistence_or_privesc",
    "resource_exhaustion",
}

# Only these names mark a string as text intended for an AI agent. Other
# strings, such as log messages and arbitrary data, are not scanned.
AI_CONTEXT_NAMES = {
    "description",
    "instruction",
    "instructions",
    "prompt",
    "system_prompt",
    "system",
    "content",
    "message",
    "text",
}

MAX_MULTILINE_STRING_SPAN = 10

OPEN_CALLS = {"open", "builtins.open", "io.open"}

PATH_PASSTHROUGH_CALLS = {
    "os.path.expanduser",
    "os.path.expandvars",
    "os.path.abspath",
    "os.path.normpath",
    "os.path.realpath",
    "os.fspath",
    "str",
}

PATH_CONSTRUCTOR_CALLS = {
    "os.path.join",
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PosixPath",
    "pathlib.PurePosixPath",
    "pathlib.PureWindowsPath",
}

PATH_READ_METHODS = {"read_text", "read_bytes"}
PATH_WRITE_METHODS = {"write_text", "write_bytes"}

# Well-known files whose contents are credentials. Paths are normalized to
# lowercase with forward slashes before matching.
CREDENTIAL_FILE_PATTERN = re.compile(
    r"(?:^|/)\.aws/credentials$"
    r"|(?:^|/)\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)$"
    r"|(?:^|/)\.docker/config\.json$"
    r"|(?:^|/)\.kube/config$"
    r"|(?:^|/)\.(?:netrc|pgpass|git-credentials|pypirc|npmrc)$"
    r"|(?:^|/)\.config/gcloud/(?:application_default_)?credentials[\w.]*$"
    r"|^/etc/shadow$"
)

# Files that grant persistence or elevated privileges when written.
PERSISTENCE_WRITE_PATTERN = re.compile(
    r"^/etc/sudoers(?:$|\.d/)"
    r"|^/(?:etc|lib|usr/lib)/systemd/(?:system|user)/"
    r"|(?:^|/)\.config/systemd/user/"
    r"|^/etc/cron(?:tab$|\.[a-z]+/|/)"
    r"|^/var/spool/cron/"
    r"|(?:^|/)\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv)$"
    r"|^/etc/(?:profile|bash\.bashrc|environment|rc\.local|ld\.so\.preload)$"
    r"|^/etc/(?:profile|init|rc\d?)\.d/"
    r"|(?:^|/)\.ssh/authorized_keys2?$"
    r"|/library/launch(?:agents|daemons)/"
    r"|/start menu/programs/startup/"
)

SQL_EXECUTE_METHODS = {
    "execute",
    "executescript",
    "read_sql",
    "read_sql_query",
    "raw",
}

SQL_STATEMENT = re.compile(
    r"\s*(SELECT|DELETE|UPDATE|DROP|TRUNCATE|INSERT|ALTER)\b",
    re.IGNORECASE,
)

SQL_VALUE_CLAUSE = re.compile(
    r"\b(?:WHERE|SET|VALUES|HAVING|LIKE|LIMIT)\b",
    re.IGNORECASE,
)

PRINTF_SPECIFIER = re.compile(
    r"%(?:\([^)]*\))?[#0\- +]*\d*(?:\.\d+)?[sdifr]"
)

FORMAT_FIELD = re.compile(r"\{[^{}]*\}")

# Calls that coerce a value to a number and therefore cannot carry SQL text.
SAFE_CAST_CALLS = {"int", "float", "bool", "len"}

DESERIALIZATION_CALLS = {
    "pickle.load",
    "pickle.loads",
    "pickle.Unpickler",
    "_pickle.load",
    "_pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "shelve.open",
    "pandas.read_pickle",
}

# Locations that other local users can write to, or names that state the
# data is not trusted.
UNTRUSTED_PATH_PATTERN = re.compile(
    r"^(?:/tmp/|/var/tmp/|/dev/shm/)"
    r"|untrusted|downloaded|uploaded|incoming|quarantine"
    r"|/temp/|%temp%",
    re.IGNORECASE,
)

UNTRUSTED_DATA_CALL_PREFIXES = (
    "requests.",
    "httpx.",
    "urllib.request.",
    "urllib2.",
)

UNTRUSTED_DATA_CALLS = {
    "base64.b64decode",
    "base64.decodebytes",
    "base64.urlsafe_b64decode",
}

UNTRUSTED_DATA_METHODS = {"recv", "recvfrom", "get_data"}

REQUEST_DATA_ATTRIBUTES = {"data", "body", "files", "form", "stream"}

LARGE_LOOP_THRESHOLD = 10_000
LARGE_ALLOCATION_THRESHOLD = 100_000_000

# Calls that create an operating-system resource which the loop does not
# release.
RESOURCE_ALLOCATING_CALLS = {
    "socket.socket",
    "socket.create_connection",
    "threading.Thread",
    "multiprocessing.Process",
    "os.fork",
    "subprocess.Popen",
}


def _resolve_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve a function name, accounting for imported aliases."""

    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)

    if isinstance(node, ast.Attribute):
        base = _resolve_name(node.value, aliases)
        return f"{base}.{node.attr}"

    return ""


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local import names to their fully qualified names."""

    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]

                if alias.asname:
                    aliases[local_name] = alias.name
                elif "." in alias.name:
                    aliases[local_name] = alias.name.split(".")[0]
                else:
                    aliases[local_name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""

            for alias in node.names:
                if alias.name == "*":
                    continue

                local_name = alias.asname or alias.name
                aliases[local_name] = f"{module}.{alias.name}"

    return aliases


def _string_value(node: ast.AST) -> str | None:
    """Return a literal string value when statically available."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return None


def _command_parts(
    node: ast.AST,
    aliases: dict[str, str],
) -> list[str] | None:
    """Extract a command from a subprocess-style argument list.

    Elements that are not string literals are replaced by a placeholder so
    that a literal executable and subcommand can still be recognized.
    """

    if not isinstance(node, (ast.List, ast.Tuple)):
        return None

    parts: list[str] = []

    for element in node.elts:
        value = _string_value(element)

        if value is None and _resolve_name(element, aliases) == "sys.executable":
            value = "python"

        parts.append(DYNAMIC_PLACEHOLDER if value is None else value)

    return parts


def _is_package_install_command(parts: list[str]) -> bool:
    """Check whether literal command arguments invoke pip installation."""

    if not parts:
        return False

    executable = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    executable = executable.removesuffix(".exe")

    # Recognize pip install ... and pip download ...
    if executable in {"pip", "pip3"}:
        return (
            len(parts) >= 2
            and parts[1].lower() in PACKAGE_INSTALL_SUBCOMMANDS
        )

    # Recognize python -m pip install ... and python3 -m pip install ...
    if executable in {"python", "python3"}:
        return (
            len(parts) >= 4
            and parts[1:3] == ["-m", "pip"]
            and parts[3].lower() in PACKAGE_INSTALL_SUBCOMMANDS
        )

    return False


def _is_unbounded_loop_test(node: ast.AST) -> bool:
    """Check whether a while-loop condition is the literal True."""

    return isinstance(node, ast.Constant) and node.value is True


def _is_suspicious_exponent(node: ast.AST) -> bool:
    """Detect exponentiation with an unusually large literal exponent."""

    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Pow):
        return False

    exponent = node.right

    return (
        isinstance(exponent, ast.Constant)
        and isinstance(exponent.value, int)
        and not isinstance(exponent.value, bool)
        and exponent.value > MAX_SAFE_LITERAL_EXPONENT
    )


def _collect_constants(tree: ast.AST) -> dict[str, ast.AST]:
    """Map names assigned exactly once to their assigned expression."""

    store_counts: Counter[str] = Counter()
    candidates: dict[str, ast.AST] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            store_counts[node.id] += 1

        elif isinstance(node, ast.arg):
            # Parameters are supplied by the caller and are never constants.
            store_counts[node.arg] += 2

        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            candidates[node.targets[0].id] = node.value

        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            candidates[node.target.id] = node.value

    return {
        name: value
        for name, value in candidates.items()
        if store_counts[name] == 1
    }


def _render_command(
    node: ast.AST,
    constants: dict[str, ast.AST],
    depth: int = 0,
) -> str | None:
    """Render the literal text of a command expression.

    Dynamic fragments become a placeholder. None is returned when the
    expression has no statically known text at all.
    """

    if depth > 5:
        return None

    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None

    if isinstance(node, ast.JoinedStr):
        return "".join(
            value.value
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            else DYNAMIC_PLACEHOLDER
            for value in node.values
        )

    if isinstance(node, ast.Name):
        assigned = constants.get(node.id)

        if assigned is None:
            return None

        return _render_command(assigned, constants, depth + 1)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _render_command(node.left, constants, depth + 1)
        right = _render_command(node.right, constants, depth + 1)

        if left is None and right is None:
            return None

        return (
            (DYNAMIC_PLACEHOLDER if left is None else left)
            + (DYNAMIC_PLACEHOLDER if right is None else right)
        )

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _render_command(node.left, constants, depth + 1)

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _render_command(node.func.value, constants, depth + 1)

    return None


def _is_fully_dynamic(text: str | None) -> bool:
    """Check whether a rendered command has no literal content."""

    return text is None or not text.replace(DYNAMIC_PLACEHOLDER, "").strip()


def _command_expression(call: ast.Call) -> ast.AST | None:
    """Return the expression holding the command passed to a call."""

    if call.args:
        return call.args[0]

    for keyword in call.keywords:
        if keyword.arg in COMMAND_KEYWORDS:
            return keyword.value

    return None


def _has_shell_true(call: ast.Call) -> bool:
    """Check for a literal shell=True keyword argument."""

    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    )


def _classify_command(text: str) -> list[dict[str, str]]:
    """Check rendered command text against the shell command patterns."""

    results: list[dict[str, str]] = []

    for finding in bash_analyzer.analyze(text):
        if finding["category"] in COMMAND_FINDING_CATEGORIES:
            results.append(
                {
                    "category": finding["category"],
                    "severity": finding["severity"],
                    "reason": finding["reason"],
                    "evidence": finding["evidence"],
                }
            )

    try:
        parts = shlex.split(text)
    except ValueError:
        parts = []

    if _is_package_install_command(parts):
        results.append(
            {
                "category": "dependency_risk",
                "severity": "high",
                "reason": (
                    "The code invokes a package installation or "
                    "download command through a subprocess."
                ),
                "evidence": "Subprocess package-management command",
            }
        )

    return results


def _ai_context_strings(tree: ast.AST) -> list[ast.Constant]:
    """Collect string literals that are presented as text for an AI agent.

    Only docstrings, values stored under AI-facing names, and keyword or
    variable names such as "description" or "prompt" are returned.
    """

    def is_text(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def is_ai_name(name: object) -> bool:
        return isinstance(name, str) and name.lower() in AI_CONTEXT_NAMES

    strings: list[ast.Constant] = []

    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            first = node.body[0] if node.body else None

            if isinstance(first, ast.Expr) and is_text(first.value):
                strings.append(first.value)

        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and is_ai_name(key.value)
                    and is_text(value)
                ):
                    strings.append(value)

        elif isinstance(node, ast.keyword):
            if is_ai_name(node.arg) and is_text(node.value):
                strings.append(node.value)

        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
            )

            if is_text(node.value) and any(
                isinstance(target, ast.Name) and is_ai_name(target.id)
                for target in targets
            ):
                strings.append(node.value)

    return strings


def _string_match_lines(
    node: ast.Constant,
    start: int,
    end: int,
) -> list[int]:
    """Map a match inside a string literal to original source lines."""

    value = node.value
    first_line = node.lineno
    last_line = getattr(node, "end_lineno", None) or first_line

    if "\n" in value:
        lines = {
            first_line + value.count("\n", 0, start),
            first_line + value.count("\n", 0, max(end - 1, start)),
        }
        return sorted(min(line, last_line) for line in lines)

    # Adjacent literals are merged into one value without newlines, so the
    # phrase may sit anywhere in the literal's source range.
    if 0 < last_line - first_line <= MAX_MULTILINE_STRING_SPAN:
        return list(range(first_line, last_line + 1))

    return [first_line]


def _render_path(
    node: ast.AST,
    constants: dict[str, ast.AST],
    aliases: dict[str, str],
    depth: int = 0,
) -> str | None:
    """Statically render a filesystem path expression.

    Unknown fragments become a placeholder. None is returned when nothing
    about the path is known.
    """

    if depth > 6:
        return None

    def render(child: ast.AST) -> str | None:
        return _render_path(child, constants, aliases, depth + 1)

    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None

    if isinstance(node, ast.Name):
        assigned = constants.get(node.id)
        return None if assigned is None else render(assigned)

    if isinstance(node, ast.JoinedStr):
        parts = []

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                rendered = render(value.value)
                parts.append(DYNAMIC_PLACEHOLDER if rendered is None else rendered)
            else:
                parts.append(DYNAMIC_PLACEHOLDER)

        return "".join(parts)

    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        left = render(node.left)
        right = render(node.right)

        if left is None and right is None:
            return None

        separator = "/" if isinstance(node.op, ast.Div) else ""

        return (
            (DYNAMIC_PLACEHOLDER if left is None else left)
            + separator
            + (DYNAMIC_PLACEHOLDER if right is None else right)
        )

    if isinstance(node, ast.Call):
        name = _resolve_name(node.func, aliases)

        if name == "pathlib.Path.home":
            return "~"

        if name in PATH_PASSTHROUGH_CALLS and node.args:
            return render(node.args[0])

        if name in PATH_CONSTRUCTOR_CALLS and node.args:
            parts = [render(argument) for argument in node.args]

            if all(part is None for part in parts):
                return None

            return "/".join(
                DYNAMIC_PLACEHOLDER if part is None else part
                for part in parts
            )

    return None


def _normalize_path(path: str) -> str:
    """Normalize separators and case so path patterns can be matched."""

    return path.replace("\\", "/").strip().lower()


def _file_access(
    node: ast.Call,
    aliases: dict[str, str],
    constants: dict[str, ast.AST],
) -> tuple[str, bool] | None:
    """Return (normalized path, is_write) for a recognizable file access."""

    def is_write_mode(mode: ast.AST | None) -> bool:
        return (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and any(flag in mode.value for flag in "wax+")
        )

    def keyword_value(name: str) -> ast.AST | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value

        return None

    call_name = _resolve_name(node.func, aliases)

    if call_name in OPEN_CALLS and node.args:
        path = _render_path(node.args[0], constants, aliases)
        mode = node.args[1] if len(node.args) > 1 else keyword_value("mode")

        if path is None:
            return None

        return _normalize_path(path), is_write_mode(mode)

    if isinstance(node.func, ast.Attribute):
        method = node.func.attr

        if method in PATH_READ_METHODS | PATH_WRITE_METHODS | {"open"}:
            path = _render_path(node.func.value, constants, aliases)

            if path is None:
                return None

            if method == "open":
                mode = node.args[0] if node.args else keyword_value("mode")
                write = is_write_mode(mode)
            else:
                write = method in PATH_WRITE_METHODS

            return _normalize_path(path), write

    return None


def _sql_part(
    node: ast.AST,
    constants: dict[str, ast.AST],
    depth: int = 0,
) -> tuple[str, bool]:
    """Render SQL text and report whether it embeds non-constant values."""

    if depth > 6:
        return DYNAMIC_PLACEHOLDER, True

    def part(child: ast.AST) -> tuple[str, bool]:
        return _sql_part(child, constants, depth + 1)

    if isinstance(node, ast.Constant):
        return str(node.value), False

    if isinstance(node, ast.Name):
        assigned = constants.get(node.id)

        if assigned is None:
            return DYNAMIC_PLACEHOLDER, True

        return part(assigned)

    if isinstance(node, ast.JoinedStr):
        text = ""
        dynamic = False

        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                rendered, is_dynamic = part(value.value)
            elif isinstance(value, ast.Constant):
                rendered, is_dynamic = str(value.value), False
            else:
                rendered, is_dynamic = DYNAMIC_PLACEHOLDER, True

            text += rendered
            dynamic = dynamic or is_dynamic

        return text, dynamic

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, left_dynamic = part(node.left)
        right, right_dynamic = part(node.right)

        return left + right, left_dynamic or right_dynamic

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left, left_dynamic = part(node.left)
        operands = (
            node.right.elts
            if isinstance(node.right, ast.Tuple)
            else [node.right]
        )
        operands_dynamic = any(part(operand)[1] for operand in operands)
        text = PRINTF_SPECIFIER.sub(
            DYNAMIC_PLACEHOLDER if operands_dynamic else "x",
            left,
        )

        return text, left_dynamic or operands_dynamic

    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            left, left_dynamic = part(node.func.value)
            arguments = [*node.args, *(kw.value for kw in node.keywords)]
            arguments_dynamic = any(part(arg)[1] for arg in arguments)
            text = FORMAT_FIELD.sub(
                DYNAMIC_PLACEHOLDER if arguments_dynamic else "x",
                left,
            )

            return text, left_dynamic or arguments_dynamic

        if (
            isinstance(node.func, ast.Name)
            and node.func.id in SAFE_CAST_CALLS
        ):
            return "0", False

    return DYNAMIC_PLACEHOLDER, True


def _sql_query_text(
    node: ast.AST,
    constants: dict[str, ast.AST],
) -> tuple[str, bool] | None:
    """Render a query argument, or None when it is not statically known."""

    if isinstance(node, ast.Name) and node.id not in constants:
        return None

    text, dynamic = _sql_part(node, constants)

    if not SQL_STATEMENT.match(text):
        return None

    return text, dynamic


def _sql_has_value_interpolation(text: str) -> bool:
    """Check whether a non-constant value sits in a value position."""

    clause = SQL_VALUE_CLAUSE.search(text)

    if clause and DYNAMIC_PLACEHOLDER in text[clause.end():]:
        return True

    return (
        re.search(
            rf"'[^']*{re.escape(DYNAMIC_PLACEHOLDER)}[^']*'",
            text,
        )
        is not None
    )


def _sql_findings(
    node: ast.Call,
    constants: dict[str, ast.AST],
) -> list[dict[str, str]]:
    """Check a database call for destructive or injectable SQL."""

    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in SQL_EXECUTE_METHODS
        and node.args
    ):
        return []

    rendered = _sql_query_text(node.args[0], constants)

    if rendered is None:
        return []

    text, dynamic = rendered
    verb = SQL_STATEMENT.match(text).group(1).upper()

    if dynamic:
        if not _sql_has_value_interpolation(text):
            return []

        if verb in {"DELETE", "UPDATE"}:
            return [
                {
                    "category": "destructive_command",
                    "reason": (
                        f"A {verb} statement is built by inserting "
                        "non-constant values into the SQL text, so its scope "
                        "can be altered by the input. Use query parameters."
                    ),
                    "evidence": f"{verb} statement built from dynamic text",
                }
            ]

        if verb == "SELECT":
            return [
                {
                    "category": "data_exfiltration",
                    "reason": (
                        "A SELECT statement is built by inserting "
                        "non-constant values into the SQL text, which can "
                        "expose unintended data. Use query parameters."
                    ),
                    "evidence": "SELECT statement built from dynamic text",
                }
            ]

        return []

    return [
        {
            "category": finding["category"],
            "reason": finding["reason"],
            "evidence": finding["evidence"],
        }
        for finding in sql_analyzer.analyze(text)
        if finding["category"] == "destructive_command"
    ]


def _is_untrusted_deserialization_source(
    argument: ast.AST,
    constants: dict[str, ast.AST],
    aliases: dict[str, str],
) -> bool:
    """Check whether deserialized data comes from an untrusted source."""

    expressions = [argument]

    if isinstance(argument, ast.Name) and argument.id in constants:
        expressions.append(constants[argument.id])

    for expression in expressions:
        path = _render_path(expression, constants, aliases)

        if path is not None and UNTRUSTED_PATH_PATTERN.search(
            _normalize_path(path)
        ):
            return True

        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                name = _resolve_name(node.func, aliases)

                if (
                    name in UNTRUSTED_DATA_CALLS
                    or name.startswith(UNTRUSTED_DATA_CALL_PREFIXES)
                ):
                    return True

                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in UNTRUSTED_DATA_METHODS
                ):
                    return True

                if name in OPEN_CALLS and node.args:
                    opened = _render_path(node.args[0], constants, aliases)

                    if opened is not None and UNTRUSTED_PATH_PATTERN.search(
                        _normalize_path(opened)
                    ):
                        return True

            elif (
                isinstance(node, ast.Attribute)
                and node.attr in REQUEST_DATA_ATTRIBUTES
                and isinstance(node.value, ast.Name)
                and node.value.id == "request"
            ):
                return True

    return False


def _integer_value(
    node: ast.AST,
    constants: dict[str, ast.AST],
    depth: int = 0,
) -> int | None:
    """Resolve a simple integer expression without evaluating code."""

    if depth > 5:
        return None

    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value

        return None

    if isinstance(node, ast.Name):
        assigned = constants.get(node.id)

        if assigned is None:
            return None

        return _integer_value(assigned, constants, depth + 1)

    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow)
    ):
        left = _integer_value(node.left, constants, depth + 1)
        right = _integer_value(node.right, constants, depth + 1)

        if left is None or right is None:
            return None

        if isinstance(node.op, ast.Add):
            return left + right

        if isinstance(node.op, ast.Sub):
            return left - right

        if isinstance(node.op, ast.Mult):
            return left * right

        if 0 <= right <= 64 and abs(left) <= 1_000_000:
            return left**right

    return None


def _range_length(
    node: ast.AST,
    constants: dict[str, ast.AST],
) -> int | None:
    """Return the length of a range(...) call with known integer bounds."""

    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "range"
        and 1 <= len(node.args) <= 3
        and not node.keywords
    ):
        return None

    values = [_integer_value(arg, constants) for arg in node.args]

    if any(value is None for value in values):
        return None

    if len(values) == 1:
        start, stop, step = 0, values[0], 1
    elif len(values) == 2:
        start, stop, step = values[0], values[1], 1
    else:
        start, stop, step = values

    if step == 0:
        return None

    if step > 0:
        return max(0, (stop - start + step - 1) // step)

    return max(0, (start - stop - step - 1) // -step)


def _large_allocation(
    node: ast.AST,
    constants: dict[str, ast.AST],
) -> bool:
    """Detect a single expression that allocates an enormous object."""

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        for sequence, count in (
            (node.left, node.right),
            (node.right, node.left),
        ):
            is_sequence = (
                isinstance(sequence, ast.Constant)
                and isinstance(sequence.value, (str, bytes))
            ) or isinstance(sequence, ast.List)

            amount = _integer_value(count, constants)

            if (
                is_sequence
                and amount is not None
                and amount > LARGE_ALLOCATION_THRESHOLD
            ):
                return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"bytearray", "bytes"}
        and len(node.args) == 1
    ):
        amount = _integer_value(node.args[0], constants)

        return amount is not None and amount > LARGE_ALLOCATION_THRESHOLD

    return False


def analyze(code: str) -> list[dict[str, Any]]:
    """Analyze Python source without executing it."""

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    aliases = _collect_import_aliases(tree)
    constants = _collect_constants(tree)

    # Initialize these ONCE, before any analyzer rules run.
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    # Detect instruction-override text in strings presented to an AI agent.
    # Comments and single-line text are handled by the shared rule.
    seen_instruction_lines: set[tuple[int, ...]] = set()

    for string_node in _ai_context_strings(tree):
        for start, end in prompt_injection.find_spans(string_node.value):
            lines = tuple(_string_match_lines(string_node, start, end))

            if lines in seen_instruction_lines:
                continue

            seen_instruction_lines.add(lines)
            findings.append(prompt_injection.build_finding(list(lines)))

    def add_finding(
        category: str,
        severity: str,
        reason: str,
        line: int,
        evidence: str,
    ) -> None:
        """Append a finding once per category and source line."""

        key = (category, line)

        if key in seen:
            return

        seen.add(key)
        findings.append(
            {
                "category": category,
                "severity": severity,
                "reason": reason,
                "lines": [line],
                "evidence": evidence,
            }
        )

    # Detect hardcoded values assigned to variables with sensitive names.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue

        value_node = node.value

        if not isinstance(value_node, ast.Constant):
            continue

        value = value_node.value

        if not isinstance(value, str) or len(value.strip()) < 8:
            continue

        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
        )

        for target in targets:
            if not isinstance(target, ast.Name):
                continue

            if not SECRET_NAME_PATTERN.search(target.id):
                continue

            normalized_value = value.strip().lower()

            if (
                normalized_value in SECRET_PLACEHOLDERS
                or normalized_value.startswith(
                    ("your_", "<", "${", "placeholder")
                )
            ):
                continue

            line = node.lineno
            key = ("secret_access", line)

            if key in seen:
                continue

            seen.add(key)

            findings.append(
                {
                    "category": "secret_access",
                    "severity": "high",
                    "reason": (
                        "A variable with a sensitive name is assigned a "
                        "hardcoded string value."
                    ),
                    "lines": [line],
                    "evidence": "Hardcoded-secret assignment pattern",
                }
            )

    # Detect potentially unbounded loops.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.While)
            and _is_unbounded_loop_test(node.test)
        ):
            key = ("resource_exhaustion", node.lineno)

            if key not in seen:
                seen.add(key)

                findings.append(
                    {
                        "category": "resource_exhaustion",
                        "severity": "high",
                        "reason": (
                            "The code contains a while True loop that may "
                            "continue indefinitely without an exit condition."
                        ),
                        "lines": [node.lineno],
                        "evidence": "while True",
                    }
                )

    # Detect potentially excessive literal exponentiation.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.BinOp)
            and _is_suspicious_exponent(node)
        ):
            key = ("resource_exhaustion", node.lineno)

            if key not in seen:
                seen.add(key)

                findings.append(
                    {
                        "category": "resource_exhaustion",
                        "severity": "high",
                        "reason": (
                            "The code uses an unusually large literal exponent, "
                            "which may cause excessive CPU or memory consumption."
                        ),
                        "lines": [node.lineno],
                        "evidence": (
                            "Exponentiation with a large literal exponent"
                        ),
                    }
                )

    # Inspect function calls without executing the submitted code.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_name(node.func, aliases)
        line = node.lineno

        # Detect recognizable dynamic package installation.
        if call_name in SUBPROCESS_CALLS and node.args:
            parts = _command_parts(node.args[0], aliases)

            if parts and _is_package_install_command(parts):
                key = ("dependency_risk", line)

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        {
                            "category": "dependency_risk",
                            "severity": "high",
                            "reason": (
                                "The code invokes a package installation or "
                                "download command through a subprocess."
                            ),
                            "lines": [line],
                            "evidence": (
                                "Subprocess package-management command"
                            ),
                        }
                    )

        # Detect risky shell and process execution from the call structure.
        if call_name in SHELL_STRING_CALLS or call_name in SUBPROCESS_CALLS:
            command_node = _command_expression(node)
            uses_shell = (
                call_name in SHELL_STRING_CALLS or _has_shell_true(node)
            )

            if command_node is not None:
                if isinstance(command_node, (ast.List, ast.Tuple)):
                    elements = [
                        _render_command(element, constants)
                        for element in command_node.elts
                    ]
                    command_text = " ".join(
                        DYNAMIC_PLACEHOLDER if element is None else element
                        for element in elements
                    )
                    executable_is_dynamic = _is_fully_dynamic(
                        elements[0] if elements else None
                    )
                else:
                    rendered = _render_command(command_node, constants)
                    command_text = rendered or ""
                    executable_is_dynamic = _is_fully_dynamic(rendered)

                if uses_shell and executable_is_dynamic:
                    key = ("obfuscated_execution", line)

                    if key not in seen:
                        seen.add(key)

                        findings.append(
                            {
                                "category": "obfuscated_execution",
                                "severity": "high",
                                "reason": (
                                    f"The code passes a dynamically supplied "
                                    f"command to {call_name} for shell "
                                    "execution."
                                ),
                                "lines": [line],
                                "evidence": "Dynamic shell command",
                            }
                        )

                elif command_text and (
                    uses_shell
                    or isinstance(command_node, (ast.List, ast.Tuple))
                ):
                    for command_finding in _classify_command(command_text):
                        key = (command_finding["category"], line)

                        if key in seen:
                            continue

                        seen.add(key)

                        findings.append(
                            {
                                "category": command_finding["category"],
                                "severity": command_finding["severity"],
                                "reason": (
                                    f"The code runs a risky command through "
                                    f"{call_name}. {command_finding['reason']}"
                                ),
                                "lines": [line],
                                "evidence": command_finding["evidence"],
                            }
                        )

        # Detect destructive or injectable SQL passed to a database call.
        for sql_finding in _sql_findings(node, constants):
            add_finding(
                sql_finding["category"],
                "high",
                sql_finding["reason"],
                line,
                sql_finding["evidence"],
            )

        # Detect access to credential files and writes to persistence or
        # privilege-granting locations.
        access = _file_access(node, aliases, constants)

        if access is not None:
            accessed_path, is_write = access

            if CREDENTIAL_FILE_PATTERN.search(accessed_path):
                add_finding(
                    "secret_access",
                    "high",
                    "The code opens a well-known credential file.",
                    line,
                    "Credential-file access",
                )

            if is_write and PERSISTENCE_WRITE_PATTERN.search(accessed_path):
                add_finding(
                    "persistence_or_privesc",
                    "high",
                    (
                        "The code writes to a file that grants persistence "
                        "or elevated privileges."
                    ),
                    line,
                    "Write to a startup or privilege configuration file",
                )

        # Detect deserialization of data from an untrusted source.
        if (
            call_name in DESERIALIZATION_CALLS
            and node.args
            and _is_untrusted_deserialization_source(
                node.args[0],
                constants,
                aliases,
            )
        ):
            add_finding(
                "obfuscated_execution",
                "high",
                (
                    f"The code deserializes data with {call_name} from a "
                    "source that is not trusted, which can run arbitrary "
                    "code when loaded."
                ),
                line,
                "Untrusted deserialization",
            )

        # Detect dynamically named imports.
        if (
            call_name in {"__import__", "builtins.__import__"}
            and node.args
            and _string_value(node.args[0]) is None
        ):
            add_finding(
                "obfuscated_execution",
                "high",
                (
                    "The code imports a module through __import__ using a "
                    "name that is computed at runtime."
                ),
                line,
                "Dynamic __import__",
            )

        # Detect destructive file and directory operations.
        if call_name in DANGEROUS_CALLS:
            key = ("destructive_command", line)

            if key not in seen:
                seen.add(key)

                findings.append(
                    {
                        "category": "destructive_command",
                        "severity": "high",
                        "reason": (
                            f"The code calls {call_name}, which can "
                            f"{DANGEROUS_CALLS[call_name].lower()}"
                        ),
                        "lines": [line],
                        "evidence": call_name,
                    }
                )

        # Detect dynamic execution.
        if call_name in DYNAMIC_EXECUTION_CALLS:
            key = ("obfuscated_execution", line)

            if key not in seen:
                seen.add(key)

                findings.append(
                    {
                        "category": "obfuscated_execution",
                        "severity": "high",
                        "reason": (
                            f"The code uses {call_name}() to evaluate "
                            "a dynamically supplied expression."
                        ),
                        "lines": [line],
                        "evidence": f"{call_name}()",
                    }
                )

        # Detect privilege-changing operations.
        if call_name in PRIVILEGE_CALLS:
            key = ("persistence_or_privesc", line)

            if key not in seen:
                seen.add(key)

                findings.append(
                    {
                        "category": "persistence_or_privesc",
                        "severity": "high",
                        "reason": (
                            f"The code calls {call_name}, which changes "
                            "process identity or group privileges."
                        ),
                        "lines": [line],
                        "evidence": call_name,
                    }
                )

    # Detect very large loops that allocate operating-system resources they
    # never release, and single expressions that allocate enormous objects.
    managed_calls = {
        id(item.context_expr)
        for node in ast.walk(tree)
        if isinstance(node, (ast.With, ast.AsyncWith))
        for item in node.items
    }

    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iterations = _range_length(node.iter, constants)
            body_nodes = node.body
        elif isinstance(
            node,
            (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp),
        ):
            iterations = (
                _range_length(node.generators[0].iter, constants)
                if node.generators
                else None
            )
            body_nodes = (
                [node.key, node.value]
                if isinstance(node, ast.DictComp)
                else [node.elt]
            )
        else:
            iterations = None
            body_nodes = []

        if iterations is not None and iterations > LARGE_LOOP_THRESHOLD:
            allocates = any(
                isinstance(child, ast.Call)
                and id(child) not in managed_calls
                and _resolve_name(child.func, aliases)
                in RESOURCE_ALLOCATING_CALLS
                for body in body_nodes
                for child in ast.walk(body)
            )

            if allocates:
                add_finding(
                    "resource_exhaustion",
                    "high",
                    (
                        "A very large loop creates sockets, threads, or "
                        "processes without releasing them, which can "
                        "exhaust system resources."
                    ),
                    node.lineno,
                    "Large loop allocating system resources",
                )

        if _large_allocation(node, constants):
            add_finding(
                "resource_exhaustion",
                "high",
                (
                    "The code allocates an enormous object, which may "
                    "cause excessive memory consumption."
                ),
                node.lineno,
                "Very large literal allocation",
            )

    # Inspect literal paths used in file-opening calls.
    # This is a narrow first-pass check, not full persistence analysis.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _resolve_name(node.func, aliases)

        if call_name not in {"open", "builtins.open"} or not node.args:
            continue

        path = _string_value(node.args[0])

        if path is None:
            continue

        normalized_path = path.replace("\\", "/")

        if not any(
            marker in normalized_path
            for marker in STARTUP_PATH_MARKERS
        ):
            continue

        key = ("persistence_or_privesc", node.lineno)

        if key not in seen:
            seen.add(key)

            findings.append(
                {
                    "category": "persistence_or_privesc",
                    "severity": "medium",
                    "reason": (
                        "The code opens a file under a recognized "
                        "startup-related configuration path."
                    ),
                    "lines": [node.lineno],
                    "evidence": "Startup-related path",
                }
            )

    return findings