"""Regression tests for credential files, SQL, deserialization, persistence
paths, and resource exhaustion. Each malicious case has a benign counterpart.
"""

from src.analyzers.sql_analyzer import analyze as analyze_sql
from src.detector import evaluate_code


def _python(code):
    return evaluate_code(code, language="python")


def _assert_blocked(result, category, line=None):
    assert result["verdict"] == "block", result
    assert category in result["categories"], result

    if line is not None:
        assert line in result["vulnerable_lines"], result


def _assert_allowed(result):
    assert result["verdict"] == "allow", result
    assert result["categories"] == [], result


# ---------------------------------------------------------------------------
# secret_access: credential files reached through variables and path helpers
# ---------------------------------------------------------------------------


def test_credential_file_path_held_in_variable_is_blocked():
    code = (
        "import os\n"
        "\n"
        "def load():\n"
        "    path = os.path.expanduser('~/.aws/credentials')\n"
        "    with open(path) as handle:\n"
        "        return handle.read()\n"
    )

    _assert_blocked(_python(code), "secret_access", 5)


def test_credential_file_path_held_in_module_constant_is_blocked():
    code = (
        "import json\n"
        "import os\n"
        "\n"
        "CONFIG_PATH = os.path.expanduser('~/.docker/config.json')\n"
        "\n"
        "def load():\n"
        "    with open(CONFIG_PATH) as handle:\n"
        "        return json.load(handle)\n"
    )

    _assert_blocked(_python(code), "secret_access", 7)


def test_credential_file_built_with_path_helpers_is_blocked():
    joined = (
        "import os\n"
        "path = os.path.join(os.path.expanduser('~'), '.ssh', 'id_rsa')\n"
        "data = open(path).read()\n"
    )
    pathlib_code = (
        "from pathlib import Path\n"
        "token = (Path.home() / '.netrc').read_text()\n"
    )

    _assert_blocked(_python(joined), "secret_access", 3)
    _assert_blocked(_python(pathlib_code), "secret_access", 2)


def test_ordinary_user_files_are_not_credential_access():
    code = (
        "import json\n"
        "import os\n"
        "\n"
        "SETTINGS = os.path.expanduser('~/.config/myapp/settings.json')\n"
        "PUBLIC_KEY = os.path.expanduser('~/.ssh/id_rsa.pub')\n"
        "\n"
        "def load():\n"
        "    with open(SETTINGS) as handle:\n"
        "        settings = json.load(handle)\n"
        "    with open(PUBLIC_KEY) as handle:\n"
        "        key = handle.read()\n"
        "    with open('/etc/hosts') as handle:\n"
        "        hosts = handle.read()\n"
        "    return settings, key, hosts\n"
    )

    _assert_allowed(_python(code))


def test_credential_path_text_that_is_never_opened_is_allowed():
    code = (
        "import os\n"
        "\n"
        "HELP = 'Credentials live in ~/.aws/credentials'\n"
        "print(HELP)\n"
        "print(os.path.expanduser('~/.aws/credentials'))\n"
    )

    _assert_allowed(_python(code))


# ---------------------------------------------------------------------------
# destructive_command: SQL without a limiting WHERE clause
# ---------------------------------------------------------------------------


def test_sql_update_without_where_is_blocked():
    result = evaluate_code(
        "UPDATE accounts SET balance = 0;\n",
        language="sql",
    )

    _assert_blocked(result, "destructive_command", 1)


def test_sql_unscoped_update_inside_procedure_is_blocked_on_its_line():
    code = (
        "CREATE PROCEDURE reconcile()\n"
        "BEGIN\n"
        "    INSERT INTO log (started) VALUES (NOW());\n"
        "    UPDATE accounts SET balance = 0;\n"
        "    UPDATE log SET finished = NOW()\n"
        "        WHERE started IS NOT NULL;\n"
        "END;\n"
    )

    result = evaluate_code(code, language="sql")

    _assert_blocked(result, "destructive_command", 4)
    assert 5 not in result["vulnerable_lines"]


def test_sql_delete_without_where_and_tautology_are_blocked():
    for statement in (
        "DELETE FROM sessions;",
        "DELETE FROM sessions WHERE 1 = 1;",
        "UPDATE users SET active = 0 WHERE true;",
    ):
        result = evaluate_code(statement + "\n", language="sql")

        _assert_blocked(result, "destructive_command", 1)


def test_sql_scoped_statements_are_allowed():
    code = (
        "DELETE FROM sessions WHERE expires_at < NOW();\n"
        "UPDATE accounts SET balance = 0 WHERE id = 7;\n"
        "UPDATE accounts\n"
        "    SET balance = 0\n"
        "    WHERE id = 7;\n"
        "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = 2;\n"
        "SELECT id FROM t WHERE name = 'DELETE FROM x';\n"
    )

    result = evaluate_code(code, language="sql")

    _assert_allowed(result)


def test_sql_unscoped_statement_in_comment_or_string_is_ignored():
    code = (
        "-- DELETE FROM sessions;\n"
        "/* UPDATE accounts SET balance = 0; */\n"
        "SELECT 'UPDATE accounts SET balance = 0;' AS note;\n"
    )

    assert analyze_sql(code) == []


def test_sql_unscoped_finding_follows_shared_schema():
    findings = analyze_sql("DELETE FROM sessions;\n")

    assert len(findings) == 1
    assert set(findings[0]) == {
        "category",
        "severity",
        "reason",
        "lines",
        "evidence",
    }
    assert findings[0]["lines"] == [1]


# ---------------------------------------------------------------------------
# destructive_command / data_exfiltration: SQL built from dynamic values
# ---------------------------------------------------------------------------


def test_delete_built_with_format_is_blocked():
    code = (
        "def remove(cur, order_id):\n"
        "    query = 'DELETE FROM orders WHERE id = {}'.format(order_id)\n"
        "    cur.execute(query)\n"
    )

    _assert_blocked(_python(code), "destructive_command", 3)


def test_delete_built_with_fstring_and_concatenation_is_blocked():
    for query in (
        "f\"DELETE FROM orders WHERE id = '{order_id}'\"",
        "'DELETE FROM orders WHERE id = ' + order_id",
        "'UPDATE orders SET status = 1 WHERE id = %s' % order_id",
    ):
        code = f"def remove(cur, order_id):\n    cur.execute({query})\n"

        _assert_blocked(_python(code), "destructive_command", 2)


def test_select_built_with_percent_formatting_is_flagged_as_exfiltration():
    code = (
        "def find(cur, name):\n"
        "    username = name\n"
        "    query = \"SELECT * FROM users WHERE name = '%s'\" % username\n"
        "    cur.execute(query)\n"
    )

    _assert_blocked(_python(code), "data_exfiltration", 4)


def test_parameterized_queries_are_allowed():
    code = (
        "def run(cur, order_id, name):\n"
        "    cur.execute('DELETE FROM orders WHERE id = ?', (order_id,))\n"
        "    cur.execute('DELETE FROM orders WHERE id = %s', (order_id,))\n"
        "    cur.execute('SELECT * FROM users WHERE name = %s', (name,))\n"
        "    cur.execute(\"UPDATE orders SET status = 1 WHERE id = :id\", "
        "{'id': order_id})\n"
    )

    _assert_allowed(_python(code))


def test_query_built_only_from_constants_or_numeric_casts_is_allowed():
    code = (
        "TABLE = 'orders'\n"
        "COLUMN = 'id'\n"
        "TEMPLATE = f'SELECT {COLUMN} FROM {TABLE} WHERE status = %s'\n"
        "\n"
        "def run(cur, status, order_id):\n"
        "    cur.execute(TEMPLATE, (status,))\n"
        "    cur.execute(f'DELETE FROM orders WHERE id = {int(order_id)}')\n"
    )

    _assert_allowed(_python(code))


def test_query_with_unknown_origin_is_not_flagged():
    code = (
        "def run(cur, query):\n"
        "    cur.execute(query)\n"
        "    cur.execute(build_query())\n"
    )

    _assert_allowed(_python(code))


def test_literal_destructive_sql_in_execute_is_blocked():
    for statement in ("DELETE FROM orders", "DROP TABLE orders"):
        code = f"def run(cur):\n    cur.execute('{statement}')\n"

        _assert_blocked(_python(code), "destructive_command", 2)


def test_non_database_execute_call_is_allowed():
    code = (
        "def run(plan, name):\n"
        "    plan.execute('start ' + name)\n"
    )

    _assert_allowed(_python(code))


# ---------------------------------------------------------------------------
# obfuscated_execution: dynamic imports and untrusted deserialization
# ---------------------------------------------------------------------------


def test_dynamic_dunder_import_is_blocked():
    code = (
        "def load(name):\n"
        "    return __import__(name)\n"
        "\n"
        "module = __import__('sub' + 'process')\n"
    )

    result = _python(code)

    _assert_blocked(result, "obfuscated_execution", 2)
    assert 4 in result["vulnerable_lines"]


def test_literal_dunder_import_and_importlib_are_allowed():
    code = (
        "import importlib\n"
        "\n"
        "def load(name):\n"
        "    plugin = importlib.import_module(name)\n"
        "    return plugin, __import__('os')\n"
    )

    _assert_allowed(_python(code))


def test_shelve_open_in_world_writable_directory_is_blocked():
    code = (
        "import shelve\n"
        "\n"
        "def load(key):\n"
        "    db = shelve.open('/tmp/untrusted.db')\n"
        "    return db.get(key)\n"
    )

    _assert_blocked(_python(code), "obfuscated_execution", 4)


def test_pickle_of_downloaded_or_decoded_data_is_blocked():
    cases = {
        "pickle.loads(base64.b64decode(blob))": "import base64\nimport pickle\n",
        "pickle.loads(requests.get(url).content)": (
            "import pickle\nimport requests\n"
        ),
        "pickle.load(open('/tmp/session.pkl', 'rb'))": "import pickle\n",
        "pickle.loads(request.data)": "import pickle\n",
    }

    for call, imports in cases.items():
        code = f"{imports}\ndef load(blob, url, request):\n    return {call}\n"
        call_line = code.count("\n")

        result = _python(code)

        _assert_blocked(result, "obfuscated_execution", call_line)


def test_deserialization_of_local_application_data_is_allowed():
    code = (
        "import pickle\n"
        "import shelve\n"
        "\n"
        "def load(path, key):\n"
        "    with open('model.pkl', 'rb') as handle:\n"
        "        model = pickle.load(handle)\n"
        "    cache = shelve.open('cache.db')\n"
        "    other = shelve.open(path)\n"
        "    return model, cache.get(key), other.get(key)\n"
    )

    _assert_allowed(_python(code))


# ---------------------------------------------------------------------------
# persistence_or_privesc: writes to startup and privilege files
# ---------------------------------------------------------------------------


def test_write_to_systemd_unit_and_sudoers_is_blocked():
    unit = (
        "def install():\n"
        "    open('/etc/systemd/system/update.service', 'w').write('[Unit]')\n"
    )
    sudoers = (
        "def grant():\n"
        "    open('/etc/sudoers', 'a').write('www-data ALL=(ALL) NOPASSWD:ALL')\n"
    )

    _assert_blocked(_python(unit), "persistence_or_privesc", 2)
    _assert_blocked(_python(sudoers), "persistence_or_privesc", 2)


def test_write_to_other_persistence_locations_is_blocked():
    cases = (
        "open('/etc/cron.d/job', 'w').write('* * * * * root run')",
        "Path('/etc/profile.d/x.sh').write_text('run')",
        "open(os.path.expanduser('~/.bashrc'), 'a').write('run')",
        "open(os.path.expanduser('~/.ssh/authorized_keys'), 'a').write('k')",
        "with open('/etc/sudoers.d/extra', mode='w') as f:\n    f.write('x')",
    )

    for statement in cases:
        code = (
            "import os\nfrom pathlib import Path\n\n"
            f"{statement}\n"
        )

        _assert_blocked(_python(code), "persistence_or_privesc", 4)


def test_write_path_held_in_constant_is_blocked():
    code = (
        "UNIT_DIR = '/etc/systemd/system'\n"
        "UNIT = UNIT_DIR + '/update.service'\n"
        "\n"
        "def install():\n"
        "    with open(UNIT, 'w') as handle:\n"
        "        handle.write('[Unit]')\n"
    )

    _assert_blocked(_python(code), "persistence_or_privesc", 5)


def test_reading_or_backing_up_privilege_files_is_allowed():
    code = (
        "import os\n"
        "\n"
        "def inspect():\n"
        "    with open('/etc/sudoers') as src, open('/etc/sudoers.bak', 'w') as dst:\n"
        "        dst.write(src.read())\n"
        "    open('/etc/systemd/system/app.service').read()\n"
        "    open(os.path.expanduser('~/.bashrc')).read()\n"
    )

    _assert_allowed(_python(code))


def test_ordinary_file_writes_are_not_persistence():
    code = (
        "import os\n"
        "\n"
        "open('notes.txt', 'w').write('hello')\n"
        "open(os.path.expanduser('~/.config/myapp/settings.json'), 'w')"
        ".write('{}')\n"
        "open('/tmp/output.log', 'a').write('done')\n"
    )

    _assert_allowed(_python(code))


# ---------------------------------------------------------------------------
# resource_exhaustion: unbounded disk writes and runaway resource creation
# ---------------------------------------------------------------------------


def test_bash_unbounded_dd_and_endless_redirects_are_blocked():
    for command in (
        "dd if=/dev/zero of=/tmp/fill bs=1M",
        "dd if=/dev/urandom of=big.bin",
        "cat /dev/zero > big.img",
        "yes > filler.txt",
    ):
        result = evaluate_code(command + "\n", language="bash")

        _assert_blocked(result, "resource_exhaustion", 1)


def test_bash_bounded_or_harmless_writes_are_allowed():
    for command in (
        "dd if=/dev/zero of=test.img bs=1M count=10",
        "dd if=/dev/urandom bs=16 count=1",
        "dd if=disk.img of=backup.img bs=4M",
        "yes > /dev/null",
        "yes | head -n 3",
        "cat /dev/zero | head -c 1024 > small.bin",
    ):
        result = evaluate_code(command + "\n", language="bash")

        _assert_allowed(result)


def test_python_shell_dd_without_limit_is_blocked():
    code = "import os\nos.system('dd if=/dev/zero of=/tmp/fill bs=1M')\n"

    _assert_blocked(_python(code), "resource_exhaustion", 2)


def test_large_loop_that_leaks_sockets_or_threads_is_blocked():
    sockets = (
        "import socket\n"
        "\n"
        "def flood():\n"
        "    [socket.socket().connect(('localhost', 80)) for _ in range(50000)]\n"
    )
    threads = (
        "import threading\n"
        "\n"
        "COUNT = 100000\n"
        "\n"
        "def spawn(items):\n"
        "    for _ in range(COUNT):\n"
        "        items.append(threading.Thread(target=print))\n"
    )

    _assert_blocked(_python(sockets), "resource_exhaustion", 4)
    _assert_blocked(_python(threads), "resource_exhaustion", 6)


def test_enormous_literal_allocation_is_blocked():
    for expression in ("bytearray(10 ** 10)", "'a' * 10 ** 9", "[0] * 5000000000"):
        result = _python(f"data = {expression}\n")

        _assert_blocked(result, "resource_exhaustion", 1)


def test_bounded_loops_and_allocations_are_allowed():
    code = (
        "import socket\n"
        "import threading\n"
        "\n"
        "MAX_WORKERS = 8\n"
        "\n"
        "def run(host):\n"
        "    sockets = [socket.socket() for _ in range(10)]\n"
        "    threads = [threading.Thread(target=print) "
        "for _ in range(MAX_WORKERS)]\n"
        "    total = 0\n"
        "    for number in range(1000000):\n"
        "        total += number\n"
        "    for _ in range(50000):\n"
        "        with socket.socket() as conn:\n"
        "            conn.connect((host, 80))\n"
        "    buffer = bytearray(1024)\n"
        "    padding = [0] * 1000\n"
        "    return sockets, threads, total, buffer, padding\n"
    )

    _assert_allowed(_python(code))


def test_new_python_findings_follow_shared_schema():
    from src.analyzers.python_analyzer import analyze

    code = (
        "import os\n"
        "path = os.path.expanduser('~/.aws/credentials')\n"
        "data = open(path).read()\n"
        "open('/etc/sudoers', 'a').write('x')\n"
        "blob = bytearray(10 ** 10)\n"
    )

    findings = analyze(code)

    assert {finding["category"] for finding in findings} >= {
        "secret_access",
        "persistence_or_privesc",
        "resource_exhaustion",
    }

    for finding in findings:
        assert set(finding) == {
            "category",
            "severity",
            "reason",
            "lines",
            "evidence",
        }
        assert finding["severity"] in {"low", "medium", "high", "critical"}
        assert all(isinstance(line, int) and line > 0 for line in finding["lines"])
