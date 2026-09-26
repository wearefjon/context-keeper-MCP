"""
tests/test_server.py — Unit tests for ContextKeeper 2.0

Covers:
  - Tool registration (all 7 tools are importable and callable)
  - checkpoint_task: persistence and AGENTS.md sync
  - get_scoped_context: budget-guard filtering
  - audit_dependencies_and_runtime: manifest parsing
  - audit_diff_compliance: diff parsing and security heuristics
  - export_sarif_report: SARIF v2.1.0 schema output
  - generate_mermaid_flow: diagram syntax correctness
  - draft_pull_request: PR template structure
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures: redirect all storage to a temp directory so tests are isolated
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """
    Redirect CONTEXT_KEEPER_DIR to a fresh temp directory for each test.
    Also pre-populate constraints.json and deprecated_rules.json so module
    helpers don't return empty data.
    """
    context_dir = tmp_path / ".context"
    context_dir.mkdir()

    monkeypatch.setenv("CONTEXT_KEEPER_DIR", str(context_dir))
    monkeypatch.chdir(tmp_path)

    # Minimal constraints fixture
    (context_dir / "constraints.json").write_text(json.dumps({
        "constraints": [
            "All async functions must wrap await calls in try/except blocks",
            "No hardcoded credentials — use environment variables",
            "All SQL queries must use parameterised statements",
        ],
        "banned_patterns": [
            r"eval\(",
            r"password\s*=\s*['\"][^'\"]{4,}['\"]",
        ],
    }), encoding="utf-8")

    # Minimal deprecated_rules fixture
    (context_dir / "deprecated_rules.json").write_text(json.dumps({
        "deprecated_packages": {
            "request": {
                "severity": "high",
                "reason": "Deprecated npm package",
                "replacement": "axios or fetch",
                "notes": "",
            },
            "moment": {
                "severity": "medium",
                "reason": "Maintenance mode",
                "replacement": "date-fns",
                "notes": "",
            },
        },
        "cve_packages": {
            "minimist": {
                "cve_id": "CVE-2021-44906",
                "reason": "Prototype pollution",
                "fix_version": ">=1.2.6",
                "severity": "high",
            },
        },
    }), encoding="utf-8")

    yield tmp_path


# ---------------------------------------------------------------------------
# Helper: re-import modules after env vars are set (they read at call time,
# so a direct import is sufficient — just ensure env is patched first).
# ---------------------------------------------------------------------------

def _import_server():
    from context_keeper_mcp import server
    return server


def _import_memory():
    from context_keeper_mcp.core import memory
    return memory


def _import_critic():
    from context_keeper_mcp.core import critic_gate
    return critic_gate


def _import_modernizer():
    from context_keeper_mcp.core import modernizer
    return modernizer


def _import_artifact():
    from context_keeper_mcp.core import artifact_engine
    return artifact_engine


# ===========================================================================
# 1. Tool registration — all 7 tools must be present on the FastMCP instance
# ===========================================================================

def test_all_seven_tools_registered():
    server = _import_server()
    # FastMCP exposes registered tools via ._tool_manager._tools dict
    tool_manager = server.mcp._tool_manager
    registered = set(tool_manager._tools.keys())
    expected = {
        "checkpoint_task",
        "get_scoped_context",
        "audit_dependencies_and_runtime",
        "audit_diff_compliance",
        "export_sarif_report",
        "generate_mermaid_flow",
        "draft_pull_request",
    }
    assert expected.issubset(registered), (
        f"Missing tools: {expected - registered}"
    )


# ===========================================================================
# 2. checkpoint_task
# ===========================================================================

def test_checkpoint_task_creates_session(isolated_storage):
    server = _import_server()
    result = server.checkpoint_task(
        task_id="T1",
        summary="Implement auth module",
        decisions=["Use JWT", "Tokens expire in 1h"],
        status="in_progress",
    )
    assert "T1" in result
    assert "AGENTS.md" in result

    # sessions.json is written to the CONTEXT_KEEPER_DIR env var path
    context_dir = Path(os.environ["CONTEXT_KEEPER_DIR"])
    sessions_file = context_dir / "sessions.json"
    assert sessions_file.exists()
    data = json.loads(sessions_file.read_text())
    tasks = data.get("tasks", [])
    assert len(tasks) == 1
    assert tasks[0]["task_id"] == "T1"
    assert tasks[0]["status"] == "in_progress"
    assert "Use JWT" in tasks[0]["decisions"]


def test_checkpoint_task_idempotent_update(isolated_storage):
    server = _import_server()
    server.checkpoint_task("T2", "Initial summary", [], "in_progress")
    server.checkpoint_task("T2", "Updated summary", ["New decision"], "done")

    context_dir = Path(os.environ["CONTEXT_KEEPER_DIR"])
    sessions_file = context_dir / "sessions.json"
    data = json.loads(sessions_file.read_text())
    tasks = data["tasks"]
    # Should still be just one entry for T2
    t2_entries = [t for t in tasks if t["task_id"] == "T2"]
    assert len(t2_entries) == 1
    assert t2_entries[0]["summary"] == "Updated summary"
    assert t2_entries[0]["status"] == "done"


def test_checkpoint_task_syncs_agents_md(isolated_storage):
    server = _import_server()
    server.checkpoint_task("T3", "Build CI pipeline", ["Use GitHub Actions"], "done")

    agents_md = isolated_storage / "AGENTS.md"
    assert agents_md.exists()
    content = agents_md.read_text()
    assert "T3" in content
    assert "Build CI pipeline" in content


def test_checkpoint_task_invalid_status():
    server = _import_server()
    result = server.checkpoint_task("T99", "Test", [], "invalid_status")
    assert "Error" in result


def test_checkpoint_task_empty_task_id():
    server = _import_server()
    result = server.checkpoint_task("  ", "Test", [], "done")
    assert "Error" in result


# ===========================================================================
# 3. get_scoped_context
# ===========================================================================

def test_scoped_context_returns_required_keys():
    server = _import_server()
    result = server.get_scoped_context("authentication")
    assert isinstance(result, dict)
    for key in ("focus_area", "constraints", "banned_patterns", "recent_decisions", "token_budget_note"):
        assert key in result, f"Missing key: {key}"


def test_scoped_context_caps_at_top_n():
    server = _import_server()
    result = server.get_scoped_context("auth", "src/auth.py")
    assert len(result["constraints"]) <= 7
    assert len(result["banned_patterns"]) <= 7
    assert len(result["recent_decisions"]) <= 7


def test_scoped_context_reflects_focus_area():
    server = _import_server()
    result = server.get_scoped_context("authentication", "src/auth.py")
    assert result["focus_area"] == "authentication"
    assert result["current_file"] == "src/auth.py"


# ===========================================================================
# 4. audit_dependencies_and_runtime
# ===========================================================================

def test_audit_package_json_detects_deprecated():
    server = _import_server()
    manifest = json.dumps({
        "dependencies": {
            "request": "^2.88.2",
            "axios": "^1.6.0",
            "moment": "^2.29.4",
        }
    })
    result = server.audit_dependencies_and_runtime(manifest, "package.json")
    assert result["status"] == "ok"
    deprecated_pkgs = {f["package"] for f in result["deprecated_findings"]}
    assert "request" in deprecated_pkgs
    assert "moment" in deprecated_pkgs
    # axios is not deprecated in our fixture
    assert "axios" not in deprecated_pkgs


def test_audit_package_json_detects_cve():
    server = _import_server()
    manifest = json.dumps({"dependencies": {"minimist": "^1.2.5"}})
    result = server.audit_dependencies_and_runtime(manifest, "package.json")
    assert result["status"] == "ok"
    cve_pkgs = {f["package"] for f in result["deprecated_findings"] if f.get("cve_id")}
    assert "minimist" in cve_pkgs


def test_audit_requirements_txt():
    server = _import_server()
    manifest = "request==2.27.0\nmoment==2.29.4\nflask>=2.0"
    result = server.audit_dependencies_and_runtime(manifest, "requirements.txt")
    assert result["status"] == "ok"
    assert result["packages_scanned"] >= 2


def test_audit_pyproject_toml():
    server = _import_server()
    manifest = '[project]\nrequires-python = ">=3.8"\ndependencies = [\n    "request>=2.0",\n]\n'
    result = server.audit_dependencies_and_runtime(manifest, "pyproject.toml")
    assert result["status"] == "ok"
    # Python 3.8 is below the 3.11 floor
    assert len(result["runtime_findings"]) >= 1


def test_audit_runtime_outdated_node():
    server = _import_server()
    manifest = json.dumps({"engines": {"node": ">=16"}})
    result = server.audit_dependencies_and_runtime(manifest, "package.json", target_runtime="")
    assert result["status"] == "ok"
    runtimes = {r["runtime"] for r in result["runtime_findings"]}
    assert "node" in runtimes


def test_audit_invalid_manifest_type():
    server = _import_server()
    result = server.audit_dependencies_and_runtime("{}", "Makefile")
    assert result["status"] == "error"


# ===========================================================================
# 5. audit_diff_compliance
# ===========================================================================

CLEAN_DIFF = """\
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
+def greet(name: str) -> str:
+    return f"Hello, {name}"
"""

DIRTY_DIFF_CREDENTIAL = """\
--- a/src/config.py
+++ b/src/config.py
@@ -1,2 +1,3 @@
+DB_HOST = "localhost"
+password = "supersecretpassword123"
"""

DIRTY_DIFF_SQL = """\
--- a/src/db.py
+++ b/src/db.py
@@ -1,3 +1,4 @@
+def fetch(conn, user_id):
+    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
"""

DIRTY_DIFF_EVAL = """\
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,2 +1,3 @@
+def run_code(code):
+    return eval(code)
"""


def test_clean_diff_passes():
    server = _import_server()
    result = server.audit_diff_compliance(CLEAN_DIFF, ["src/app.py"])
    assert result["verdict"] == "pass"
    assert len([f for f in result["findings"] if f["level"] == "error"]) == 0


def test_credential_diff_fails():
    server = _import_server()
    result = server.audit_diff_compliance(DIRTY_DIFF_CREDENTIAL, ["src/config.py"])
    assert result["verdict"] == "fail"
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "SEC001" in rule_ids


def test_sql_injection_diff_fails():
    server = _import_server()
    result = server.audit_diff_compliance(DIRTY_DIFF_SQL, ["src/db.py"])
    assert result["verdict"] == "fail"
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "SEC002" in rule_ids


def test_eval_diff_fails():
    server = _import_server()
    result = server.audit_diff_compliance(DIRTY_DIFF_EVAL, ["src/utils.py"])
    assert result["verdict"] == "fail"
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "SEC004" in rule_ids


def test_diff_compliance_returns_required_keys():
    server = _import_server()
    result = server.audit_diff_compliance(CLEAN_DIFF, ["src/app.py"])
    for key in ("verdict", "findings", "constraint_violations", "files_checked", "summary"):
        assert key in result


# ===========================================================================
# 6. export_sarif_report
# ===========================================================================

def test_sarif_output_valid_schema(isolated_storage):
    server = _import_server()
    findings = [
        {"rule_id": "SEC001", "level": "error", "message": "Hardcoded credential", "line": 5, "file": "src/config.py"},
        {"rule_id": "SEC004", "level": "error", "message": "eval() usage", "line": 12, "file": "src/utils.py"},
    ]
    output_path = str(isolated_storage / "reports" / "test_audit.sarif")
    result = server.export_sarif_report(findings, output_file=output_path)
    assert "SARIF report written" in result
    assert Path(output_path).exists()

    sarif = json.loads(Path(output_path).read_text())
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ContextKeeper2"
    assert len(run["results"]) == 2


def test_sarif_empty_findings(isolated_storage):
    server = _import_server()
    output_path = str(isolated_storage / "reports" / "empty.sarif")
    result = server.export_sarif_report([], output_file=output_path)
    assert "0 finding(s)" in result
    sarif = json.loads(Path(output_path).read_text())
    assert sarif["runs"][0]["results"] == []


# ===========================================================================
# 7. generate_mermaid_flow
# ===========================================================================

def test_mermaid_sequence_contains_participants():
    server = _import_server()
    result = server.generate_mermaid_flow(
        subsystem_name="AuthService",
        components_touched=["TokenStore", "UserDB"],
        flow_type="sequence",
    )
    assert "sequenceDiagram" in result
    assert "AuthService" in result
    assert "TokenStore" in result
    assert "UserDB" in result
    assert "Bob" in result


def test_mermaid_flowchart_structure():
    server = _import_server()
    result = server.generate_mermaid_flow(
        subsystem_name="Pipeline",
        components_touched=["Linter", "Tests", "Deploy"],
        flow_type="flowchart",
    )
    assert "flowchart LR" in result
    assert "Pipeline" in result
    assert "-->" in result


def test_mermaid_empty_components():
    server = _import_server()
    result = server.generate_mermaid_flow("MySystem", [], flow_type="sequence")
    assert "sequenceDiagram" in result
    assert "MySystem" in result


# ===========================================================================
# 8. draft_pull_request
# ===========================================================================

def test_draft_pr_structure(isolated_storage):
    server = _import_server()
    # Seed a task first
    server.checkpoint_task(
        "feat-auth",
        "Implement JWT authentication",
        ["Use HS256 algorithm", "Store refresh tokens in httpOnly cookies"],
        "done",
    )
    result = server.draft_pull_request("feat-auth", "feature/auth", True)
    assert isinstance(result, dict)
    for key in ("title", "branch", "body", "metadata"):
        assert key in result
    assert "feat-auth" in result["title"]
    assert "feature/auth" == result["branch"]
    assert "mermaid" in result["body"]
    assert result["metadata"]["tests_passed"] is True


def test_draft_pr_unknown_task(isolated_storage):
    server = _import_server()
    # No checkpoint for "unknown-task", but should still return a valid PR dict
    result = server.draft_pull_request("unknown-task", "feature/x", False)
    assert isinstance(result, dict)
    assert "title" in result
    assert "unknown-task" in result["title"]


def test_draft_pr_conventional_commit_types(isolated_storage):
    server = _import_server()
    for summary, expected_type in [
        ("Fix login bug", "fix"),
        ("Add new dashboard feature", "feat"),
        ("Refactor database layer", "refactor"),
        ("Update documentation", "docs"),
        ("Add unit tests for auth", "test"),
    ]:
        server.checkpoint_task(summary, summary, [], "done")
        result = server.draft_pull_request(summary, "branch", True)
        assert result["metadata"]["conventional_commit_type"] == expected_type, (
            f"Expected type '{expected_type}' for summary '{summary}', "
            f"got '{result['metadata']['conventional_commit_type']}'"
        )
