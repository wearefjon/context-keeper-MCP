"""
ContextKeeper 2.0 — MCP Server entry point

Developer governance, runtime modernization, actor-critic review, and release
engine built for IBM Bob 2.0 and agentic IDE workflows.

Run (stdio, for IDE MCP config):
  context-keeper-mcp

Test with MCP Inspector:
  npx -y @modelcontextprotocol/inspector context-keeper-mcp
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .core.artifact_engine import (
    draft_pull_request as _draft_pr,
    generate_mermaid_flow as _mermaid,
)
from .core.budget_guard import get_scoped_context as _scoped_ctx
from .core.critic_gate import audit_diff_compliance as _audit_diff
from .core.critic_gate import export_sarif as _export_sarif
from .core.memory import sync_agents_md, upsert_task
from .core.modernizer import audit_dependencies_and_runtime as _audit_deps

mcp = FastMCP("ContextKeeper 2.0")


# ---------------------------------------------------------------------------
# Tool 1 — checkpoint_task
# ---------------------------------------------------------------------------
@mcp.tool()
def checkpoint_task(
    task_id: str,
    summary: str,
    decisions: list[str],
    status: str,
) -> str:
    """
    Persist a task checkpoint to .context/sessions.json and idempotently
    update AGENTS.md (Bob's /init-compatible session log).

    Args:
        task_id:   Unique identifier for this task (e.g. "T42" or "auth-refactor").
        summary:   One-sentence description of what was accomplished.
        decisions: List of architectural or design decisions made during this task.
        status:    Lifecycle state: "in_progress", "blocked", or "done".

    Returns:
        Confirmation string with the persisted task_id.
    """
    valid_statuses = {"todo", "in_progress", "blocked", "done"}
    if status not in valid_statuses:
        return f"Error: status must be one of {sorted(valid_statuses)}, got {status!r}."
    if not task_id.strip():
        return "Error: task_id cannot be empty."
    if not summary.strip():
        return "Error: summary cannot be empty."

    entry = upsert_task(
        task_id=task_id.strip(),
        summary=summary.strip(),
        decisions=[d for d in decisions if d.strip()],
        status=status,
    )
    sync_agents_md()
    return (
        f"Checkpoint saved: [{entry['task_id']}] {entry['summary']} "
        f"(status={entry['status']}, {len(entry['decisions'])} decision(s) recorded). "
        f"AGENTS.md synchronised."
    )


# ---------------------------------------------------------------------------
# Tool 2 — get_scoped_context
# ---------------------------------------------------------------------------
@mcp.tool()
def get_scoped_context(focus_area: str, current_file: str = "") -> dict:
    """
    Return a focused subset of project constraints and recent decisions
    relevant to *focus_area*, capped at 5–7 items per category to minimise
    token consumption.

    Args:
        focus_area:   The sub-system or feature area currently being worked on
                      (e.g. "authentication", "database migrations").
        current_file: Optional path of the file being edited — used to improve
                      relevance scoring.

    Returns:
        Dict with keys: focus_area, current_file, constraints,
        banned_patterns, recent_decisions, token_budget_note.
    """
    return _scoped_ctx(focus_area=focus_area, current_file=current_file)


# ---------------------------------------------------------------------------
# Tool 3 — audit_dependencies_and_runtime
# ---------------------------------------------------------------------------
@mcp.tool()
def audit_dependencies_and_runtime(
    manifest_content: str,
    manifest_type: str,
    target_runtime: str = "",
) -> dict:
    """
    Inspect a package manifest for deprecated libraries, CVE-flagged packages,
    and outdated runtime targets caused by LLM training-data cutoff drift.

    Args:
        manifest_content: Raw text content of the manifest file.
        manifest_type:    One of "package.json", "requirements.txt", "pyproject.toml".
        target_runtime:   Optional desired runtime hint, e.g. "node@22" or "python@3.12".

    Returns:
        Dict with deprecated_findings, modern_alternatives, runtime_findings, summary.
    """
    return _audit_deps(
        manifest_content=manifest_content,
        manifest_type=manifest_type,
        target_runtime=target_runtime,
    )


# ---------------------------------------------------------------------------
# Tool 4 — audit_diff_compliance
# ---------------------------------------------------------------------------
@mcp.tool()
def audit_diff_compliance(diff_text: str, modified_files: list[str]) -> dict:
    """
    Evaluate a unified diff against .context/constraints.json rules and
    deterministic security heuristics (hardcoded credentials, unparameterised SQL,
    unhandled async exceptions, eval usage, insecure deserialisation).

    Args:
        diff_text:      Unified diff text (output of `git diff`).
        modified_files: List of file paths affected by the diff.

    Returns:
        Dict with verdict ("pass"/"fail"), findings (line-by-line), and summary.
    """
    return _audit_diff(diff_text=diff_text, modified_files=modified_files)


# ---------------------------------------------------------------------------
# Tool 5 — export_sarif_report
# ---------------------------------------------------------------------------
@mcp.tool()
def export_sarif_report(
    audit_findings: list[dict],
    output_file: str = "reports/bob_audit.sarif",
) -> str:
    """
    Format audit findings into an OASIS SARIF v2.1.0 compliant JSON report
    and write it to disk.

    Args:
        audit_findings: List of finding dicts from audit_diff_compliance
                        (each with rule_id, level, message, line, file).
        output_file:    Output path for the SARIF file.
                        Defaults to "reports/bob_audit.sarif".

    Returns:
        Absolute path to the written SARIF report file.
    """
    path = _export_sarif(audit_findings=audit_findings, output_file=output_file)
    return f"SARIF report written: {path} ({len(audit_findings)} finding(s))."


# ---------------------------------------------------------------------------
# Tool 6 — generate_mermaid_flow
# ---------------------------------------------------------------------------
@mcp.tool()
def generate_mermaid_flow(
    subsystem_name: str,
    components_touched: list[str],
    flow_type: str = "sequence",
) -> str:
    """
    Generate valid Mermaid.js diagram syntax reflecting modified components
    and their control flow within a subsystem.

    Args:
        subsystem_name:     Name of the subsystem or feature being documented.
        components_touched: List of component/module names involved.
        flow_type:          "sequence" (default) for sequenceDiagram,
                            or "flowchart" for flowchart LR.

    Returns:
        Mermaid diagram syntax as a plain string (paste into a ```mermaid block).
    """
    return _mermaid(
        subsystem_name=subsystem_name,
        components_touched=components_touched,
        flow_type=flow_type,
    )


# ---------------------------------------------------------------------------
# Tool 7 — draft_pull_request
# ---------------------------------------------------------------------------
@mcp.tool()
def draft_pull_request(
    task_id: str,
    branch_name: str,
    tests_passed: bool,
) -> dict:
    """
    Compile session state, constraint verifications, and Mermaid diagrams
    into a production-grade PR markdown template using Conventional Commits
    formatting.

    Args:
        task_id:      Task ID whose checkpoint data to include in the PR body.
        branch_name:  Git branch name for the PR.
        tests_passed: Whether automated tests passed for this branch.

    Returns:
        Dict with title (str), branch (str), body (full markdown), and metadata.
    """
    return _draft_pr(task_id=task_id, branch_name=branch_name, tests_passed=tests_passed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
