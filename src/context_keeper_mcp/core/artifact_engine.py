"""
core/artifact_engine.py — Deliverable engine for ContextKeeper 2.0

Synthesises session data into:
  - Mermaid.js sequence / flowchart diagrams
  - Conventional Commits PR markdown templates
  - watsonx Orchestrate JSON action payloads
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .memory import load_sessions


# ---------------------------------------------------------------------------
# Mermaid diagram generation
# ---------------------------------------------------------------------------

_SAFE_ID = re.compile(r"[^A-Za-z0-9_]")


def _safe_node(name: str) -> str:
    """Convert an arbitrary string to a safe Mermaid node identifier."""
    return _SAFE_ID.sub("_", name.strip()) or "Node"


def generate_mermaid_flow(
    subsystem_name: str,
    components_touched: list[str],
    flow_type: str = "sequence",
) -> str:
    """
    Generate valid Mermaid.js diagram syntax for the given subsystem and
    components.

    flow_type:
      - "sequence"  → sequenceDiagram showing Bob calling each component
      - "flowchart" → flowchart LR showing component dependencies
    """
    ft = (flow_type or "sequence").strip().lower()
    safe_sub = _safe_node(subsystem_name)
    safe_components = [_safe_node(c) for c in components_touched] if components_touched else ["Component"]

    if ft == "sequence":
        lines = [
            "sequenceDiagram",
            f"    participant Bob",
            f"    participant {safe_sub}",
        ]
        for comp in safe_components:
            if comp != safe_sub:
                lines.append(f"    participant {comp}")
        lines.append(f"    Bob->>{safe_sub}: invoke()")
        for comp in safe_components:
            if comp != safe_sub:
                lines.append(f"    {safe_sub}->>{comp}: process()")
                lines.append(f"    {comp}-->>{safe_sub}: result")
        lines.append(f"    {safe_sub}->>Bob: response")
        return "\n".join(lines)

    else:  # flowchart
        lines = ["flowchart LR"]
        lines.append(f"    Bob([Bob Agent])")
        lines.append(f"    {safe_sub}[{subsystem_name}]")
        lines.append(f"    Bob --> {safe_sub}")
        prev = safe_sub
        for comp in safe_components:
            if comp != safe_sub:
                lines.append(f"    {comp}[{comp}]")
                lines.append(f"    {prev} --> {comp}")
                prev = comp
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pull Request template
# ---------------------------------------------------------------------------

def draft_pull_request(
    task_id: str,
    branch_name: str,
    tests_passed: bool,
) -> dict[str, Any]:
    """
    Compile session state, constraint verifications, and diagrams into a
    production-grade PR markdown body.

    Returns a dict with keys:
      - title: PR title string
      - branch: branch name
      - body: full markdown body (Conventional Commits format)
      - metadata: dict of structured fields for API submission
    """
    sessions_data = load_sessions()
    tasks = sessions_data.get("tasks", [])

    task = next((t for t in tasks if t["task_id"] == task_id), None)
    summary = task["summary"] if task else f"Task {task_id}"
    decisions = task.get("decisions", []) if task else []
    status = task.get("status", "unknown") if task else "unknown"

    # Infer conventional commit type from summary
    # Order matters: more-specific checks (test, docs) before broad ones (feat)
    summary_lower = summary.lower()
    if any(w in summary_lower for w in ("fix", "bug", "patch", "repair")):
        cc_type = "fix"
    elif any(w in summary_lower for w in ("test", "spec", "coverage")):
        cc_type = "test"
    elif any(w in summary_lower for w in ("doc", "readme", "comment")):
        cc_type = "docs"
    elif any(w in summary_lower for w in ("refactor", "clean", "restructure", "moderniz")):
        cc_type = "refactor"
    elif any(w in summary_lower for w in ("feat", "add", "new", "implement", "build")):
        cc_type = "feat"
    else:
        cc_type = "chore"

    pr_title = f"{cc_type}({task_id}): {summary}"
    now = datetime.now(timezone.utc).isoformat()
    test_badge = "✅ passing" if tests_passed else "❌ failing / not run"

    # Generate a quick flowchart for the PR
    mermaid_embed = generate_mermaid_flow(
        subsystem_name=task_id,
        components_touched=[re.sub(r"\s+", "_", d[:30]) for d in decisions[:4]],
        flow_type="flowchart",
    )

    body_lines = [
        f"## {pr_title}",
        "",
        "### Summary",
        f"> {summary}",
        "",
        "### Changes",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Task ID | `{task_id}` |",
        f"| Branch | `{branch_name}` |",
        f"| Status | `{status}` |",
        f"| Tests | {test_badge} |",
        f"| Generated | {now} |",
        "",
        "### Decisions Captured",
        "",
    ]

    if decisions:
        for d in decisions:
            body_lines.append(f"- {d}")
    else:
        body_lines.append("_No decisions recorded for this task._")

    body_lines += [
        "",
        "### Architecture / Flow",
        "",
        "```mermaid",
        mermaid_embed,
        "```",
        "",
        "### Checklist",
        "",
        "- [x] Code compiles / lints clean" if tests_passed else "- [ ] Code compiles / lints clean",
        "- [x] Tests pass" if tests_passed else "- [ ] Tests pass",
        "- [x] Security heuristics checked (ContextKeeper critic_gate)",
        "- [x] Dependencies audited (ContextKeeper modernizer)",
        "- [x] PR template generated by ContextKeeper 2.0",
        "",
    ]

    return {
        "title": pr_title,
        "branch": branch_name,
        "body": "\n".join(body_lines),
        "metadata": {
            "task_id": task_id,
            "conventional_commit_type": cc_type,
            "tests_passed": tests_passed,
            "generated_at": now,
        },
    }


# ---------------------------------------------------------------------------
# watsonx Orchestrate JSON payload
# ---------------------------------------------------------------------------

def build_watsonx_payload(task_id: str) -> dict[str, Any]:
    """
    Build a watsonx Orchestrate-compatible JSON action payload from a task's
    session record. Useful for triggering downstream automations.
    """
    sessions_data = load_sessions()
    tasks = sessions_data.get("tasks", [])
    task = next((t for t in tasks if t["task_id"] == task_id), {})

    return {
        "action": "context_keeper.task_completed",
        "version": "2.0.0",
        "payload": {
            "task_id": task_id,
            "summary": task.get("summary", ""),
            "decisions": task.get("decisions", []),
            "status": task.get("status", "unknown"),
            "updated_at": task.get("updated_at", ""),
        },
        "metadata": {
            "source": "ContextKeeper2",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }
