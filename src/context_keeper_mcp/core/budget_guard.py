"""
core/budget_guard.py — Token and context compaction engine for ContextKeeper 2.0

Computes a focused context bracket (top 5-7 items) from the full project
state for a given focus area, minimising Bobcoin consumption by excluding
irrelevant constraints, decisions, and patterns.
"""

from __future__ import annotations

import re
from typing import Any

from .memory import load_constraints, load_sessions

# Maximum items surfaced per category in a scoped context response
_TOP_N = 7


def _score_relevance(text: str, focus_area: str, current_file: str) -> float:
    """
    Simple token-overlap relevance score (0.0–1.0).
    Compares lowercased focus_area / file tokens against the text.
    """
    tokens = set(
        re.findall(r"[a-z0-9]+", (focus_area + " " + current_file).lower())
    )
    if not tokens:
        return 0.0
    text_lower = text.lower()
    hits = sum(1 for t in tokens if t in text_lower and len(t) > 2)
    return hits / len(tokens)


def get_scoped_context(focus_area: str, current_file: str = "") -> dict[str, Any]:
    """
    Return only the top 5-7 architectural constraints, banned patterns, and
    recent decisions that are relevant to *focus_area*, to avoid stuffing
    the full project state into every tool call.

    Returns a dict with keys:
      - focus_area: echoed back
      - current_file: echoed back
      - constraints: list of up to _TOP_N relevant constraint strings
      - banned_patterns: list of up to _TOP_N relevant banned pattern strings
      - recent_decisions: list of up to _TOP_N relevant task decisions
      - token_budget_note: advisory string about what was excluded
    """
    constraints_data = load_constraints()
    sessions_data = load_sessions()

    # --- Constraints --------------------------------------------------------
    raw_constraints: list[str] = constraints_data.get("constraints", [])
    if isinstance(raw_constraints, list):
        scored_constraints = sorted(
            raw_constraints,
            key=lambda c: _score_relevance(str(c), focus_area, current_file),
            reverse=True,
        )
    else:
        scored_constraints = []

    # --- Banned patterns ----------------------------------------------------
    raw_banned: list[str] = constraints_data.get("banned_patterns", [])
    if isinstance(raw_banned, list):
        scored_banned = sorted(
            raw_banned,
            key=lambda p: _score_relevance(str(p), focus_area, current_file),
            reverse=True,
        )
    else:
        scored_banned = []

    # --- Recent decisions (from sessions) -----------------------------------
    all_tasks = sessions_data.get("tasks", [])
    all_decisions: list[str] = []
    for task in all_tasks:
        for d in task.get("decisions", []):
            all_decisions.append(f"[{task['task_id']}] {d}")

    scored_decisions = sorted(
        all_decisions,
        key=lambda d: _score_relevance(d, focus_area, current_file),
        reverse=True,
    )

    top_constraints = scored_constraints[:_TOP_N]
    top_banned = scored_banned[:_TOP_N]
    top_decisions = scored_decisions[:_TOP_N]

    excluded = (
        max(0, len(scored_constraints) - _TOP_N)
        + max(0, len(scored_banned) - _TOP_N)
        + max(0, len(scored_decisions) - _TOP_N)
    )
    token_note = (
        f"Showing top {_TOP_N} items per category. "
        f"{excluded} lower-relevance items excluded to reduce token usage."
        if excluded > 0
        else "All available items fit within the top-N budget."
    )

    return {
        "focus_area": focus_area,
        "current_file": current_file,
        "constraints": top_constraints,
        "banned_patterns": top_banned,
        "recent_decisions": top_decisions,
        "token_budget_note": token_note,
    }
