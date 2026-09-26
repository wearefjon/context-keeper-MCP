"""
core/critic_gate.py — Actor-critic validation engine for ContextKeeper 2.0

Evaluates code diffs against project constraints and deterministic security
heuristics (hardcoded credentials, unparameterised SQL, unhandled async
exceptions). Produces structured pass/fail findings and can export SARIF v2.1.0.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .memory import load_constraints

# ---------------------------------------------------------------------------
# Security heuristic patterns (deterministic, no LLM required)
# ---------------------------------------------------------------------------

_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "SEC001",
        "name": "HardcodedCredential",
        "level": "error",
        "pattern": re.compile(
            r'(?i)(password|passwd|secret|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{4,}["\']'
        ),
        "description": "Hardcoded credential detected. Use environment variables or a secrets manager.",
    },
    {
        "id": "SEC002",
        "name": "UnparameterisedSQL",
        "level": "error",
        "pattern": re.compile(
            r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\'][^"\']*%[sd][^"\']*["\']',
            re.MULTILINE,
        ),
        "description": "String-formatted SQL query detected. Use parameterised queries to prevent SQL injection.",
    },
    {
        "id": "SEC003",
        "name": "UnhandledAsyncException",
        "level": "warning",
        "pattern": re.compile(
            r"async\s+def\s+\w+[^:]*:(?:[^#\n]|\n(?!\s*(?:try|\"\"\"|\s*#)))*?await\s",
            re.MULTILINE | re.DOTALL,
        ),
        "description": "Async function body without a try/except block — unhandled exceptions may crash the event loop.",
    },
    {
        "id": "SEC004",
        "name": "EvalUsage",
        "level": "error",
        "pattern": re.compile(r"\beval\s*\("),
        "description": "Use of eval() detected. This is a code injection risk; avoid dynamic code execution.",
    },
    {
        "id": "SEC005",
        "name": "InsecureDeserialization",
        "level": "warning",
        "pattern": re.compile(r"\bpickle\.loads?\b|\byaml\.load\b(?!\s*\(.*Loader)"),
        "description": "Insecure deserialisation detected. Use pickle only for trusted data; use yaml.safe_load instead of yaml.load.",
    },
    {
        "id": "SEC006",
        "name": "DebugFlagEnabled",
        "level": "warning",
        "pattern": re.compile(r'(?i)debug\s*=\s*True'),
        "description": "Debug mode enabled in code. Ensure this is not deployed to production.",
    },
]


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

def _parse_diff_lines(diff_text: str) -> list[tuple[int, str]]:
    """
    Extract added lines (+) from a unified diff, returning (line_number, content) pairs.
    Line numbers are tracked from +++ hunks.
    """
    added: list[tuple[int, str]] = []
    current_line = 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            # @@ -old_start,old_count +new_start,new_count @@
            m = re.search(r"\+(\d+)", raw_line)
            current_line = int(m.group(1)) if m else 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            added.append((current_line, raw_line[1:]))
            current_line += 1
        elif not raw_line.startswith("-"):
            current_line += 1
    return added


def _check_async_no_try(diff_text: str) -> list[dict[str, Any]]:
    """
    Specialised check: find async defs in added lines that lack a try block.
    Returns a list of finding dicts.
    """
    findings = []
    added_lines = _parse_diff_lines(diff_text)
    added_content = "\n".join(line for _, line in added_lines)

    async_blocks = re.finditer(
        r"async\s+def\s+(\w+)\s*\([^)]*\)\s*(?:->[^:]+)?:(.*?)(?=\nasync\s+def|\Z)",
        added_content,
        re.DOTALL,
    )
    for block in async_blocks:
        body = block.group(2)
        if "await" in body and "try:" not in body:
            findings.append({
                "rule_id": "SEC003",
                "level": "warning",
                "message": f"Async function '{block.group(1)}' uses await but has no try/except — unhandled exceptions may crash the event loop.",
                "line": None,
            })
    return findings


# ---------------------------------------------------------------------------
# Main audit entry point
# ---------------------------------------------------------------------------

def audit_diff_compliance(
    diff_text: str,
    modified_files: list[str],
) -> dict[str, Any]:
    """
    Evaluate a unified diff against project constraints and security heuristics.

    Returns:
      verdict: "pass" | "fail"
      findings: list of {rule_id, level, message, line, file}
      constraint_violations: list of violated constraint strings
      files_checked: list of modified file paths
      summary: human-readable summary string
    """
    constraints_data = load_constraints()
    project_constraints: list[str] = constraints_data.get("constraints", [])
    banned_patterns_cfg: list[str] = constraints_data.get("banned_patterns", [])

    findings: list[dict[str, Any]] = []
    added_lines = _parse_diff_lines(diff_text)

    # Run security rules against each added line
    for lineno, content in added_lines:
        for rule in _SECURITY_RULES:
            if rule["id"] == "SEC003":
                continue  # handled separately below
            if rule["pattern"].search(content):
                findings.append({
                    "rule_id": rule["id"],
                    "level": rule["level"],
                    "message": rule["description"],
                    "line": lineno,
                    "snippet": content.strip()[:120],
                })

    # Async-no-try check
    findings.extend(_check_async_no_try(diff_text))

    # Check banned patterns from constraints.json
    constraint_violations: list[str] = []
    added_full = "\n".join(line for _, line in added_lines)
    for bp in banned_patterns_cfg:
        try:
            if re.search(bp, added_full, re.IGNORECASE):
                constraint_violations.append(bp)
                findings.append({
                    "rule_id": "PROJ001",
                    "level": "error",
                    "message": f"Banned pattern detected: {bp}",
                    "line": None,
                    "snippet": "",
                })
        except re.error:
            # treat banned_pattern as literal substring
            if bp.lower() in added_full.lower():
                constraint_violations.append(bp)

    error_count = sum(1 for f in findings if f.get("level") == "error")
    verdict = "fail" if error_count > 0 else "pass"

    return {
        "verdict": verdict,
        "findings": findings,
        "constraint_violations": constraint_violations,
        "files_checked": modified_files,
        "summary": (
            f"Verdict: {verdict.upper()}. "
            f"{len(findings)} finding(s) — {error_count} error(s), "
            f"{len(findings) - error_count} warning(s)."
        ),
    }


# ---------------------------------------------------------------------------
# SARIF export
# ---------------------------------------------------------------------------

def export_sarif(
    audit_findings: list[dict[str, Any]],
    output_file: str = "reports/bob_audit.sarif",
) -> str:
    """
    Format audit findings into an OASIS SARIF v2.1.0 compliant JSON file.
    Returns the path to the written file.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build rule index from findings
    rule_ids_seen: set[str] = set()
    rules: list[dict[str, Any]] = []
    for f in audit_findings:
        rid = f.get("rule_id", "UNKNOWN")
        if rid not in rule_ids_seen:
            rule_ids_seen.add(rid)
            # Find description from built-in rules
            desc = next(
                (r["description"] for r in _SECURITY_RULES if r["id"] == rid),
                f.get("message", rid),
            )
            rules.append({
                "id": rid,
                "shortDescription": {"text": desc},
            })

    results: list[dict[str, Any]] = []
    for f in audit_findings:
        result: dict[str, Any] = {
            "ruleId": f.get("rule_id", "UNKNOWN"),
            "level": f.get("level", "warning"),
            "message": {"text": f.get("message", "")},
            "locations": [],
        }
        file_uri = f.get("file", "unknown")
        lineno = f.get("line")
        if file_uri or lineno:
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri or "unknown"},
                }
            }
            if lineno is not None:
                loc["physicalLocation"]["region"] = {"startLine": lineno}
            result["locations"].append(loc)
        results.append(result)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ContextKeeper2",
                        "version": "2.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return str(output_path.resolve())
