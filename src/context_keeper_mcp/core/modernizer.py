"""
core/modernizer.py — Modernization sentinel for ContextKeeper 2.0

Scans package manifests (package.json, requirements.txt, pyproject.toml)
for deprecated libraries, outdated runtime targets, and known vulnerable
patterns. Returns approved modern alternatives and required runtime flags.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .memory import load_deprecated_rules

# ---------------------------------------------------------------------------
# Known outdated runtime versions (lower bound for "outdated")
# ---------------------------------------------------------------------------
_RUNTIME_FLOOR: dict[str, str] = {
    "node": "18",
    "python": "3.11",
    "ruby": "3.2",
    "java": "17",
    "go": "1.21",
}

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_SEM_RE = re.compile(r"(\d+)(?:\.(\d+))?")


def _major(version_str: str) -> int | None:
    m = _SEM_RE.search(version_str)
    return int(m.group(1)) if m else None


def _minor(version_str: str) -> int | None:
    m = _SEM_RE.search(version_str)
    return int(m.group(2)) if m and m.group(2) else None


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_package_json(content: str) -> dict[str, Any]:
    """Extract dependencies, devDependencies, and engines from package.json."""
    try:
        pkg = json.loads(content)
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}"}

    deps: dict[str, str] = {}
    deps.update(pkg.get("dependencies", {}))
    deps.update(pkg.get("devDependencies", {}))
    engines: dict[str, str] = pkg.get("engines", {})
    return {"deps": deps, "engines": engines, "type": "npm"}


def _parse_requirements_txt(content: str) -> dict[str, Any]:
    """Parse requirements.txt lines into {package: version_spec}."""
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle: package==1.2, package>=1.2, package~=1.2, package
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~^].+)?", line)
        if m:
            deps[m.group(1).lower()] = (m.group(2) or "").strip()
    return {"deps": deps, "engines": {}, "type": "pip"}


def _parse_pyproject_toml(content: str) -> dict[str, Any]:
    """
    Minimal TOML parser for pyproject.toml — only extracts
    [project].dependencies and requires-python without a full TOML library.
    """
    deps: dict[str, str] = {}
    engines: dict[str, str] = {}

    # requires-python = ">=3.11"
    rp = re.search(r'requires-python\s*=\s*"([^"]+)"', content)
    if rp:
        engines["python"] = rp.group(1)

    # dependencies = [ "package>=1.0", ... ]
    dep_block = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if dep_block:
        for item in re.findall(r'"([^"]+)"', dep_block.group(1)):
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~^].+)?", item.strip())
            if m:
                deps[m.group(1).lower()] = (m.group(2) or "").strip()

    return {"deps": deps, "engines": engines, "type": "pip"}


# ---------------------------------------------------------------------------
# Core audit logic
# ---------------------------------------------------------------------------

def audit_dependencies_and_runtime(
    manifest_content: str,
    manifest_type: str,
    target_runtime: str = "",
) -> dict[str, Any]:
    """
    Inspect a manifest for deprecated packages, flagged CVEs, and outdated
    runtime targets. Returns a structured findings dict.

    manifest_type: one of "package.json", "requirements.txt", "pyproject.toml"
    target_runtime: optional hint like "node@22" or "python@3.12"
    """
    deprecated_rules = load_deprecated_rules()
    deprecated_packages: dict[str, Any] = deprecated_rules.get("deprecated_packages", {})
    cve_packages: dict[str, Any] = deprecated_rules.get("cve_packages", {})

    # Parse manifest
    mt = manifest_type.lower().strip()
    if "package.json" in mt:
        parsed = _parse_package_json(manifest_content)
    elif "requirements" in mt:
        parsed = _parse_requirements_txt(manifest_content)
    elif "pyproject" in mt:
        parsed = _parse_pyproject_toml(manifest_content)
    else:
        parsed = {"error": f"Unsupported manifest type: {manifest_type!r}. Use package.json, requirements.txt, or pyproject.toml."}

    if "error" in parsed:
        return {"status": "error", "message": parsed["error"]}

    deps: dict[str, str] = parsed.get("deps", {})
    engines: dict[str, str] = parsed.get("engines", {})
    findings: list[dict[str, str]] = []
    modern_alternatives: list[dict[str, str]] = []

    # Check each dep against deprecated rules
    for pkg, version_spec in deps.items():
        pkg_lower = pkg.lower()

        # Deprecated / replaced package
        if pkg_lower in deprecated_packages:
            rule = deprecated_packages[pkg_lower]
            findings.append({
                "package": pkg,
                "severity": rule.get("severity", "medium"),
                "reason": rule.get("reason", "Deprecated"),
                "version_found": version_spec or "any",
            })
            modern_alternatives.append({
                "replace": pkg,
                "with": rule.get("replacement", "See documentation"),
                "notes": rule.get("notes", ""),
            })

        # CVE-flagged package
        if pkg_lower in cve_packages:
            cve = cve_packages[pkg_lower]
            findings.append({
                "package": pkg,
                "severity": "high",
                "reason": cve.get("reason", "Known CVE"),
                "cve_id": cve.get("cve_id", ""),
                "version_found": version_spec or "any",
                "fix_version": cve.get("fix_version", "upgrade to latest"),
            })

    # Runtime version check
    runtime_findings: list[dict[str, str]] = []
    all_engines = dict(engines)
    if target_runtime:
        # e.g. "node@22" or "python3.12"
        m = re.match(r"([a-z]+)[@ ]?(\d+[\d.]*)", target_runtime.lower())
        if m:
            all_engines[m.group(1)] = ">=" + m.group(2)

    for runtime, spec in all_engines.items():
        floor = _RUNTIME_FLOOR.get(runtime.lower())
        if floor:
            v_major = _major(spec)
            v_minor = _minor(spec)
            floor_major = _major(floor)
            floor_minor = _minor(floor)
            # Outdated if: major is lower, OR same major but minor is lower
            is_outdated = False
            if v_major is not None and floor_major is not None:
                if v_major < floor_major:
                    is_outdated = True
                elif v_major == floor_major:
                    fmin = floor_minor if floor_minor is not None else 0
                    vmin = v_minor if v_minor is not None else 0
                    if vmin < fmin:
                        is_outdated = True
            if is_outdated:
                runtime_findings.append({
                    "runtime": runtime,
                    "version_found": spec,
                    "minimum_recommended": floor,
                    "note": f"Upgrade to {runtime} {floor}+ for active LTS support and security patches.",
                })

    return {
        "status": "ok",
        "manifest_type": manifest_type,
        "packages_scanned": len(deps),
        "deprecated_findings": findings,
        "modern_alternatives": modern_alternatives,
        "runtime_findings": runtime_findings,
        "summary": (
            f"{len(findings)} deprecated/CVE package(s) found, "
            f"{len(runtime_findings)} runtime concern(s)."
        ),
    }
