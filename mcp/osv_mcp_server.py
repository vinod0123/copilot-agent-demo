"""
MCP server that exposes OSV vulnerability lookups using existing repo logic.

This wraps functions from tools/osv_lookup.py so Copilot coding agent can call
package and requirements-based vulnerability checks as MCP tools.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# Ensure repository root is importable even when this file is executed directly.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse existing OSV logic from this repository.
from tools import osv_lookup as osv

mcp = FastMCP("osv-security-tools")


def _filter_and_sort(
    vulns: list[dict[str, Any]], min_severity: str
) -> list[dict[str, Any]]:
    min_rank = osv.SEVERITY_RANK.get(min_severity.upper(), osv.SEVERITY_RANK["HIGH"])
    filtered = [
        v
        for v in vulns
        if osv.SEVERITY_RANK.get(osv._normalized_severity(v), 0) >= min_rank
    ]
    filtered.sort(
        key=lambda v: osv.SEVERITY_RANK.get(osv._normalized_severity(v), 0),
        reverse=True,
    )
    return filtered


@mcp.tool()
def osv_lookup_package(
    ecosystem: str,
    package: str,
    version: str,
    min_severity: str = "HIGH",
    max_results: int = 5,
) -> str:
    """
    Query OSV for a specific package version and return compact text output.
    """
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    try:
        response = osv._post_osv(payload)
        vulns = response.get("vulns", [])
        if not isinstance(vulns, list):
            vulns = []
        vulns = _filter_and_sort(vulns, min_severity=min_severity)
        return osv._render_text(payload, vulns, max_items=max(1, int(max_results)))
    except Exception as exc:
        return f"osv_lookup_package failed: {exc}"


@mcp.tool()
def osv_lookup_requirements(
    requirements_path: str = "myapp/requirements.txt",
    ecosystem: str = "PyPI",
    min_severity: str = "HIGH",
    max_results: int = 5,
    detail_limit: int = 200,
) -> str:
    """
    Query OSV in batch for pinned dependencies from a requirements.txt file.
    """
    path = Path(requirements_path)
    if not path.exists():
        return f"Requirements file not found: {requirements_path}"

    try:
        req_items = osv._parse_requirements(str(path))
        if not req_items:
            return f"No pinned dependencies found in: {requirements_path}"

        batch_queries = [
            {
                "package": {"name": item["name"], "ecosystem": ecosystem},
                "version": item["version"],
            }
            for item in req_items
        ]
        response = osv._post_osv_batch({"queries": batch_queries})
        vulns = osv._flatten_batch_results(batch_queries, response)
        vulns = osv._enrich_batch_vulns(vulns, detail_limit=max(0, int(detail_limit)))
        vulns = _filter_and_sort(vulns, min_severity=min_severity)
        return osv._render_batch_text(
            query_count=len(req_items),
            scanned_count=len(batch_queries),
            vulns=vulns,
            max_items=max(1, int(max_results)),
        )
    except Exception as exc:
        return f"osv_lookup_requirements failed: {exc}"


if __name__ == "__main__":
    mcp.run()
