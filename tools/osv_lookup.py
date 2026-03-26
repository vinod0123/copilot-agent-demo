#!/usr/bin/env python
"""
Compact OSV query helper for dependency vulnerability checks.

Examples:
  python tools/osv_lookup.py --ecosystem PyPI --package jinja2 --version 2.4.1
  python tools/osv_lookup.py --commit 6879efc2c1596d11a6a6ad296f80063b558d5e0f
  python tools/osv_lookup.py --ecosystem npm --package lodash --version 4.17.20 --format json
  python tools/osv_lookup.py --requirements requirements.txt --ecosystem PyPI
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import urllib.error
import urllib.request
from typing import Any

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_API_URL = "https://api.osv.dev/v1/vulns/"
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}


def _build_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.commit:
        return {"commit": args.commit}
    return {
        "version": args.version,
        "package": {"name": args.package, "ecosystem": args.ecosystem},
    }


def _post_osv(payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_osv_batch(payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_osv_vuln(vuln_id: str) -> dict[str, Any]:
    req = urllib.request.Request(
        OSV_VULN_API_URL + vuln_id,
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _severity_label(vuln: dict[str, Any]) -> str:
    db_sev = vuln.get("database_specific", {}).get("severity")
    if db_sev:
        return str(db_sev).upper()
    sev = vuln.get("severity", [])
    if not sev:
        return "UNKNOWN"
    chunks = []
    for entry in sev:
        etype = entry.get("type", "unknown")
        score = entry.get("score", "n/a")
        chunks.append(f"{etype}:{score}")
    return "; ".join(chunks)


def _normalized_severity(vuln: dict[str, Any]) -> str:
    """
    Best-effort normalized severity for filtering.
    OSV often provides database_specific.severity values we can map directly.
    """
    raw = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if raw in SEVERITY_RANK:
        return raw
    return "UNKNOWN"


def _fixed_versions(vuln: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fix = event.get("fixed")
                if fix:
                    out.append(str(fix))
    # Preserve order, remove duplicates
    deduped = list(dict.fromkeys(out))
    return deduped


def _aliases(vuln: dict[str, Any]) -> list[str]:
    aliases = vuln.get("aliases", [])
    if isinstance(aliases, list):
        return [str(a) for a in aliases]
    return []


def _first_reference(vuln: dict[str, Any]) -> str | None:
    refs = vuln.get("references", [])
    if refs and isinstance(refs, list):
        url = refs[0].get("url")
        if url:
            return str(url)
    return None


def _summary(vuln: dict[str, Any]) -> str:
    text = vuln.get("summary") or vuln.get("details") or "No summary provided."
    return " ".join(str(text).split())


def _compact_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": vuln.get("id", "UNKNOWN"),
        "severity": _severity_label(vuln),
        "aliases": _aliases(vuln),
        "summary": _summary(vuln),
        "fixed_versions": _fixed_versions(vuln),
        "reference": _first_reference(vuln),
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
    }


def _render_text(query_payload: dict[str, Any], vulns: list[dict[str, Any]], max_items: int) -> str:
    lines: list[str] = []
    lines.append("OSV compact result")
    lines.append(f"Query: {json.dumps(query_payload, separators=(',', ':'))}")
    lines.append(f"Matches: {len(vulns)}")
    if not vulns:
        lines.append("Status: No known vulnerabilities found for this exact query.")
        return "\n".join(lines)

    lines.append("")
    for idx, vuln in enumerate(vulns[:max_items], start=1):
        compact = _compact_vuln(vuln)
        lines.append(f"[{idx}] {compact['id']} | severity={compact['severity']}")
        if compact["aliases"]:
            lines.append(f"aliases: {', '.join(compact['aliases'][:5])}")
        if compact["fixed_versions"]:
            lines.append(f"fixed: {', '.join(compact['fixed_versions'][:6])}")
        summary = textwrap.shorten(compact["summary"], width=180, placeholder="...")
        lines.append(f"summary: {summary}")
        if compact["reference"]:
            lines.append(f"ref: {compact['reference']}")
        if compact["published"] or compact["modified"]:
            lines.append(
                f"published: {compact['published'] or 'n/a'} | modified: {compact['modified'] or 'n/a'}"
            )
        lines.append("")

    if len(vulns) > max_items:
        lines.append(f"... {len(vulns) - max_items} more result(s) omitted. Increase --max to view.")
    return "\n".join(lines).rstrip()


def _parse_requirements(path: str) -> list[dict[str, str]]:
    queries: list[dict[str, str]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r ") or line.startswith("--requirement "):
                continue
            # keep this lightweight and explicit: only pinned package==version lines
            if "==" not in line:
                continue
            left, right = line.split("==", 1)
            name = left.strip()
            version = right.strip()
            if not name or not version:
                continue
            queries.append({"name": name, "version": version})
    return queries


def _flatten_batch_results(batch_queries: list[dict[str, Any]], batch_response: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    results = batch_response.get("results", [])
    if not isinstance(results, list):
        return out
    for idx, result in enumerate(results):
        if idx >= len(batch_queries):
            break
        query = batch_queries[idx]
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if not isinstance(vulns, list):
            vulns = []
        for vuln in vulns:
            if isinstance(vuln, dict):
                vuln_copy = dict(vuln)
                vuln_copy["__package_name"] = query.get("package", {}).get("name")
                vuln_copy["__package_version"] = query.get("version")
                vuln_copy["__ecosystem"] = query.get("package", {}).get("ecosystem")
                out.append(vuln_copy)
    return out


def _enrich_batch_vulns(vulns: list[dict[str, Any]], detail_limit: int) -> list[dict[str, Any]]:
    if detail_limit <= 0:
        return vulns
    by_id: dict[str, dict[str, Any]] = {}
    for vuln in vulns:
        vid = str(vuln.get("id", "")).strip()
        if vid and vid not in by_id and len(by_id) < detail_limit:
            by_id[vid] = {}
    for vid in by_id:
        try:
            by_id[vid] = _get_osv_vuln(vid)
        except Exception:
            by_id[vid] = {}

    enriched: list[dict[str, Any]] = []
    for vuln in vulns:
        vid = str(vuln.get("id", "")).strip()
        detail = by_id.get(vid, {})
        if detail and isinstance(detail, dict):
            merged = dict(detail)
            merged["id"] = vid or merged.get("id")
            merged["__package_name"] = vuln.get("__package_name")
            merged["__package_version"] = vuln.get("__package_version")
            merged["__ecosystem"] = vuln.get("__ecosystem")
            enriched.append(merged)
        else:
            enriched.append(vuln)
    return enriched


def _render_batch_text(query_count: int, scanned_count: int, vulns: list[dict[str, Any]], max_items: int) -> str:
    lines: list[str] = []
    lines.append("OSV compact batch result")
    lines.append(f"Input dependencies: {query_count}")
    lines.append(f"Scanned dependencies: {scanned_count}")
    lines.append(f"Matched vulnerabilities: {len(vulns)}")
    if not vulns:
        lines.append("Status: No known vulnerabilities found for scanned dependencies.")
        return "\n".join(lines)

    lines.append("")
    for idx, vuln in enumerate(vulns[:max_items], start=1):
        pkg = f"{vuln.get('__package_name', 'unknown')}=={vuln.get('__package_version', 'unknown')}"
        severity = _severity_label(vuln)
        lines.append(f"[{idx}] {pkg} -> {vuln.get('id', 'UNKNOWN')} | severity={severity}")
        aliases = _aliases(vuln)
        if aliases:
            lines.append(f"aliases: {', '.join(aliases[:5])}")
        fixed = _fixed_versions(vuln)
        if fixed:
            lines.append(f"fixed: {', '.join(fixed[:6])}")
        lines.append(f"summary: {textwrap.shorten(_summary(vuln), width=160, placeholder='...')}")
        ref = _first_reference(vuln)
        if ref:
            lines.append(f"ref: {ref}")
        lines.append("")
    if len(vulns) > max_items:
        lines.append(f"... {len(vulns) - max_items} more result(s) omitted. Increase --max to view.")
    return "\n".join(lines).rstrip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Compact OSV vulnerability lookup helper")
    parser.add_argument("--ecosystem", help="Ecosystem name, e.g. PyPI, npm, Maven")
    parser.add_argument("--package", help="Package name, e.g. jinja2")
    parser.add_argument("--version", help="Package version, e.g. 2.4.1")
    parser.add_argument("--commit", help="Commit hash to query instead of package/version")
    parser.add_argument("--requirements", help="Path to requirements.txt for batch lookup")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--max", type=int, default=3, help="Max vulnerabilities to print in text mode")
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MODERATE", "HIGH", "CRITICAL"],
        default="LOW",
        help="Only include vulnerabilities at or above this severity.",
    )
    parser.add_argument(
        "--detail-limit",
        type=int,
        default=200,
        help="In batch mode, fetch up to this many unique vulnerability detail records by ID.",
    )
    args = parser.parse_args()

    mode_count = sum(
        [
            1 if args.commit else 0,
            1 if args.requirements else 0,
            1 if (args.ecosystem and args.package and args.version) else 0,
        ]
    )
    if mode_count != 1:
        parser.error(
            "Use exactly one mode: --commit OR --requirements (+ --ecosystem) OR --ecosystem + --package + --version."
        )
    if args.requirements and not args.ecosystem:
        parser.error("--requirements mode requires --ecosystem.")

    if args.requirements:
        req_items = _parse_requirements(args.requirements)
        batch_queries = [
            {
                "package": {"name": item["name"], "ecosystem": args.ecosystem},
                "version": item["version"],
            }
            for item in req_items
        ]
        payload = {"queries": batch_queries}
        try:
            response = _post_osv_batch(payload)
        except urllib.error.HTTPError as exc:
            print(f"OSV batch request failed: HTTP {exc.code}", file=sys.stderr)
            return 2
        except urllib.error.URLError as exc:
            print(f"OSV batch request failed: {exc.reason}", file=sys.stderr)
            return 2
        except TimeoutError:
            print("OSV batch request failed: timeout", file=sys.stderr)
            return 2

        vulns = _flatten_batch_results(batch_queries, response)
        vulns = _enrich_batch_vulns(vulns, detail_limit=max(0, args.detail_limit))
        min_rank = SEVERITY_RANK[args.min_severity]
        vulns = [v for v in vulns if SEVERITY_RANK.get(_normalized_severity(v), 0) >= min_rank]
        # show highest severity first
        vulns.sort(key=lambda v: SEVERITY_RANK.get(_normalized_severity(v), 0), reverse=True)

        if args.format == "json":
            output = {
                "mode": "requirements_batch",
                "requirements_file": args.requirements,
                "ecosystem": args.ecosystem,
                "input_dependencies": len(req_items),
                "scanned_dependencies": len(batch_queries),
                "match_count": len(vulns),
                "min_severity": args.min_severity,
                "vulnerabilities": [_compact_vuln(v) | {
                    "package": v.get("__package_name"),
                    "version": v.get("__package_version"),
                    "ecosystem": v.get("__ecosystem"),
                } for v in vulns],
            }
            print(json.dumps(output, indent=2))
            return 0

        print(_render_batch_text(len(req_items), len(batch_queries), vulns, max_items=max(1, args.max)))
        return 0

    payload = _build_payload(args)
    try:
        response = _post_osv(payload)
    except urllib.error.HTTPError as exc:
        print(f"OSV request failed: HTTP {exc.code}", file=sys.stderr)
        return 2
    except urllib.error.URLError as exc:
        print(f"OSV request failed: {exc.reason}", file=sys.stderr)
        return 2
    except TimeoutError:
        print("OSV request failed: timeout", file=sys.stderr)
        return 2

    vulns = response.get("vulns", [])
    if not isinstance(vulns, list):
        vulns = []
    min_rank = SEVERITY_RANK[args.min_severity]
    vulns = [
        v
        for v in vulns
        if SEVERITY_RANK.get(_normalized_severity(v), 0) >= min_rank
    ]

    if args.format == "json":
        output = {
            "query": payload,
            "match_count": len(vulns),
            "min_severity": args.min_severity,
            "vulnerabilities": [_compact_vuln(v) for v in vulns],
        }
        print(json.dumps(output, indent=2))
        return 0

    print(_render_text(payload, vulns, max_items=max(1, args.max)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
