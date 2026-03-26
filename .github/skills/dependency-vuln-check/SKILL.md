# Dependency Vulnerability Check

## Purpose

Use this skill to assess pinned dependency versions against known vulnerabilities.

## Workflow

1. Identify package, version, and ecosystem.
2. Prefer local OSV helper output from `tools/osv_lookup.py`.
3. Use `HIGH+` severity by default.
4. Summarize only top actionable findings.

## Commands

Single package:

```bash
python tools/osv_lookup.py --ecosystem PyPI --package jinja2 --version 2.4.1 --min-severity HIGH --max 3
```

Batch requirements:

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

## Output

1. Package/version
2. Vulnerability status
3. Evidence source
4. Suggested safe upgrade
5. Confidence

## Rules

- Do not claim vulnerability without evidence.
- Prefer structured advisory sources over generic web posts.
- If uncertain, label as possible risk.

