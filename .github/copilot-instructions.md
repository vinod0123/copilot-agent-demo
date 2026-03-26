## Repository Instructions for Copilot

You are assisting a DevSecOps proof of concept.

Priorities:
- Review security risks before style issues.
- Flag hardcoded credentials, tokens, API keys, passwords, and connection strings.
- Flag sensitive logging and accidental secret disclosure.
- Flag unsafe command execution (`shell=True`) and weak input validation.
- Prefer minimal, practical remediations suitable for PR review.

Dependency risk guidance:
- Use structured sources (OSV, GitHub Advisory data, NVD) over generic web claims.
- For this repo, use `tools/osv_lookup.py` output as primary dependency evidence.
- Default summary size: top `3` findings for single-package checks, top `5` for batch checks.

Output style:
1. Findings
2. Why it matters
3. Minimal fix
4. Residual risk

