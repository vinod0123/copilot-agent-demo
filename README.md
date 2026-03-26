# Copilot DevSecOps Workflow

This repository implements a security-first Copilot workflow for code and dependency review.

## Security Workflow

1. Open a feature branch and raise a pull request.
2. Request Copilot review for code-level findings.
3. Run dependency checks with OSV helper:

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

4. Ask the Security Auditor agent to propose minimal remediation patches.
5. Re-review after changes and merge only when risk is reduced.

## Repository Components

- `.github/copilot-instructions.md`: repository-level Copilot behavior
- `.github/agents/security-auditor.agent.md`: security-focused agent profile
- `.github/skills/dependency-vuln-check/SKILL.md`: dependency vulnerability review playbook
- `.github/skills/secure-python-review/SKILL.md`: Python secure code review playbook
- `tools/osv_lookup.py`: compact OSV lookup tool for packages and requirements files
- `mcp/osv_mcp_server.py`: MCP server wrapper to expose OSV lookups to coding agent tools
- `myapp/insecure_app.py`: application code under review
- `myapp/requirements.txt`: current dependency pins under review

## MCP Configuration

In GitHub repository settings:

- Go to `Settings -> Copilot -> Coding agent -> MCP configuration`
- Use [`mcp/mcp-config.example.json`](c:/Users/kkapil/OneDrive%20-%20Sopra%20Steria/p/3.%20mlops/test/copilot-dev-sec-ops/mcp/mcp-config.example.json) as the starting config

## Useful Commands

Single package vulnerability lookup:

```bash
python tools/osv_lookup.py --ecosystem PyPI --package requests --version 2.19.1 --min-severity HIGH --max 3
```

Batch dependency lookup:

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

## Review Prompts

```text
Use the Security Auditor agent. Review myapp/insecure_app.py and rank findings by exploitability.
```

```text
Use dependency-vuln-check on myapp/requirements.txt and summarize top 5 HIGH/CRITICAL findings with upgrade guidance.
```
