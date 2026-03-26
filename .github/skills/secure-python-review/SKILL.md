# Secure Python Review

## Purpose

Use this skill to review Python code for common DevSecOps/security flaws.

## Focus

- hardcoded secrets
- sensitive logging
- unsafe subprocess and command execution
- weak validation/auth
- unsafe deserialization

## Workflow

1. Identify security findings first.
2. Rank by exploitability.
3. Propose minimal patch.
4. Note residual risk.

## Output

1. Findings
2. Why it matters
3. Minimal fix
4. Residual risk

## Rules

- Keep fixes small and reviewable.
- Avoid overstating uncertain issues.
- Prefer practical, concrete remediations.

