# Copilot Pro DevSecOps POC

This repository is a proof of concept for showing how `GitHub Copilot Pro` can support a lightweight DevSecOps workflow during code review and remediation.

The goal is not to prove that Copilot replaces GitHub security products. The goal is to show that Copilot adds value by reviewing risky code in context, explaining why it is risky, and helping the developer fix it with minimal effort.

## POC Objective

Demonstrate a realistic pull request workflow where Copilot acts as a security-aware reviewer and coding assistant.

This POC should answer:

- How can Copilot help identify security weaknesses in code before merge?
- How can Copilot explain the issue in a way that a developer or student understands?
- How can Copilot help remediate the issue quickly without needing a full custom agent platform?
- Where does Copilot add value beyond basic secret scanning?

## Why This POC Matters

A simple secret-leak demo is not enough because GitHub already has native secret scanning and push protection in many cases.

A stronger Copilot Pro demo is:

- contextual PR review
- security-focused code explanation
- suggested remediation
- optional agentic fix workflow through Copilot review comments and follow-up prompts

This better represents a modern DevSecOps workflow because it sits inside the normal developer loop:

1. write code
2. open PR
3. get automated review help
4. fix issues
5. merge with better security posture

## Scope Of This POC

This repository currently focuses on a small insecure Python deployment example in `demo/insecure_app.py`.

The file intentionally contains issues such as:

- hardcoded secret values
- sensitive logging
- unsafe shell execution with `shell=True`
- missing validation on external input

These are enough to demonstrate that Copilot can do more than just flag an obvious secret. It can reason about the surrounding code path and propose a safer implementation.

## Features Used

This POC is designed around `GitHub Copilot Pro` capabilities rather than GitHub Actions or Advanced Security.

Relevant Copilot capabilities:

- Copilot Chat in VS Code
- repository custom instructions from `.github/copilot-instructions.md`
- custom agent profile from `.github/agents/security-auditor.agent.md`
- reusable repo skills from `.github/skills/`
- PR-oriented review workflow with Copilot comments
- follow-up prompts asking Copilot to generate a minimal fix

Supporting files in this repository:

- `.github/copilot-instructions.md`
- `.github/agents/security-auditor.agent.md`
- `.github/skills/dependency-vuln-check/SKILL.md`
- `.github/skills/secure-python-review/SKILL.md`
- `demo/insecure_app.py`

## Agent-First POC Design

This repository should be presented as an `agent-based` Copilot Pro demo, not just a generic chat demo.

### Default Copilot vs Security Auditor Agent

Default Copilot is broad and reactive. It responds to the current prompt and code context.

The `Security Auditor` agent is narrower and more repeatable:

- it starts from a security-review role by default
- it follows a stable review structure
- it prioritizes risk over style suggestions
- it is better suited for repeatable PR review demos

This is important for the POC because the audience should see that Copilot Pro can be shaped into a specialized teammate rather than only used as a general assistant.

### Skills Used By The Agent

The POC also includes reusable skills so the agent is not just a single long prompt.

- `dependency-vuln-check`: helps the agent reason about package-version vulnerability status using structured advisory sources
- `secure-python-review`: helps the agent review Python code for secrets exposure, subprocess risk, and related DevSecOps issues

This makes the setup more realistic because it models how a team might separate general agent behavior from focused review playbooks.

## Proposed Demo Workflow

The most effective flow is to demo this as a pull request review and remediation story.

### Workflow Summary

1. Create a feature branch with intentionally insecure code.
2. Push the branch and open a pull request.
3. Use Copilot to review the change.
4. Ask Copilot to explain the security findings in plain language.
5. Ask Copilot to generate a minimal fix.
6. Commit the safer version.
7. Re-run review and show reduced risk.

### Workflow In Detail

#### Step 1: Prepare The Insecure Change

Use `demo/insecure_app.py` as the vulnerable example.

The current issues in that file are:

- `AWS_ACCESS_KEY_ID` is hardcoded
- `DB_PASSWORD` is hardcoded
- the password is printed in logs
- user-controlled input reaches a shell command through `shell=True`

This gives you a strong teaching example because the same file contains:

- secrets hygiene problems
- command injection risk
- observability/logging risk

#### Step 2: Open A Pull Request

Create a PR with a title such as:

```text
demo: add deployment helper
```

In the PR description, state that this is a deployment utility for a DevOps automation flow.

That framing makes the review realistic because insecure deployment utilities are common in real teams.

#### Step 3: Request Copilot Review

Use Copilot to review the PR or the changed file.

Expected Copilot observations:

- credentials should not be hardcoded
- sensitive data should not appear in logs
- `subprocess.check_output(..., shell=True)` is risky when input can be influenced externally
- environment variables should be used instead of inline secrets

#### Step 4: Ask Copilot For A Security Explanation

Example prompts:

```text
Review this pull request like a security engineer. Focus on secrets handling, logging, and command execution risks.
```

```text
Explain each issue in simple language and suggest the smallest safe fix.
```

Expected outcome:

- Copilot explains not just what is wrong, but why it matters
- Copilot provides a developer-friendly explanation suitable for training or classroom use

#### Step 5: Ask Copilot To Generate A Fix

Example prompts:

```text
Rewrite this code to remove hardcoded secrets, avoid logging credentials, and replace shell=True with a safer approach.
```

```text
Keep the fix minimal and easy to explain in a classroom demo.
```

Expected outcome:

- secrets moved to environment variables
- logging sanitized
- shell invocation replaced with a safe subprocess call
- optional input validation added

#### Step 6: Show Before And After

This is the most important teaching moment in the POC.

Before:

- insecure code exists in a realistic helper script
- developer may not notice all issues during local coding

After Copilot review:

- issues are called out in context
- safer code is proposed quickly
- the developer still retains responsibility for final approval

This demonstrates augmented DevSecOps rather than blind automation.

## Example Demo Narrative

Below is a simple story you can present while demoing:

```text
We created a deployment helper quickly, but it contains several common security mistakes.
Instead of relying only on a scanner to match patterns, we use Copilot Pro to review the change in context.
Copilot identifies hardcoded secrets, sensitive logging, and shell injection risk.
Then we ask Copilot to produce a minimal remediation patch.
This shows how Copilot supports secure development directly in the developer workflow.
```

## Example Findings To Expect

If the POC works well, Copilot should identify issues similar to these:

- Hardcoded credentials may be exposed in source control and reused elsewhere.
- Logging the database password leaks sensitive data into logs and monitoring tools.
- Using `shell=True` with branch input can enable command injection.
- External input should be validated or safely passed as a command argument list.

## What Makes This Better Than A Secret Scan Demo

This POC is stronger than a simple leaked-secret example because it demonstrates reasoning across multiple concerns in one review:

- secure coding practices
- runtime safety
- developer guidance
- remediation support

It also better matches how teams actually work. Developers do not just need a blocked push. They need:

- context
- explanation
- a safe fix
- fast iteration

That is where Copilot Pro becomes useful.

## Suggested Prompts For The Demo

Use these prompts during the live walkthrough.

### Prompt 1: Initial Review

```text
Review this file like a DevSecOps engineer. Identify security risks, rank them by severity, and explain each one briefly.
```

### Prompt 2: Minimal Remediation

```text
Fix the identified issues with minimal code changes. Replace hardcoded secrets, remove sensitive logging, and avoid unsafe shell execution.
```

### Prompt 3: Teaching Version

```text
Explain the before-and-after changes so I can present this as a classroom DevSecOps example.
```

### Prompt 4: PR Review Tone

```text
Write review comments for this PR as if you were a security reviewer on the platform team.
```

## Suggested Success Criteria

The POC is successful if it demonstrates the following:

- Copilot identifies more than one type of issue
- Copilot explains the issues in a useful way
- Copilot suggests or generates an actionable fix
- the developer can apply the fix with minimal effort
- the story clearly shows value beyond simple pattern matching

## Limitations

This POC intentionally avoids claiming capabilities that belong to other GitHub products.

Important limitations:

- Copilot is not a guaranteed enforcement control
- Copilot does not replace formal SAST, secret scanning, or policy engines
- findings may vary depending on the prompt and the code context
- human review is still required before merge

## Recommendations To Make The POC Better

The current single-file example is a good start, but the demo will be stronger if we extend it slightly.

Recommended next improvements:

- add an `MLOps-specific` vulnerable example such as unsafe model loading or insecure API inference code
- create a `fixed` version of the same file for before-and-after comparison
- prepare one realistic PR description and one set of review comments for the live demo
- include a short threat-model section so the audience sees the business impact, not just the code smell
- optionally show how repository instructions influence Copilot's review style

## Recommended Next Version Of The POC

If we extend this repository, the best next version would include:

1. `demo/insecure_app.py` for classic application security issues
2. `demo/insecure_model_loader.py` for MLOps-specific risk
3. `demo/fixed_app.py` for the remediated version
4. a scripted PR walkthrough that demonstrates review, explanation, and remediation
5. optional dependency-vulnerability lookup through MCP or API-backed tooling

## Conclusion

This POC should be positioned as:

`Copilot Pro as a practical DevSecOps assistant for code review and remediation`

It should not be positioned as:

`Copilot as a replacement for secret scanning or security enforcement`

That positioning keeps the demo technically accurate and makes the Copilot value much clearer.

## Recommendation For Vulnerability Intelligence

If you want the agent to comment on `dependency vulnerabilities`, use a package-vulnerability source rather than a general news search tool.

### Recommended order

1. `OSV API`
2. `GitHub Advisory Database / Dependabot alerts`
3. `NVD API`
4. `Brave Search API` only as a supporting signal for latest news or exploit discussion

### Why OSV is the best free starting point

OSV is free, API-first, and specifically built for open-source vulnerability lookups by package and version. Its API currently has no rate limits documented and is a much better fit than general search for package risk checks.

Use OSV when your agent needs to answer questions like:

- Is `jinja2 2.4.1` known vulnerable?
- What advisories affect a specific package version?
- Which ecosystem and fixed version are relevant?

### OSV Tool In This Repo (No jq Needed)

To avoid huge raw JSON output, this repo includes:

- `tools/osv_lookup.py`

Example:

```bash
python tools/osv_lookup.py --ecosystem PyPI --package jinja2 --version 2.4.1
```

Actionable view (only higher severity, fewer rows):

```bash
python tools/osv_lookup.py --ecosystem PyPI --package jinja2 --version 2.4.1 --min-severity HIGH --max 3
```

Batch scan for many dependencies:

```bash
python tools/osv_lookup.py --requirements requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

App-specific batch scan:

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

Commit query:

```bash
python tools/osv_lookup.py --commit 6879efc2c1596d11a6a6ad296f80063b558d5e0f
```

JSON mode (compact structured output):

```bash
python tools/osv_lookup.py --ecosystem PyPI --package jinja2 --version 2.4.1 --format json
```

What this gives you:

- compact finding summaries
- key severity signal
- aliases (CVE/GHSA)
- fixed-version hints when present
- top reference URL
- batch support for `requirements.txt`

### Why Brave is not the primary choice

Brave Search can help with `latest news`, active discussion, or exploit chatter, but it is not the cleanest source of truth for dependency vulnerabilities.

Use Brave as a secondary source only for prompts like:

- Are there recent reports or write-ups about this CVE?
- Has this dependency vulnerability been actively discussed this week?

Do not use Brave as the main evidence source for "this version is vulnerable."

### Better free and practical options

- `OSV API`: best free structured API for package-version vulnerability lookups
- `Dependabot alerts`: best if your repo already has a dependency graph on GitHub
- `GitHub Advisory Database`: good for advisory detail and ecosystem coverage
- `NVD API`: useful as a secondary authority for CVEs and severity metadata
- `deps.dev API`: useful for dependency graph enrichment and package metadata, but not a full replacement for OSV

### Best technical pattern for this repo

Use the `Security Auditor` agent for code and PR review, and give it access to one vulnerability-intel tool:

- primary tool: `OSV lookup`
- optional secondary tool: `Brave Search` for latest discussion or exploit news

That keeps the agent grounded in structured security data first, then lets it enrich the result with recent context if needed.

## Current Best Recommendation For Latest Vulnerability Updates

If your goal is `latest and accurate vulnerability awareness`, use a layered approach instead of only one web tool.

### Recommended stack

1. `OSV API` for package-version vulnerability truth
2. `GitHub Advisory Database` or `Dependabot alerts` for GitHub-native dependency risk
3. `NVD API` for CVE metadata and severity context
4. `Brave Search API` for latest web discussion, exploit chatter, and recent write-ups

### Why this is the best balance

- `OSV` is best for precise dependency matching
- `GitHub Advisory Database` is strong for ecosystem and GitHub workflow alignment
- `NVD` adds standardized CVE detail
- `Brave` adds freshness, but should not be your primary vulnerability authority

### If you want one free source to start with

Start with `OSV`.

It is the cleanest free API for:

- package name + version lookup
- open-source ecosystems
- advisory references
- fixed-version guidance

### If you want best freshness from the web

Use `Brave Search` only as a secondary enrichment tool for questions like:

- Is this CVE actively discussed right now?
- Are there recent exploit reports this week?
- Is there a vendor post or incident write-up we should read?

### Best practical setup for this POC

- agent reviews code using the custom agent profile
- `secure-python-review` skill handles code-level risks
- `dependency-vuln-check` skill handles dependency risk
- `OSV` is the first external source
- `Brave` is optional for "latest news" context

## Maximum-Coverage POC Walkthrough

If your goal is to showcase the largest practical set of findings in one demo, use this sequence.

### Inputs to use

- `myapp/insecure_app.py` for code-level risks
- `myapp/requirements.txt` for dependency vulnerability checks

### Expected issue categories captured

- hardcoded credentials and tokens
- sensitive logging exposure
- shell command injection risk
- unsafe deserialization (`pickle`)
- weak auth pattern
- vulnerable dependency versions via OSV

### Demo commands

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity HIGH --max 5
```

If you want broader coverage:

```bash
python tools/osv_lookup.py --requirements myapp/requirements.txt --ecosystem PyPI --min-severity MODERATE --max 8
```

### Copilot agent prompts

```text
Use the Security Auditor agent. Review myapp/insecure_app.py and rank findings by exploitability.
```

```text
Use dependency-vuln-check skill on myapp/requirements.txt and summarize only the top 5 HIGH/CRITICAL findings.
```

```text
Propose a minimal remediation patch that removes secrets from code, avoids shell=True, and suggests safe dependency upgrade targets.
```

git checkout -b demo/copilot-devsecops-poc
git add .
git commit -m "Add insecure app + dependency risk demo for Copilot security agent"
git push -u origin demo/copilot-devsecops-poc

