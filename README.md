# skill-audit

Security auditing tool for AI agent skills and agent execution environments.

> Part of the [Vercel Skills](https://skills.sh) ecosystem — validating skills against the Agent Skills specification and detecting vulnerabilities across OWASP Agentic Top 10 categories.

## Why

AI agent skills can execute arbitrary code, access files, and make network requests.
Before installing a third-party skill, you need to know:

- Does it try to hijack the agent's goals?
- Does it leak your API keys or tokens?
- Does it run dangerous scripts?
- Are its dependencies vulnerable?
- Is the local agent shell/config environment already compromised?
- Did agent hooks, PATH, shell startup files, or MCP/tool configs drift since the last trusted baseline?

`skill-audit` answers these questions automatically.

## Overview

`skill-audit` is a CLI tool that validates AI agent skills for security risks before installation. It detects:

- **Prompt injection** patterns (ASI01)
- **Credential leaks** / hardcoded secrets (ASI04)
- **Code execution** risks (ASI05)
- **Exfiltration** patterns (ASI02)
- **Behavioral manipulation** (ASI09)
- **PII exposure** (ASI03) — 39 patterns for Vietnam and International PII
- **Optional compliance heuristics** — Vietnam AI Law 2026, EU AI Act, GDPR
- **Dependency vulnerabilities** (CVE/GHSA/KEV/EPSS)
- **Agent environment risks** — suspicious hooks, shell startup files, PATH hijacking, MCP/tool command configs, workspace instruction poisoning, and package lifecycle scripts
- **Session context gaps** — skills that do not declare what agent/session facts they read, require, and write back

## Quick Start

v0.10.0 was tagged and built but never published; a release-workflow defect was
caught before publication. Use v0.10.1.

```bash
# Download the immutable Node 24 executable and its checksum
version=v0.10.1
gh release download "$version" \
  --repo nfma/skill-audit \
  --pattern "skill-audit-$version.mjs" \
  --pattern "skill-audit-$version.mjs.sha256"
shasum -a 256 -c "skill-audit-$version.mjs.sha256"
mkdir -p "$HOME/.local/bin"
install -m 0755 "skill-audit-$version.mjs" "$HOME/.local/bin/skill-audit"
export PATH="$HOME/.local/bin:$PATH"

# Audit global skills
skill-audit -g

# Lint mode (spec validation only - fast)
skill-audit --mode lint

# Full audit with JSON output
skill-audit --mode audit -j > audit-results.json

# Include heuristic compliance checks (not a legal determination)
skill-audit --mode audit --compliance

# Fail CI/CD on dangerous skills
skill-audit -g -t 3.0

# Scan the local agent execution environment before invoking skills
skill-audit doctor

# Store and compare compact trusted environment context across sessions
skill-audit trust env
skill-audit diff-env

# Hook-friendly check for risky shell commands
skill-audit --check-command "npx skills add owner/repo"
```

## Context-Aware Agent Environment Auditing

`skill-audit` is no longer limited to scanning a skill at install time. It can also check the agent environment that will execute skills.

This matters because a clean skill can still be unsafe if the agent runtime is already compromised by a malicious hook, poisoned shell startup file, shadowed binary in `PATH`, risky MCP/tool command config, or dangerous package lifecycle script.

### `skill-audit doctor`

Run a read-only scan of the local agent execution environment:

```bash
skill-audit doctor
skill-audit doctor --verbose
skill-audit doctor --json
skill-audit doctor --threshold 5 --block
```

The doctor checks:

- Agent hook/config files for shell-command hooks, remote script execution, unpinned `npx` MCP/tool servers, and secret-like config values
- Shell startup files for remote script execution, reverse shells, command-shadowing aliases, and exported secrets
- `PATH` entries and sensitive binaries for workspace-local or world-writable executable resolution
- Workspace instruction files such as `AGENTS.md`, `CLAUDE.md`, `QWEN.md`, and `GEMINI.md`
- Workspace package files for risky lifecycle scripts such as `postinstall`, `prepare`, `preinstall`, and `install`

Secret-like evidence is redacted in reports.

### Environment baselines and drift

Agents should not keep full environment history in the prompt window. Instead, `skill-audit` stores a compact trusted baseline outside the conversation:

```bash
# Save current trusted shell/config state
skill-audit trust env

# Compare current state against the baseline
skill-audit diff-env

# Fail automation if environment drift is detected
skill-audit diff-env --block
```

The baseline is stored at:

```text
~/.skill-audit/baselines/environment.json
```

It records file hashes and redacted finding summaries, not full logs or conversation history.

### Hook-sensitive command assessment

Hooks can call `--check-command` to avoid scanning everything on every shell command. The command is classified first, then environment drift is checked only for sensitive operations:

```bash
skill-audit --check-command "npm install" --json
skill-audit --check-command "curl https://example.test/install.sh | bash" --block
```

Sensitive operations include skill installs, package installs, remote script execution, agent config edits, shell startup edits, and executable permission changes.

## Session Context Contracts

Skills can declare how they interact with agent session context:

```yaml
context:
  reads:
    - user_goal
    - target_environment
    - changed_files
  requires:
    - explicit_user_intent
    - confirmation_for_mutating_actions
  writes:
    - commands_run
    - files_changed
    - verification_result
  confirmation: on-risk
```

`skill-audit` treats this as an audit extension, not a replacement for Claude/Agent Skills required `name` and `description` frontmatter. Skills without this contract receive `CTX-*` findings so agents can identify missing invocation boundaries, confirmation requirements, and write-back summaries.

## Sample Output

```
🔍 Auditing 3 skills...

✅ safe-skill (0.5) - No issues
⚠️  risky-skill (3.2) - 2 findings
   - PI-001: Prompt injection pattern detected (SKILL.md:15)
   - SC-003: Hardcoded API key pattern (src/index.ts:8)
🔴 dangerous-skill (6.8) - 5 findings, exceeds threshold

❌ 1 skill exceeds threshold 3.0
```

## CI/CD Integration

```yaml
# .github/workflows/audit-skills.yml
name: Audit Skills
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          persist-credentials: false
      - name: Download pinned skill-audit release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          version=v0.10.1
          gh release download "$version" --repo nfma/skill-audit \
            --pattern "skill-audit-$version.mjs" \
            --pattern "skill-audit-$version.mjs.sha256" \
            --dir "$RUNNER_TEMP/skill-audit"
          cd "$RUNNER_TEMP/skill-audit"
          shasum -a 256 -c "skill-audit-$version.mjs.sha256"
      - run: node "$RUNNER_TEMP/skill-audit/skill-audit-v0.10.1.mjs" -g -t 3.0 --json > results.json
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: audit-results
          path: results.json
```

## SonarQube Cloud

CI-based analysis uses `sonar-project.properties` for project
`nfma_skill-audit`. Automatic Analysis must be disabled under **Administration
→ Analysis Method** in SonarQube Cloud. Add a repository Actions secret named
`SONAR_TOKEN`. Dependabot and fork pull requests, which cannot read Actions
secrets, skip the scan with a warning; a missing token on any other run fails
the job. The workflow type-checks, tests with LCOV coverage, builds, scans, and
waits for the quality gate.

This fork publishes one tree-shaken Node 24 executable through immutable GitHub Releases and is not published to npm. Release assets include a SHA-256 checksum and a descriptor binding the executable, source commit, workflow, embedded rules, and documentation digests. The embedded-rules digest covers canonical decoded JSON: array order is retained, object keys are sorted by UTF-8 bytes, finite numbers use the RFC 8785 shortest round-trippable IEEE 754 representation, and sparse arrays or unsupported values are rejected. JSON presentation details such as whitespace, line endings, and source key order do not affect rule identity.

## Project Structure

```
.
├── README.md              # This file (project overview)
├── skill-audit/           # Node.js/TypeScript package
│   ├── README.md          # Package documentation
│   ├── SKILL.md           # Agent skill definition
│   ├── src/               # TypeScript source
│   └── package.json       # Node package manifest
└── rules/                 # Security patterns (future)
```

## Packages

| Package                         | Description                                                            |
| ------------------------------- | ---------------------------------------------------------------------- |
| [`skill-audit`](./skill-audit/) | CLI tool for auditing AI agent skills and agent execution environments |

## Risk Scoring

| Level        | Score   | Action                      |
| ------------ | ------- | --------------------------- |
| ✅ Safe      | 0-3.0   | No issues or minor concerns |
| ⚠️ Risky     | 3.1-5.0 | Review recommended          |
| 🔴 Dangerous | 5.1-7.0 | Fix before use              |
| ☠️ Malicious | 7.1+    | Do not use                  |

## Vulnerability Intelligence

Enriched with real-time threat data from:

- **CISA KEV** — Known Exploited Vulnerabilities (daily updates)
- **FIRST EPSS** — Exploit Prediction Scoring System (3-day updates)
- **OSV.dev** — Open Source Vulnerabilities database

### Feed Updates

Normal audits never start background network requests. Refresh feeds explicitly when needed:

1. **Manual** - Run `skill-audit --update-db` anytime
2. **Scheduled** - The repository's GitHub Actions workflow refreshes its published feed cache

⚠️ **Stale cache warning**: If feeds are >3 days old, audit output will warn you to update.

### Manual Cron Setup (Enterprise)

For environments without GitHub Actions:

```bash
# Daily update at 2 AM (Linux/macOS)
0 2 * * * skill-audit --update-db --quiet

# Windows Task Scheduler
schtasks /create /tn "skill-audit-update" /tr "skill-audit --update-db" /sc daily /st 02:00
```

## Use Cases

### For Skill Authors

- Validate your skill before publishing
- Catch security issues early in development
- Ensure Agent Skills spec compliance

### For Skill Users

- Audit third-party skills before installation
- Check agent hooks, shell config, PATH, and MCP/tool configs before invoking skills
- Detect environment drift across agent sessions with trusted baselines
- CI/CD gate for skill installation pipelines
- Generate security reports for compliance

### For Registries

- Automated skill validation at submission
- Risk scoring for skill discovery
- Vulnerability monitoring across skill ecosystem

## Related Projects

### Vercel Skills Ecosystem

- **[Vercel Skills](https://skills.sh)** — Agent skills registry and runtime where `skill-audit` validates submissions
- **[Anthropic Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)** — SKILL.md specification that `skill-audit` validates against

### Security & Validation

- **[AgentVeil](https://github.com/vurakit/agentveil)** — Security proxy for AI agents with PII anonymization, prompt injection protection, and compliance checking. Inspired `skill-audit`'s PII detection patterns and compliance validation framework
- **[GoClaw](https://github.com/nextlevelbuilder/goclaw)** — Multi-agent gateway with 5-layer security (prompt injection detection, SSRF protection, shell deny patterns). Inspired `skill-audit`'s pattern-based vulnerability detection
- **[Trivy](https://github.com/aquasecurity/trivy)** — Vulnerability scanner used by `skill-audit` for dependency CVE scanning

### Standards

- **[OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-application-security-verification-standard/)** — ASI01-ASI10 threat categories that `skill-audit` maps findings to

## License

MIT

## Attribution

This independently maintained fork is authored by [Nuno Marques](https://github.com/nfma).
It is based on the original [`skill-audit`](https://github.com/harrypham2000/skill-audit)
work by [Hung Pham](https://github.com/harrypham2000), whose contribution remains
credited here and in the repository history.
