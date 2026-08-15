# skill-audit

Security auditing CLI for AI agent skills.

## Features

- **Static Analysis**: Detect prompt injection, dangerous scripts, hardcoded secrets
- **Dependency Scanning**: Uses Trivy to scan for known vulnerabilities in dependencies
- **Risk Scoring**: 0-10 score mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- **Multi-Agent Support**: Groups results by agent (Claude Code, Qwen Code, Gemini CLI, etc.)
- **Agent Environment Doctor**: Detect risky hooks, shell startup files, PATH hijacking, MCP/tool configs, and workspace lifecycle scripts
- **Session Context Contracts**: Warn when executable skills do not declare what agent/session facts they read, require, and write back
- **CI/CD Ready**: JSON output, threshold-based pass/fail

## Installation

### Option 1: Install the CLI from Git

```bash
git clone https://github.com/nfma/skill-audit.git
cd skill-audit/skill-audit
npm ci --ignore-scripts
npm run build
npm link --ignore-scripts
```

This fork is distributed from Git and is not published to npm. The commands
above build the checked-out source and link its `skill-audit` executable.

### Option 2: Install as a Skill (For Claude Code)

```bash
# Install from this GitHub fork (not an npm package name)
npx skills add nfma/skill-audit -g -y
```

> ⚠️ **Important**: The skills CLI expects `owner/repo` format, not npm scoped packages.
> - ✅ Correct: `nfma/skill-audit`
> - ❌ Incorrect: `@hungpg/skill-audit`

### Option 3: Install for Qwen Code

```bash
# Clone to Qwen skills directory
mkdir -p ~/.qwen/skills
git clone https://github.com/nfma/skill-audit.git ~/.qwen/skills/skill-audit
cd ~/.qwen/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

### Option 4: Install for Gemini CLI

```bash
# Clone to Gemini skills directory
mkdir -p ~/.gemini/skills
git clone https://github.com/nfma/skill-audit.git ~/.gemini/skills/skill-audit
cd ~/.gemini/skills/skill-audit/skill-audit
npm install && npm run build

# Or with bun (faster)
bun install && bun run build
```

## About the Postinstall Script

This package includes a `postinstall` script that runs automatically after `npm install`. **This script is completely safe and informational only:**

- ✅ Does NOT automatically install any hooks
- ✅ Does NOT execute any code that could be considered malicious
- ✅ Does NOT make any network requests
- ✅ Does NOT modify any files without user consent
- ✅ Does NOT collect any user data

The script simply displays a banner message prompting users to optionally run `skill-audit --install-hook` if they want to set up automatic skill auditing. Users must manually run this command to install the hook.

In CI environments (GitHub Actions, GitLab CI, Jenkins, etc.), the script exits silently without displaying anything.

## Automatic Hook Setup

After installation, you'll see a message about setting up the PreToolUse hook:

```
┌─────────────────────────────────────────────────────────┐
│           🛡️  skill-audit installed!                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Protect your skills from vulnerabilities:              │
│                                                         │
│    skill-audit --install-hook                           │
│                                                         │
│  This adds a PreToolUse hook that audits skills         │
│  before installation via 'npx skills add'.             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

Run the command to set up automatic skill auditing:

```bash
skill-audit --install-hook
```

### Manual Hook Management

```bash
# Install hook manually
skill-audit --install-hook

# Install with custom threshold
skill-audit --install-hook --hook-threshold 5.0

# Check hook status
skill-audit --hook-status

# Remove hook
skill-audit --uninstall-hook
```

### How the Hook Works

1. **Trigger**: When you run `npx skills add <package>`
2. **Scan**: skill-audit analyzes the skill before installation
3. **Decision**:
   - Risk score < 3.0 with no high/critical spec, security, PII, or intelligence finding → Installation proceeds
   - Risk score ≥ 3.0 or a high/critical spec, security, PII, or intelligence finding → Installation blocked
4. **Report**: Detailed findings shown in terminal

## Usage

```bash
# Audit global skills
skill-audit -g

# Audit with verbose output
skill-audit -v

# JSON output for CI
skill-audit --json > audit-results.json

# Exit 1 if risk meets the selected threshold
skill-audit --threshold 5.0 --block

# Skip dependency scanning (faster)
skill-audit --no-deps

# Filter by agent
skill-audit -a "Claude Code" "Qwen Code"

# Project-level skills only
skill-audit --project

# Lint mode (spec validation only)
skill-audit --mode lint

# Agent environment scan (hooks, shell, PATH, MCP/tool configs)
skill-audit doctor

# Save current agent environment as trusted baseline
skill-audit trust env

# Compare current environment against the trusted baseline
skill-audit diff-env

# Hook-friendly check for sensitive shell commands
skill-audit --check-command "npx skills add owner/repo"

# Update vulnerability DB manually
skill-audit --update-db
```

## Agent Environment Doctor

`skill-audit doctor` is a read-only scan of the local agent execution environment. It complements skill auditing by checking whether the shell and agent configuration are safe before any skill is invoked.

It currently checks:

- Agent hook/config files for shell-command hooks, remote script execution, unpinned `npx` MCP/tool servers, and secrets in config
- Shell startup files for remote script execution, reverse shells, command-shadowing aliases, and exported secrets
- `PATH` entries and sensitive binaries for workspace-local or world-writable executable resolution
- Workspace instruction files (`AGENTS.md`, `CLAUDE.md`, `QWEN.md`, `GEMINI.md`) for prompt-injection style directives
- Workspace package files for risky lifecycle scripts such as `postinstall`, `prepare`, `preinstall`, and `install`

Examples:

```bash
# Human-readable environment report
skill-audit doctor

# Full evidence and recommendations
skill-audit doctor --verbose

# JSON output for automation
skill-audit doctor --json

# Block automation if environment risk exceeds a threshold
skill-audit doctor --threshold 5 --block
```

Secret-like evidence is redacted in reports. The doctor mode does not modify files.

### Environment baselines and drift

Use a baseline when you want agents to keep a compact, durable understanding of the trusted shell/config state across sessions:

```bash
# Record hashes and redacted findings for the current environment
skill-audit trust env

# Detect changed files, new findings, and resolved findings since baseline
skill-audit diff-env

# Fail automation if drift is detected
skill-audit diff-env --block
```

The baseline is stored at `~/.skill-audit/baselines/environment.json`. It records file hashes and redacted finding summaries, not full conversation history.

### Hook-sensitive command assessment

Hooks can call `--check-command` to avoid scanning everything on every shell command. The command is classified first, and environment drift is checked only for sensitive commands such as skill installs, package installs, remote script execution, agent config edits, shell startup edits, and executable permission changes.

```bash
skill-audit --check-command "npm install" --json
skill-audit --check-command "curl https://example.test/install.sh | bash" --block
```

## Session Context Contracts

Executable skills can declare how they interact with agent session context. `skill-audit` warns when a skill can run shell/tool behavior but does not declare this contract.

Example frontmatter:

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

Context checks include:

- `CTX-001`: executable skill has no context contract
- `CTX-002`: missing declared session facts read by the skill
- `CTX-003`: missing invocation preconditions
- `CTX-004`: missing write-back summary fields
- `CTX-005`: missing confirmation boundary
- `CTX-006`: overbroad context reads such as full conversation or all files

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-g, --global` | Audit global skills | ✓ |
| `-p, --project` | Audit project-level skills | |
| `-a, --agent <agents...>` | Filter by agent names | |
| `-x, --exclude-skill <names...>` | Exclude skills by name | |
| `--mode <mode>` | `lint`, `audit`, `doctor`, `trust-env`, or `diff-env` | audit |
| `-t, --threshold <score>` | Set the risk threshold used with `--block` | unset (3.0 with `--block`) |
| `-j, --json` | JSON output | |
| `-o, --output <file>` | Save to file | |
| `--no-deps` | Skip dependency scan | |
| `--compliance` | Run opt-in documentation heuristics in audit mode | |
| `--update-db` | Update the KEV, EPSS, and NVD maintenance caches | |
| `--source <sources...>` | Select `kev`, `epss`, `nvd`, or `all` for `--update-db` | all |
| `--strict` | Exit 1 if a feed update fails; requires `--update-db` | |
| `--quiet` | Suppress non-error output | |
| `--download-offline-db <dir>` | Export KEV, EPSS, and NVD snapshots | |
| `--check-command <command>` | Classify a shell command and check environment drift if sensitive | |
| `-v, --verbose` | Verbose output | |
| `--install-hook` | Install PreToolUse hook | |
| `--uninstall-hook` | Remove PreToolUse hook | |
| `--hook-threshold <score>` | Hook risk threshold | 3.0 |
| `--hook-status` | Show hook status | |
| `--block` | Exit 1 for a high/critical blocking finding or when the threshold is met | |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no blocking issues) |
| 1 | Blocking finding, threshold met, strict update failure, or command error |

## Risk Levels

| Level | Score | Icon |
|-------|-------|------|
| Safe | 0 | ✅ |
| Risky | 0.1-3.0 | ⚠️ |
| Dangerous | 3.1-7.0 | 🔴 |
| Malicious | 7.1+ | ☠️ |

## OWASP Agentic Top 10 Mapping

- **ASI01** - Goal Hijack (prompt injection)
- **ASI02** - Tool Misuse and Exploitation
- **ASI04** - Supply Chain Vulnerabilities (secrets, deps)
- **ASI05** - Unexpected Code Execution (dangerous scripts)

## Vulnerability Intelligence

The maintenance commands can download vulnerability-intelligence snapshots:

| Source | Current behavior |
|--------|------------------|
| CISA KEV | Downloaded by `--update-db` and `--download-offline-db` |
| NIST NVD | Downloads CVEs modified in the preceding 24 hours |
| FIRST EPSS | Downloaded by `--update-db` and `--download-offline-db` |
| OSV.dev | Queried live by dependency scanning; not cached by `--update-db` |
| GHSA | Query helper exists but is not wired into ordinary audits |

**Feed refresh:**
- Daily root GitHub Actions workflow maintains a CI cache
- Manual: `skill-audit --update-db`
- Audits and the informational postinstall script do not refresh feeds in the background

**Current audit behavior:** Ordinary audits do not read the KEV, EPSS, or NVD maintenance caches and do not populate `intelFindings` from them. The exported snapshots are not an offline-audit input. Dependency scanning continues to use its configured live scanners and OSV fallback.

### NVD Synchronization

The `--update-db` command fetches CVEs modified in the last 24 hours and replaces the prior NVD cache. It does not build a historical database across repeated runs:

```bash
skill-audit --update-db
```

Note: NVD API rate limits apply (5 requests/30 sec without API key). Set `NVD_API_KEY` environment variable for 50 requests/30 sec.

## Trust Sources

1. Static pattern matching for known attack vectors
2. Trivy for dependency vulnerability scanning
3. Heuristic rules for common security issues

## Requirements

- Node.js 18+
- npx (for skills CLI)
- trivy (optional, for dependency scanning)

## Troubleshooting

**False positives**: Review finding at file:line, add inline comment explaining legitimate use

**Refresh maintenance cache**: Run `skill-audit --update-db` for KEV, EPSS, and NVD

**Skill not found**: Verify `SKILL.md` exists in root or `skills/` directory

**Feed refresh fails**: Re-run `skill-audit --update-db`; installation and ordinary audits do not depend on a background refresh.

**Offline snapshots**: `--download-offline-db <dir>` exports feed data for external inspection; ordinary audits do not consume these files.
