# skill-audit

Security auditing CLI for AI agent skills.

## Features

- **Static Analysis**: Detect prompt injection, dangerous scripts, hardcoded secrets
- **Dependency Scanning**: Uses Trivy to scan for known vulnerabilities in dependencies
- **Risk Scoring**: 0-10 score mapped to OWASP Agentic Top 10 (ASI01-ASI10)
- **Multi-Agent Support**: Groups results by agent (Claude Code, Qwen Code, Gemini CLI, etc.)
- **Agent Environment Doctor**: Detect risky hooks, shell startup files, PATH hijacking, MCP/tool configs, and workspace lifecycle scripts
- **Session Context Contracts**: Warn when skills do not declare what agent/session facts they read, require, and write back
- **CI/CD Ready**: JSON output, threshold-based pass/fail

## Installation

### Install the executable

```bash
version=v0.10.0
gh release download "$version" \
  --repo nfma/skill-audit \
  --pattern "skill-audit-$version.mjs" \
  --pattern "skill-audit-$version.mjs.sha256"
shasum -a 256 -c "skill-audit-$version.mjs.sha256"
install -m 0755 "skill-audit-$version.mjs" "$HOME/.local/bin/skill-audit"
```

The release executable requires Node 24 or newer. It is a single tree-shaken
`.mjs` file: no npm install, local build, archive, or extraction step is
required. Immutable GitHub Releases are the only publication channel; this
fork is not published to npm.

Each release also contains a SHA-256 file and a deterministic descriptor that
binds the executable to its source commit, release workflow, embedded rules,
and documentation digests. `embeddedRulesSha256` is computed from canonical
UTF-8 JSON of the decoded rules: arrays retain order; object keys are sorted by
UTF-8 bytes; strings, booleans, `null`, and finite numbers use JSON scalar
encoding; and unsupported values, non-finite numbers, and non-plain objects are
rejected. Whitespace, line endings, and source object-key order therefore do not
change rule identity. Maintainers accepting an upgrade should inspect the
release with `gh release view` and verify the asset provenance with
`gh attestation verify` against the pinned repository.

### Install the human-readable skill

```bash
# Install the nested skill documentation from this GitHub fork.
npx skills add nfma/skill-audit --skill skill-audit -g -y
```

> ⚠️ **Important**: The skills CLI expects `owner/repo` format, not npm scoped packages.
>
> - ✅ Correct: `nfma/skill-audit`
> - ❌ Incorrect: `@hungpg/skill-audit`

Agent harnesses need the ordinary `SKILL.md` and `references/` files; they
cannot discover those documents inside the executable. The executable and the
human-readable skill are therefore installed separately.

## About the Postinstall Script

Source developers who run `npm install` in a checkout will invoke this package's informational `postinstall` script. Release-executable users do not run it. **This script is completely safe and informational only:**

- ✅ Does NOT automatically install any hooks
- ✅ Does NOT execute any code that could be considered malicious
- ✅ Does NOT make any network requests
- ✅ Does NOT modify any files without user consent
- ✅ Does NOT collect any user data

The script simply displays a banner message prompting users to optionally run `skill-audit --install-hook` if they want to set up automatic skill auditing. Users must manually run this command to install the hook.

In CI environments (GitHub Actions, GitLab CI, Jenkins, etc.), the script exits silently without displaying anything.

## Source-checkout Hook Setup

Developers who run `npm install` in a source checkout may see this message
about setting up the PreToolUse hook. Installing the GitHub Release executable
does not run `postinstall` and does not display this banner:

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

Skills can declare how they interact with agent session context. `skill-audit` reports missing contracts universally rather than attempting to infer capability from tool names or prose.

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

- `CTX-001`: skill has no context contract
- `CTX-002`: missing declared session facts read by the skill
- `CTX-003`: missing invocation preconditions
- `CTX-004`: missing write-back summary fields
- `CTX-005`: missing confirmation boundary
- `CTX-006`: overbroad context reads such as full conversation or all files

## Options

| Flag                             | Description                                                              | Default                    |
| -------------------------------- | ------------------------------------------------------------------------ | -------------------------- |
| `-g, --global`                   | Audit global skills                                                      | ✓                          |
| `-p, --project`                  | Audit project-level skills                                               |                            |
| `--path <paths...>`              | Audit explicit skill directories instead of discovery                    |                            |
| `-a, --agent <agents...>`        | Filter by agent names                                                    |                            |
| `-x, --exclude-skill <names...>` | Exclude skills by name                                                   |                            |
| `--mode <mode>`                  | `lint`, `audit`, `doctor`, `trust-env`, or `diff-env`                    | audit                      |
| `-t, --threshold <score>`        | Set the risk threshold used with `--block`                               | unset (3.0 with `--block`) |
| `-j, --json`                     | JSON output                                                              |                            |
| `-o, --output <file>`            | Save to file                                                             |                            |
| `--no-deps`                      | Skip dependency scan                                                     |                            |
| `--compliance`                   | Run opt-in documentation heuristics in audit mode                        |                            |
| `--update-db`                    | Update the KEV, EPSS, and NVD maintenance caches                         |                            |
| `--source <sources...>`          | Select `kev`, `epss`, `nvd`, or `all` for `--update-db`                  | all                        |
| `--strict`                       | Exit 1 if a feed update fails; requires `--update-db`                    |                            |
| `--quiet`                        | Suppress non-error output                                                |                            |
| `--download-offline-db <dir>`    | Export KEV, EPSS, and NVD snapshots                                      |                            |
| `--check-command <command>`      | Classify a shell command and check environment drift if sensitive        |                            |
| `-v, --verbose`                  | Verbose output                                                           |                            |
| `--install-hook`                 | Install PreToolUse hook                                                  |                            |
| `--uninstall-hook`               | Remove PreToolUse hook                                                   |                            |
| `--hook-threshold <score>`       | Hook risk threshold                                                      | 3.0                        |
| `--hook-status`                  | Show hook status                                                         |                            |
| `--block`                        | Exit 1 for a high/critical blocking finding or when the threshold is met |                            |

## Exit Codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| 0    | Success (no blocking issues)                                             |
| 1    | Blocking finding, threshold met, strict update failure, or command error |

## Risk Levels

| Level     | Score   | Icon |
| --------- | ------- | ---- |
| Safe      | 0       | ✅   |
| Risky     | 0.1-3.0 | ⚠️   |
| Dangerous | 3.1-7.0 | 🔴   |
| Malicious | 7.1+    | ☠️   |

## OWASP Agentic Top 10 Mapping

- **ASI01** - Goal Hijack (prompt injection)
- **ASI02** - Tool Misuse and Exploitation
- **ASI04** - Supply Chain Vulnerabilities (secrets, deps)
- **ASI05** - Unexpected Code Execution (dangerous scripts)

## Vulnerability Intelligence

The maintenance commands can download vulnerability-intelligence snapshots:

| Source     | Current behavior                                                 |
| ---------- | ---------------------------------------------------------------- |
| CISA KEV   | Downloaded by `--update-db` and `--download-offline-db`          |
| NIST NVD   | Downloads CVEs modified in the preceding 24 hours                |
| FIRST EPSS | Downloaded by `--update-db` and `--download-offline-db`          |
| OSV.dev    | Queried live by dependency scanning; not cached by `--update-db` |
| GHSA       | Query helper exists but is not wired into ordinary audits        |

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

## Attribution

This fork is authored and maintained by [Nuno Marques](https://github.com/nfma).
It builds on the original [`skill-audit`](https://github.com/harrypham2000/skill-audit)
work by [Hung Pham](https://github.com/harrypham2000), whose contribution remains
credited here, in `package.json`, and in the repository history.
