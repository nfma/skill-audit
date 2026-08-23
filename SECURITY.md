# Security Policy

## Supported Versions

Security fixes are made on `main` and included in the next attested GitHub
release. This fork is distributed from GitHub and is not published to npm.

## Reporting a Vulnerability

Use GitHub's private security advisory flow for `nfma/skill-audit`. Do not open
a public issue containing exploit details, secrets, personal data, or a malicious
skill payload. Include the affected commit or release, impact, reachable input,
and a minimal reproduction when safe.

## System and Scope

`skill-audit` is a local TypeScript CLI that treats AI-agent skills as untrusted
data. It discovers skill trees, parses instruction and metadata files, applies
security and PII rules, inspects dependencies, optionally refreshes public
vulnerability intelligence, and emits human or JSON reports. Release builders,
rule data, hooks, and update workflows are also in scope.

## Threat Model and Trust Boundaries

Treat skill paths and contents, frontmatter, filenames, symlinks, dependency
metadata, remote feed responses, cache files, configuration, CLI arguments, and
report evidence as attacker-controlled. A caller selecting a path authorizes
reading only the resolved files within that skill boundary; it does not authorize
execution or arbitrary filesystem access.

## Security Invariants

- Discovery and parsing must remain within the canonical selected root and fail
  closed on symlink, traversal, race, unsupported-format, size, or count limits.
- Auditing must never execute a scanned skill, its scripts, build hooks, or
  dependency code.
- Remote responses must use pinned HTTPS origins, bounded retries, timeouts and
  body limits; redirects or error details must not become arbitrary local reads
  or persisted sensitive data.
- Findings, evidence, metrics and reports must not expose raw secrets or more PII
  than is required to identify and remediate a problem.
- Baselines and rule feeds must use exact, stale-detecting identities; ambiguous,
  missing, new, or obsolete entries fail closed.
- Release artifacts and workflows must be reproducible, immutable, least
  privilege, and must not publish this fork to npm.

## Reportable Findings and Severity Context

Report sandbox escapes, arbitrary code execution, traversal or symlink escapes,
filesystem races, SSRF or unsafe redirects, unbounded attacker-controlled
parsing, secret or PII disclosure, unsafe persistence, dependency-verification
bypasses, and false-negative paths that materially weaken a claimed blocking
gate. Heuristic disagreement alone is not a vulnerability unless it bypasses a
documented security property.

## Known Limitations

Pattern and compliance checks are heuristics, not legal determinations or proof
that a skill is safe. Live dependency and intelligence coverage depends on the
available public data sources; degraded or unavailable coverage must be visible
rather than silently treated as success.
