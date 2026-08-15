# AGENTS.md - Agent-Specific Instructions

This file provides specialized guidance for different AI agents working on this project.

## Claude Code / Qwen Code / Gemini CLI

### Working with This Project

When asked to make changes to skill-audit:

1. **Always run tests first**: `npm test`
2. **Build after changes**: `npm run build`
3. **Check for lint errors**: Ensure no TypeScript errors

### Distribution Policy

This fork is distributed from Git and must not be published to npm. Do not run
`npm publish` or add npm publishing or automatic release workflows. Validate
changes locally, then use the repository's normal Git review process.

## Security Auditing Context

When using skill-audit to audit other skills:

- This package includes a postinstall script for UX
- The postinstall is informational only - does NOT auto-install hooks
- Scanner excludes known-safe scripts (postinstall, preinstall, prepare)
- See `SECURITY.md` for full security policy

## Reference

- `references/postinstall-safety.md` - Documentation pattern for safe postinstall scripts
